// +build darwin freebsd linux

// Package godaemon runs a program as a Unix daemon.
package godaemon

// Copyright (c) 2013-2015 VividCortex, Inc. All rights reserved.
// Please see the LICENSE file for applicable license terms.

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Environment variables to support this process
const (
	stageVar    = "__DAEMON_STAGE"
	fdVarPrefix = "__DAEMON_FD_"
)

// DaemonAttr describes the options that apply to daemonization
type DaemonAttr struct {
	ProgramName   string      // child's os.Args[0]; copied from parent if empty
	CaptureOutput bool        // whether to capture stdout/stderr
	Files         []**os.File // files to keep open in the daemon
}

/*
MakeDaemon turns the process into a daemon. But given the lack of Go's
support for fork(), MakeDaemon() is forced to run the process all over again,
from the start. Hence, this should probably be your first call after main
begins, unless you understand the effects of calling from somewhere else.
Keep in mind that the PID changes after this function is called, given
that it only returns in the child; the parent will exit without returning.

Options are provided as a DaemonAttr structure. In particular, setting the
CaptureOutput member to true will make the function return two io.Reader
streams to read the process' standard output and standard error, respectively.
That's useful if you want to capture things you'd normally lose given the
lack of console output for a daemon. Some libraries can write error conditions
to standard error or make use of Go's log package, that defaults to standard
error too. Having these streams allows you to capture them as required. (Note
that this function takes no action whatsoever on any of the streams.)

NOTE: If you use them, make sure NOT to take one of these readers and write
the data back again to standard output/error, or you'll end up with a loop.
Also, note that data will be flushed on a line-by-line basis; i.e., partial
lines will be buffered until an end-of-line is seen.

By using the Files member of DaemonAttr you can inherit open files that will
still be open once the program is running as a daemon. This may be convenient in
general, but it's primarily intended to avoid race conditions while forking, in
case a lock (flock) was held on that file. Repeatedly releasing and re-locking
while forking is subject to race conditions, cause a different process could
lock the file in between. But locks held on files declared at DaemonAttr.Files
are guaranteed NOT to be released during the whole process, and still be held by
the daemon. To use this feature you should open the file(s), lock if required
and then call MakeDaemon using pointers to that *os.File objects; i.e., you'd be
passing **os.File objects to MakeDaemon(). However, opening the files (and
locking if required) should only be attempted at the parent. (Recall that
MakeDaemon() will run the code coming "before" it three times; see the
explanation above.) You can filter that by calling Stage() and looking for a
godaemon.StageParent result. The last call to MakeDaemon() at the daemon itself
will actually *load* the *os.File objects for you; that's why you need to
provide a pointer to them. So here's how you'd use it:

	var (
		f   *os.File
		err error
	)

	if godaemon.Stage() == godaemon.StageParent {
		f, err = os.OpenFile(name, opts, perm)
		if err != nil {
			os.Exit(1)
		}
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != nil {
			os.Exit(1)
		}
	}

	_, _, err = godaemon.MakeDaemon(&godaemon.DaemonAttr{
		Files: []**os.File{&f},
	})

	// Only the daemon will reach this point, where f will be a valid descriptor
	// pointing to your file "name", still holding the lock (which will have
	// never been released during successive forks). You can operate on f as you
	// normally would, like:
	f.Close()

NOTE: Do not abuse this feature. Even though you could, it's obviously not a
good idea to use this mechanism to keep a terminal device open, for instance.
Otherwise, what you get is not strictly a daemon.


Daemonizing is a 3-stage process. In stage 0, the program increments the
magical environment variable and starts a copy of itself that's a session
leader, with its STDIN, STDOUT, and STDERR disconnected from any tty. It
then exits.

In stage 1, the (new copy of) the program starts another copy that's not
a session leader, and then exits.

In stage 2, the (new copy of) the program chdir's to /, then sets the umask
and reestablishes the original value for the environment variable.
*/
func MakeDaemon(attrs *DaemonAttr) (io.Reader, io.Reader, error) {
	stage, advanceStage, resetEnv := getStage()

	// This is a handy wrapper to do the proper thing in case of fatal
	// conditions. For the first stage you may want to recover, so it will
	// return the error. Otherwise it will exit the process, cause you'll be
	// half-way with some descriptors already changed. There's no chance to
	// write to stdout or stderr in the later case; they'll be already closed.
	fatal := func(err error) (io.Reader, io.Reader, error) {
		if stage > 0 {
			os.Exit(1)
		}
		resetEnv()
		return nil, nil, err
	}

	fileCount := 3 + len(attrs.Files)
	files := make([]*os.File, fileCount, fileCount+2)

	if stage == 0 {
		// Descriptors 0, 1 and 2 are fixed in the "os" package. If we close
		// them, the process may choose to open something else there, with bad
		// consequences if some write to os.Stdout or os.Stderr follows (even
		// from Go's library itself, through the default log package). We thus
		// reserve these descriptors to avoid that.
		nullDev, err := os.OpenFile("/dev/null", 0, 0)
		if err != nil {
			return fatal(err)
		}
		files[0], files[1], files[2] = nullDev, nullDev, nullDev

		fd := 3
		for _, fPtr := range attrs.Files {
			files[fd] = *fPtr
			saveFileName(fd, (*fPtr).Name())
			fd++
		}
	} else {
		files[0], files[1], files[2] = os.Stdin, os.Stdout, os.Stderr

		fd := 3
		for _, fPtr := range attrs.Files {
			*fPtr = os.NewFile(uintptr(fd), getFileName(fd))
			syscall.CloseOnExec(fd)
			files[fd] = *fPtr
			fd++
		}
	}

	if stage < 2 {
		// getExecutablePath() is OS-specific.
		procName, err := GetExecutablePath()
		if err != nil {
			return fatal(fmt.Errorf("can't determine full path to executable: %s", err))
		}

		// If getExecutablePath() returns "" but no error, determinating the
		// executable path is not implemented on the host OS, so daemonization
		// is not supported.
		if len(procName) == 0 {
			return fatal(fmt.Errorf("can't determine full path to executable"))
		}

		if stage == 1 && attrs.CaptureOutput {
			files = files[:fileCount+2]

			// stdout: write at fd:1, read at fd:fileCount
			if files[fileCount], files[1], err = os.Pipe(); err != nil {
				return fatal(err)
			}
			// stderr: write at fd:2, read at fd:fileCount+1
			if files[fileCount+1], files[2], err = os.Pipe(); err != nil {
				return fatal(err)
			}
		}

		if err := advanceStage(); err != nil {
			return fatal(err)
		}
		dir, _ := os.Getwd()
		osAttrs := os.ProcAttr{Dir: dir, Env: os.Environ(), Files: files}

		if stage == 0 {
			sysattrs := syscall.SysProcAttr{Setsid: true}
			osAttrs.Sys = &sysattrs
		}

		progName := attrs.ProgramName
		if len(progName) == 0 {
			progName = os.Args[0]
		}
		args := append([]string{progName}, os.Args[1:]...)
		proc, err := os.StartProcess(procName, args, &osAttrs)
		if err != nil {
			return fatal(fmt.Errorf("can't create process %s: %s", procName, err))
		}
		proc.Release()
		os.Exit(0)
	}

	os.Chdir("/")
	syscall.Umask(0)
	resetEnv()

	for fd := 3; fd < fileCount; fd++ {
		resetFileName(fd)
	}
	currStage = DaemonStage(stage)

	var stdout, stderr *os.File
	if attrs.CaptureOutput {
		stdout = os.NewFile(uintptr(fileCount), "stdout")
		stderr = os.NewFile(uintptr(fileCount+1), "stderr")
	}
	return stdout, stderr, nil
}

func saveFileName(fd int, name string) {
	// We encode in hex to avoid issues with filename encoding, and to be able
	// to separate it from the original variable value (if set) that we want to
	// keep. Otherwise, all non-zero characters are valid in the name, and we
	// can't insert a zero in the var as a separator.
	fdVar := fdVarPrefix + fmt.Sprint(fd)
	value := fmt.Sprintf("%s:%s",
		hex.EncodeToString([]byte(name)), os.Getenv(fdVar))

	if err := os.Setenv(fdVar, value); err != nil {
		fmt.Fprintf(os.Stderr, "can't set %s: %s\n", fdVar, err)
		os.Exit(1)
	}
}

func getFileName(fd int) string {
	fdVar := fdVarPrefix + fmt.Sprint(fd)
	value := os.Getenv(fdVar)
	sep := bytes.IndexByte([]byte(value), ':')

	if sep < 0 {
		fmt.Fprintf(os.Stderr, "bad fd var %s\n", fdVar)
		os.Exit(1)
	}
	name, err := hex.DecodeString(value[:sep])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding %s\n", fdVar)
		os.Exit(1)
	}
	return string(name)
}

func resetFileName(fd int) {
	fdVar := fdVarPrefix + fmt.Sprint(fd)
	value := os.Getenv(fdVar)
	sep := bytes.IndexByte([]byte(value), ':')

	if sep < 0 {
		fmt.Fprintf(os.Stderr, "bad fd var %s\n", fdVar)
		os.Exit(1)
	}
	if err := os.Setenv(fdVar, value[sep+1:]); err != nil {
		fmt.Fprintf(os.Stderr, "can't reset %s\n", fdVar)
		os.Exit(1)
	}
}

// Daemonize is equivalent to MakeDaemon(&DaemonAttr{}). It is kept only for
// backwards API compatibility, but it's usage is otherwise discouraged. Use
// MakeDaemon() instead. The child parameter, previously used to tell whether
// to reset the environment or not (see MakeDaemon()), is currently ignored.
// The environment is reset in all cases.
func Daemonize(child ...bool) {
	MakeDaemon(&DaemonAttr{})
}

// DaemonStage tells in what stage in the process we are. See Stage().
type DaemonStage int

// Stages in the daemonizing process.
const (
	StageParent = DaemonStage(iota) // Original process
	StageChild                      // MakeDaemon() called once: first child
	StageDaemon                     // MakeDaemon() run twice: final daemon

	stageUnknown = DaemonStage(-1)
)

// currStage keeps the current stage. This is used only as a cache for Stage(),
// in order to extend a valid result after MakeDaemon() has returned, where the
// environment variable would have already been reset. (Also, this is faster
// than repetitive calls to getStage().) Note that this approach is valid cause
// the stage doesn't change throughout any single process execution. It does
// only for the next process after the MakeDaemon() call.
var currStage = stageUnknown

// Stage returns the "stage of daemonizing", i.e., it allows you to know whether
// you're currently working in the parent, first child, or the final daemon.
// This is useless after the call to MakeDaemon(), cause that call will only
// return for the daemon stage. However, you can still use Stage() to tell
// whether you've daemonized or not, in case you have a running path that may
// exclude the call to MakeDaemon().
func Stage() DaemonStage {
	if currStage == stageUnknown {
		s, _, _ := getStage()
		currStage = DaemonStage(s)
	}
	return currStage
}

// String returns a humanly readable daemonization stage.
func (s DaemonStage) String() string {
	switch s {
	case StageParent:
		return "parent"
	case StageChild:
		return "first child"
	case StageDaemon:
		return "daemon"
	default:
		return "unknown"
	}
}

// Returns the current stage in the "daemonization process", that's kept in
// an environment variable. The variable is instrumented with a digital
// signature, to avoid misbehavior if it was present in the user's
// environment. The original value is restored after the last stage, so that
// there's no final effect on the environment the application receives.
func getStage() (stage int, advanceStage func() error, resetEnv func() error) {
	var origValue string
	stage = 0

	daemonStage := os.Getenv(stageVar)
	stageTag := strings.SplitN(daemonStage, ":", 2)
	stageInfo := strings.SplitN(stageTag[0], "/", 3)

	if len(stageInfo) == 3 {
		stageStr, tm, check := stageInfo[0], stageInfo[1], stageInfo[2]

		hash := sha1.New()
		hash.Write([]byte(stageStr + "/" + tm + "/"))

		if check != hex.EncodeToString(hash.Sum([]byte{})) {
			// This whole chunk is original data
			origValue = daemonStage
		} else {
			stage, _ = strconv.Atoi(stageStr)

			if len(stageTag) == 2 {
				origValue = stageTag[1]
			}
		}
	} else {
		origValue = daemonStage
	}

	advanceStage = func() error {
		base := fmt.Sprintf("%d/%09d/", stage+1, time.Now().Nanosecond())
		hash := sha1.New()
		hash.Write([]byte(base))
		tag := base + hex.EncodeToString(hash.Sum([]byte{}))

		if err := os.Setenv(stageVar, tag+":"+origValue); err != nil {
			return fmt.Errorf("can't set %s: %s", stageVar, err)
		}
		return nil
	}
	resetEnv = func() error {
		return os.Setenv(stageVar, origValue)
	}

	return stage, advanceStage, resetEnv
}
