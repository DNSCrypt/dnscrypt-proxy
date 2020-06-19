package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/jedisct1/dlog"
)

func (proxy *Proxy) dropPrivilege(userStr string, fds []*os.File) {
	currentUser, err := user.Current()
	if err != nil && currentUser.Uid != "0" {
		dlog.Fatal("Root privileges are required in order to switch to a different user. Maybe try again with 'sudo'")
	}
	userInfo, err := user.Lookup(userStr)
	args := os.Args

	if err != nil {
		uid, err2 := strconv.Atoi(userStr)
		if err2 != nil || uid <= 0 {
			dlog.Fatalf("Unable to retrieve any information about user [%s]: [%s] - Remove the user_name directive from the configuration file in order to avoid identity switch", userStr, err)
		}
		dlog.Warnf("Unable to retrieve any information about user [%s]: [%s] - Switching to user id [%v] with the same group id, as [%v] looks like a user id. But you should remove or fix the user_name directive in the configuration file if possible", userStr, err, uid, uid)
		userInfo = &user.User{Uid: userStr, Gid: userStr}
	}
	uid, err := strconv.Atoi(userInfo.Uid)
	if err != nil {
		dlog.Fatal(err)
	}
	gid, err := strconv.Atoi(userInfo.Gid)
	if err != nil {
		dlog.Fatal(err)
	}
	execPath, err := exec.LookPath(args[0])
	if err != nil {
		dlog.Fatalf("Unable to get the path to the dnscrypt-proxy executable file: [%s]", err)
	}
	path, err := filepath.Abs(execPath)
	if err != nil {
		dlog.Fatal(err)
	}

	if err := ServiceManagerReadyNotify(); err != nil {
		dlog.Fatal(err)
	}

	args = append(args, "-child")

	dlog.Notice("Dropping privileges")

	runtime.LockOSThread()
	if _, _, rcode := syscall.RawSyscall(syscall.SYS_SETGROUPS, uintptr(0), uintptr(0), 0); rcode != 0 {
		dlog.Fatalf("Unable to drop additional groups: [%s]", rcode.Error())
	}
	if _, _, rcode := syscall.RawSyscall(syscall.SYS_SETGID, uintptr(gid), 0, 0); rcode != 0 {
		dlog.Fatalf("Unable to drop group privileges: [%s]", rcode.Error())
	}
	if _, _, rcode := syscall.RawSyscall(syscall.SYS_SETUID, uintptr(uid), 0, 0); rcode != 0 {
		dlog.Fatalf("Unable to drop user privileges: [%s]", rcode.Error())
	}
	for i, fd := range fds {
		if fd.Fd() >= InheritedDescriptorsBase {
			dlog.Fatal("Duplicated file descriptors are above base")
		}
		if err := unix.Dup2(int(fd.Fd()), int(InheritedDescriptorsBase+uintptr(i))); err != nil {
			dlog.Fatalf("Unable to clone file descriptor: [%s]", err)
		}
		if _, err := unix.FcntlInt(fd.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			dlog.Fatalf("Unable to set the close on exec flag: [%s]", err)
		}
	}
	err = unix.Exec(path, args, os.Environ())
	dlog.Fatalf("Unable to reexecute [%s]: [%s]", path, err)
	os.Exit(1)
}
