// +build !windows,!linux,!darwin

package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"

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
	if err := unix.Setgroups([]int{}); err != nil {
		dlog.Fatalf("Unable to drop additional groups: %s", err)
	}
	if err := unix.Setgid(gid); err != nil {
		dlog.Fatalf("Unable to drop group privileges: %s", err)
	}
	if err := unix.Setuid(uid); err != nil {
		dlog.Fatalf("Unable to drop user privileges: %s", err)
	}
	maxfd := uintptr(0)
	for _, fd := range fds {
		if fd.Fd() > maxfd {
			maxfd = fd.Fd()
		}
	}
	fdbase := maxfd + 1
	for i, fd := range fds {
		if err := unix.Dup2(int(fd.Fd()), int(fdbase+uintptr(i))); err != nil {
			dlog.Fatalf("Unable to clone file descriptor: [%s]", err)
		}
		if _, err := unix.FcntlInt(fd.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			dlog.Fatalf("Unable to set the close on exec flag: [%s]", err)
		}
	}
	for i := range fds {
		if err := unix.Dup2(int(fdbase+uintptr(i)), int(i)+3); err != nil {
			dlog.Fatalf("Unable to reassign descriptor: [%s]", err)
		}
	}
	err = unix.Exec(path, args, os.Environ())
	dlog.Fatalf("Unable to reexecute [%s]: [%s]", path, err)
	os.Exit(1)
}
