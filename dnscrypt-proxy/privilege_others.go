// +build !windows,!linux

package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/jedisct1/dlog"
)

var cmd *exec.Cmd

func (proxy *Proxy) dropPrivilege(userStr string, fds []*os.File) {
	currentUser, err := user.Current()
	if err != nil && currentUser.Uid != "0" {
		dlog.Fatal("Root privileges are required in order to switch to a different user. Maybe try again with 'sudo'")
	}
	user, err := user.Lookup(userStr)
	args := os.Args

	if err != nil {
		dlog.Fatal(err)
	}
	uid, err := strconv.Atoi(user.Uid)
	if err != nil {
		dlog.Fatal(err)
	}
	gid, err := strconv.Atoi(user.Gid)
	if err != nil {
		dlog.Fatal(err)
	}
	execPath, err := exec.LookPath(args[0])
	if err != nil {
		dlog.Fatal(err)
	}
	path, err := filepath.Abs(execPath)
	if err != nil {
		dlog.Fatal(err)
	}

	ServiceManagerReadyNotify()

	args = append(args, "-child")

	dlog.Notice("Dropping privileges")
	runtime.LockOSThread()
	if _, _, rcode := syscall.RawSyscall(syscall.SYS_SETGROUPS, uintptr(0), uintptr(0), 0); rcode != 0 {
		dlog.Fatalf("Unable to drop additional groups: %s", err)
	}
	if _, _, rcode := syscall.RawSyscall(syscall.SYS_SETGID, uintptr(gid), 0, 0); rcode != 0 {
		dlog.Fatalf("Unable to drop user privileges: %s", err)
	}
	if _, _, rcode := syscall.RawSyscall(syscall.SYS_SETUID, uintptr(uid), 0, 0); rcode != 0 {
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
		if _, _, rcode := syscall.RawSyscall(syscall.SYS_DUP2, fd.Fd(), fdbase+uintptr(i), 0); rcode != 0 {
			dlog.Fatal("Unable to clone file descriptor")
		}
		if _, _, rcode := syscall.RawSyscall(syscall.SYS_FCNTL, fd.Fd(), syscall.F_SETFD, syscall.FD_CLOEXEC); rcode != 0 {
			dlog.Fatal("Unable to set the close on exec flag")
		}
	}
	for i := range fds {
		if _, _, rcode := syscall.RawSyscall(syscall.SYS_DUP2, fdbase+uintptr(i), uintptr(i)+3, 0); rcode != 0 {
			dlog.Fatal("Unable to reassign descriptor")
		}
	}
	err = syscall.Exec(path, args, os.Environ())
	dlog.Fatalf("Unable to reexecute [%s]: [%s]", path, err)
	os.Exit(1)
}
