// +build !windows

package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/jedisct1/dlog"
)

func (proxy *Proxy) dropPrivilege(userStr string, fds []*os.File) {
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

	args = args[1:]
	args = append(args, "-child")

	cmd := exec.Command(path, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = fds
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	dlog.Notice("Dropping privileges")
	if err := cmd.Run(); err != nil {
		dlog.Fatal(err)
	}
	os.Exit(0)
}
