// +build !windows

package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

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

	ServiceManagerReadyNotify()

	args = args[1:]
	args = append(args, "-child")

	dlog.Notice("Dropping privileges")
	for {
		cmd := exec.Command(path, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.ExtraFiles = fds
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
		if cmd.Run() == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	os.Exit(0)
}
