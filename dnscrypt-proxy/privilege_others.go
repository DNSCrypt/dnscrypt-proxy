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

var cmd *exec.Cmd

func (proxy *Proxy) dropPrivilege(userStr string, fds []*os.File) {
	currentUser, err := user.Current()
	if err != nil {
		dlog.Fatal(err)
	}
	if currentUser.Uid != "0" {
		dlog.Fatal("I need root permissions. Try again with 'sudo'")
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

	args = args[1:]
	args = append(args, "-child")

	dlog.Notice("Dropping privileges")
	for {
		cmd = exec.Command(path, args...)
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

func killChild() {
	if cmd != nil {
		if err := cmd.Process.Kill(); err != nil {
			dlog.Fatal("Failed to kill child process.")
		}
	}
}
