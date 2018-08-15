// +build openbsd

package main

import (
	"golang.org/x/sys/unix"
)

func Pledge() {
	unix.Pledge("stdio rpath wpath cpath tmppath inet fattr flock dns getpw sendfd recvfd proc exec id", nil)
}

func PledgeChild() {
	unix.Pledge("stdio rpath wpath cpath tmppath inet fattr flock dns recvfd", nil)
}
