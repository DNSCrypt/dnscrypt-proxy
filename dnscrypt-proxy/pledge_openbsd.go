// +build openbsd

package main

import (
	"golang.org/x/sys/unix"
)

func Pledge() error {
	err := unix.Pledge("stdio rpath wpath cpath tmppath inet fattr flock dns getpw sendfd recvfd proc exec id unix", "stdio rpath wpath cpath tmppath inet fattr flock dns sendfd recvfd")
	if err != nil {
		return err
	}
	return nil
}

//func PledgeChild() {
//	unix.Pledge("stdio rpath wpath cpath tmppath inet fattr flock dns recvfd", "stdio rpath wpath cpath tmppath inet fattr flock dns recvfd")
//}
