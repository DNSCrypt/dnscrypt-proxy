// +build openbsd

package main

import "unix"

func Pledge() {
	unix.Pledge("stdio rpath wpath cpath tmppath inet fattr flock dns getpw sendfd recvfd proc exec id",
		"stdio rpath wpath cpath tmppath inet fattr flock dns recvfd")
}
