// +build linux

package main

import "github.com/VividCortex/godaemon"

func Daemonize() {
	godaemon.MakeDaemon(&godaemon.DaemonAttr{})
}
