package main

import "github.com/coreos/go-systemd/daemon"

func ServiceManagerStartNotify() error {
	daemon.SdNotify(false, "STATUS=Starting")
	return nil
}

func ServiceManagerReadyNotify() {
	daemon.SdNotify(false, "READY=1")
}
