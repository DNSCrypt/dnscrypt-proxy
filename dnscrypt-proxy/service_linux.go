// +build !android

package main

import (
	"github.com/coreos/go-systemd/daemon"
	clocksmith "github.com/jedisct1/go-clocksmith"
)

func ServiceManagerStartNotify() error {
	daemon.SdNotify(false, "STATUS=Starting")
	return nil
}

func ServiceManagerReadyNotify() error {
	daemon.SdNotify(false, "READY=1")
	return systemDWatchdog()
}

func systemDWatchdog() error {
	watchdogFailureDelay, err := daemon.SdWatchdogEnabled(false)
	if err != nil || watchdogFailureDelay == 0 {
		return err
	}
	refreshInterval := watchdogFailureDelay / 3
	go func() {
		for {
			// TODO There could be other checks this just
			// checks program is not totally stuck and can
			// run this goroutine
			daemon.SdNotify(false, "WATCHDOG=1")
			clocksmith.Sleep(refreshInterval)
		}

	}()
	return nil
}
