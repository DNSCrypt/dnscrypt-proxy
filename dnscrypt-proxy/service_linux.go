//go:build !android
// +build !android

package main

import (
	"github.com/coreos/go-systemd/daemon"
	clocksmith "github.com/jedisct1/go-clocksmith"
)

const SdNotifyStatus = "STATUS="

func ServiceManagerStartNotify() error {
	daemon.SdNotify(false, SdNotifyStatus+"Starting...")
	return nil
}

func ServiceManagerReadyNotify() error {
	daemon.SdNotify(false, daemon.SdNotifyReady+"\n"+SdNotifyStatus+"Ready")
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
			daemon.SdNotify(false, daemon.SdNotifyWatchdog)
			clocksmith.Sleep(refreshInterval)
		}
	}()
	return nil
}
