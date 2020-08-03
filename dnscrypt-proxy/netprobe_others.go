// +build !windows

package main

import (
	"net"
	"time"

	"github.com/jedisct1/dlog"
)

func NetProbe(address string, timeout int) error {
	cancelChannels := ColdStart([]string{"0.0.0.0:53"})
	defer ColdStartStop(cancelChannels)
	if len(address) <= 0 || timeout == 0 {
		return nil
	}
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}
	retried := false
	if timeout < 0 {
		timeout = MaxTimeout
	} else {
		timeout = Min(MaxTimeout, timeout)
	}
	for tries := timeout; tries > 0; tries-- {
		pc, err := net.DialUDP("udp", nil, remoteUDPAddr)
		if err != nil {
			if !retried {
				retried = true
				dlog.Notice("Network not available yet -- waiting...")
			}
			dlog.Debug(err)
			time.Sleep(1 * time.Second)
			continue
		}
		pc.Close()
		dlog.Notice("Network connectivity detected")
		return nil
	}
	dlog.Error("Timeout while waiting for network connectivity")
	return nil
}
