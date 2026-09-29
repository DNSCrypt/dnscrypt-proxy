//go:build !windows

package main

import (
	"net"
	"time"

	"github.com/jedisct1/dlog"
)

func NetProbe(proxy *Proxy, address string, timeout int) error {
	if len(address) <= 0 || timeout == 0 {
		return nil
	}
	if captivePortalHandler, err := ColdStart(proxy); err == nil {
		if captivePortalHandler != nil {
			defer captivePortalHandler.Stop()
		}
	} else {
		dlog.Critical(err)
	}
	remoteUDPAddrs, err := resolveNetprobeAddresses(address)
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
		var err error
		for _, remoteUDPAddr := range remoteUDPAddrs {
			var pc net.Conn
			pc, err = net.DialTimeout("udp", remoteUDPAddr.String(), proxy.timeout)
			if err == nil {
				pc.Close()
				break
			}
		}
		if err != nil {
			if !retried {
				retried = true
				dlog.Notice("Network not available yet -- waiting...")
			}
			dlog.Debug(err)
			time.Sleep(1 * time.Second)
			continue
		}
		dlog.Notice("Network connectivity detected")
		return nil
	}
	dlog.Error("Timeout while waiting for network connectivity")
	return nil
}
