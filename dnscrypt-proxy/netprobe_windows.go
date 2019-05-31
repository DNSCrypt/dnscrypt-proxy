package main

import (
	"errors"
	"net"
 	"time"

	"github.com/jedisct1/dlog"
)

func NetProbe(address string, timeout int) error {
	if len(address) <= 0 || timeout <= 0 {
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
		timeout = Max(MaxTimeout, timeout)
	}
	for tries := timeout; tries > 0; tries-- {
		pc, err := net.DialUDP("udp", nil, remoteUDPAddr)
		if err == nil {
			// Write at least 1 byte. This ensures that sockets are ready to use for writing.
			// Windows specific: during the system startup, sockets can be created but the underlying buffers may not be setup yet. If this is the case
			// Write fails with WSAENOBUFS: "An operation on a socket could not be performed because the system lacked sufficient buffer space or because a queue was full"
			_, err = pc.Write([]byte{0})
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
		pc.Close()
		dlog.Notice("Network connectivity detected")
		return nil
	}
	es := "Timeout while waiting for network connectivity"
	dlog.Error(es)
	return errors.New(es)
}
