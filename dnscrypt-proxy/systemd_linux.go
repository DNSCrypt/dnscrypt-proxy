// +build !android

package main

import (
	"fmt"
	"net"

	"github.com/coreos/go-systemd/activation"
	"github.com/jedisct1/dlog"
)

func (proxy *Proxy) SystemDListeners() error {
	files := activation.Files(true)

	if len(files) > 0 {
		if len(proxy.userName) > 0 || proxy.child {
			dlog.Fatal("Systemd activated sockets are incompatible with privilege dropping. Remove activated sockets and fill `listen_addresses` in the dnscrypt-proxy configuration file instead.")
		}
		dlog.Warn("Systemd sockets are untested and unsupported - use at your own risk")
	}
	for i, file := range files {
		defer file.Close()
		ok := false
		if listener, err := net.FileListener(file); err == nil {
			dlog.Noticef("Wiring systemd TCP socket #%d, %s, %s", i, file.Name(), listener.Addr())
			ok = true
			proxy.wg.Add(1)
			go proxy.tcpListener(listener.(*net.TCPListener))
		} else if pc, err := net.FilePacketConn(file); err == nil {
			dlog.Noticef("Wiring systemd UDP socket #%d, %s, %s", i, file.Name(), pc.LocalAddr())
			ok = true
			proxy.wg.Add(1)
			go proxy.udpListener(pc.(*net.UDPConn))
		}
		if !ok {
			return fmt.Errorf("Could not wire systemd socket #%d, %s", i, file.Name())
		}
	}

	return nil
}
