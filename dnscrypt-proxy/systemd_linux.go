//go:build !android

package main

import (
	"net"

	"github.com/coreos/go-systemd/activation"
	"github.com/jedisct1/dlog"
)

func hasStringElement(array []string, s string) bool {
	for _, ele := range array {
		if ele == s {
			return true
		}
	}
	return false
}

func (proxy *Proxy) addSystemDListeners() error {
	files := activation.Files(true)

	if len(files) > 0 {
		if len(proxy.userName) > 0 || proxy.child {
			dlog.Fatal(
				"Systemd activated sockets are incompatible with privilege dropping. Remove activated sockets and fill `listen_addresses` in the dnscrypt-proxy configuration file instead.",
			)
		}
		dlog.Warn("Systemd sockets are untested and unsupported - use at your own risk")
		proxy.listenAddresses = make([]string, 0)
	}
	for i, file := range files {
		defer file.Close()
		var listenAddress string
		if listener, err := net.FileListener(file); err == nil {
			proxy.registerTCPListener(listener.(*net.TCPListener))
			listenAddress = listener.Addr().String()
			dlog.Noticef("Wiring systemd TCP socket #%d, %s, %s", i, file.Name(), listenAddress)
		} else if pc, err := net.FilePacketConn(file); err == nil {
			proxy.registerUDPListener(pc.(*net.UDPConn))
			listenAddress = pc.LocalAddr().String()
			dlog.Noticef("Wiring systemd UDP socket #%d, %s, %s", i, file.Name(), listenAddress)
		}
		if len(listenAddress) > 0 && !hasStringElement(proxy.listenAddresses, listenAddress) {
			proxy.listenAddresses = append(proxy.listenAddresses, listenAddress)
		}
	}
	return nil
}
