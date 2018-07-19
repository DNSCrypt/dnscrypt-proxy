package main

import (
	"net"

	"github.com/coreos/go-systemd/activation"
	"github.com/jedisct1/dlog"
)

func (proxy *Proxy) SystemDListeners() error {
	files := activation.Files(true)

	if len(files) > 0 && (len(proxy.userName) > 0 || proxy.child) {
		dlog.Fatal("Systemd activated sockets are incompatible with privilege dropping. Remove activated sockets and fill `listen_addresses` in the dnscrypt-proxy configuration file instead.")
	}

	for i, file := range files {
		if listener, err := net.FileListener(file); err == nil {
			dlog.Noticef("Wiring systemd TCP socket #%d, %s, %s", i, file.Name(), listener.Addr())
			go proxy.tcpListener(listener.(*net.TCPListener))
		} else if pc, err := net.FilePacketConn(file); err == nil {
			dlog.Noticef("Wiring systemd UDP socket #%d, %s, %s", i, file.Name(), pc.LocalAddr())
			go proxy.udpListener(pc.(*net.UDPConn))
		}
		file.Close()
	}

	return nil
}
