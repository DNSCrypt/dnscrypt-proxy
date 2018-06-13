package main

import (
	"net"

	"github.com/coreos/go-systemd/activation"
	"github.com/coreos/go-systemd/daemon"
	"github.com/jedisct1/dlog"
)

func (proxy *Proxy) SystemDListeners() error {
	files := activation.Files(true)

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

func SystemDNotify() {
	daemon.SdNotify(false, "READY=1")
}
