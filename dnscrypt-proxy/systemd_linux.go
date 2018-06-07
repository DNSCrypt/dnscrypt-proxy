package main

import (
	"net"

	"github.com/coreos/go-systemd/activation"
	"github.com/coreos/go-systemd/daemon"
	"github.com/jedisct1/dlog"
)

func (proxy *Proxy) SystemDListeners() error {
	listeners, err := activation.Listeners()
	if err == nil && len(listeners) > 0 {
		for i, listener := range listeners {
			if listener != nil {
				dlog.Noticef("Wiring systemd TCP socket #%d", i)
				go proxy.tcpListener(listener.(*net.TCPListener))
			}
		}
	}
	packetConns, err := activation.PacketConns()
	if err == nil && len(packetConns) > 0 {
		for i, packetConn := range packetConns {
			if packetConn != nil {
				dlog.Noticef("Wiring systemd UDP socket #%d", i)
				go proxy.udpListener(packetConn.(*net.UDPConn))
			}
		}
	}
	return nil
}

func SystemDNotify() {
	daemon.SdNotify(false, "READY=1")
}
