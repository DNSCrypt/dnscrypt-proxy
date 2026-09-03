//go:build !darwin && !linux && !freebsd && !windows

package quic

import (
	"net"
	"net/netip"
)

func newConn(c net.PacketConn, supportsDF bool) (*basicConn, error) {
	return &basicConn{PacketConn: c, supportsDF: supportsDF}, nil
}

type packetInfo struct {
	addr netip.Addr
}

func (i *packetInfo) OOB() []byte { return nil }
