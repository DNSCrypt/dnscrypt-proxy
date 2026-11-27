//go:build !darwin && !linux && !freebsd

package udp

import "net/netip"

type PacketInfo struct {
	Addr netip.Addr
}

func (i *PacketInfo) OOB() []byte { return nil }
