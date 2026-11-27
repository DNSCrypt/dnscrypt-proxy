//go:build !darwin && !linux && !freebsd && !windows && !openbsd

package udp

import (
	"net"
)

func newConn(c net.PacketConn, supportsDF bool) (*basicConn, error) {
	return &basicConn{PacketConn: c, supportsDF: supportsDF}, nil
}

func inspectReadBuffer(any) (int, error)  { return 0, nil }
func inspectWriteBuffer(any) (int, error) { return 0, nil }

const desiredBufferSize = 7 << 20 // 7 MiB
