//go:build linux

package quic

import (
	"syscall"

	"golang.org/x/sys/unix"
)

const msgTypeIPTOS = unix.IP_TOS

const (
	ipv4RECVPKTINFO = unix.IP_PKTINFO
	ipv6RECVPKTINFO = unix.IPV6_RECVPKTINFO
)

const (
	msgTypeIPv4PKTINFO = unix.IP_PKTINFO
	msgTypeIPv6PKTINFO = unix.IPV6_PKTINFO
)

const batchSize = 8 // needs to smaller than MaxUint8 (otherwise the type of oobConn.readPos has to be changed)

func forceSetReceiveBuffer(c syscall.RawConn, bytes int) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, bytes)
	}); err != nil {
		return err
	}
	return serr
}

func forceSetSendBuffer(c syscall.RawConn, bytes int) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, bytes)
	}); err != nil {
		return err
	}
	return serr
}
