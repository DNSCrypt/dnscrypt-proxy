// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

//go:build aix || darwin || dragonfly || freebsd || netbsd || openbsd || (linux && !386 && !amd64 && !arm)
// +build aix darwin dragonfly freebsd netbsd openbsd linux,!386,!amd64,!arm

package dhcpdns

import (
	"context"
	"net"
	"syscall"
)

func reuseListenPacket(network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
			})
		},
	}
	return lc.ListenPacket(context.Background(), network, address)
}
