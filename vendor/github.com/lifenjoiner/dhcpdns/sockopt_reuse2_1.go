// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

//go:build (linux && 386) || (linux && amd64) || (linux && arm)
// +build linux,386 linux,amd64 linux,arm

package dhcpdns

import (
	"context"
	"net"
	"syscall"
)

const SO_REUSEPORT = 0xf

func reuseListenPacket(network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				// SO_REUSEPORT Requires same UID for security reason.
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
		},
	}
	return lc.ListenPacket(context.Background(), network, address)
}
