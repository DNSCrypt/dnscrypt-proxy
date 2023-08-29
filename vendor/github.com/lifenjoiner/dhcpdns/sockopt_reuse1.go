// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

//go:build solaris
// +build solaris

package dhcpdns

import (
	"context"
	"net"
	"syscall"
)

// No SO_REUSEPORT implemented. Doesn't work for SO_EXCLBIND on Solaris.
func reuseListenPacket(network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
		},
	}
	return lc.ListenPacket(context.Background(), network, address)
}
