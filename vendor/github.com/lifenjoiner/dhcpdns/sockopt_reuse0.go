// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

//go:build windows || (js && wasm)
// +build windows js,wasm

package dhcpdns

import (
	"net"
)

// SO_REUSEADDR and SO_REUSEPORT: https://stackoverflow.com/questions/14388706/

// `SO_REUSEADDR` doesn't really work for this on Windows, if `DHCP Client` service occupies the port!
// https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
// On Windows, the 1st bind receives the reply data.
func reuseListenPacket(network, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}
