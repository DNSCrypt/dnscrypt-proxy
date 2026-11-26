//go:build windows

package dns

import "net"

func setUDPSocketOptions(*net.UDPConn) error { return nil }
