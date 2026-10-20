//go:build windows

package dns

import "net"

var oobSize = func() int { return 0 }()

func setUDPSocketOptions(*net.UDPConn) error { return nil }
func parseFromOOB([]byte, net.IP) net.IP     { return nil }
func sourceFromOOB([]byte) []byte            { return nil }
