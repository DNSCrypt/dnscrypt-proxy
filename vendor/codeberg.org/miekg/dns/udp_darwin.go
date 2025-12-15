//go:build darwin

package dns

import (
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func setUDPSocketOptions(conn *net.UDPConn) error {
	ip := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
	switch {
	case ip.Is6():
		// udp://0.0.0.0 == udp://[::] both ipv4 and ipv6 flags must be set
		// on udp6://* ipv4 flags are ignored
		err6 := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
		err4 := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
		if err6 != nil && err4 != nil {
			return err4
		}
	case ip.Is4() && ip == netip.IPv4Unspecified():
		// Per udp(4), setting IP_PKTINFO changes local address to INADDR_ANY.
		// Which is OK if the address is already INADDR_ANY.
		return ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	}
	return nil
}
