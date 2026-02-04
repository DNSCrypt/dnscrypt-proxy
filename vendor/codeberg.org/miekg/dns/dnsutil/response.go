package dnsutil

import (
	"net"
	"net/netip"
	"strconv"

	"codeberg.org/miekg/dns"
)

// RemoteIP returns the IP address of the client making the request.
func RemoteIP(w dns.ResponseWriter) string {
	switch t := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		return t.AddrPort().Addr().String()
	case *net.TCPAddr:
		return t.AddrPort().Addr().String()
	}
	return ""
}

// LocalIP gets the IP address of server handling the request.
func LocalIP(w dns.ResponseWriter) string {
	switch t := w.LocalAddr().(type) {
	case *net.UDPAddr:
		return t.AddrPort().Addr().String()
	case *net.TCPAddr:
		return t.AddrPort().Addr().String()
	}
	return ""
}

// RemotePort gets the port of the client making the request.
func RemotePort(w dns.ResponseWriter) string {
	switch t := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		return strconv.Itoa(t.Port)
	case *net.TCPAddr:
		return strconv.Itoa(t.Port)
	}
	return ""
}

// LocalPort gets the local port of the server handling the request.
func LocalPort(w dns.ResponseWriter) string {
	switch t := w.LocalAddr().(type) {
	case *net.UDPAddr:
		return strconv.Itoa(t.Port)
	case *net.TCPAddr:
		return strconv.Itoa(t.Port)
	}
	return ""
}

// Network returns the network used to make the request, this can be udp or tcp.
func Network(w dns.ResponseWriter) string {
	switch w.RemoteAddr().(type) {
	case *net.UDPAddr:
		return "udp"
	case *net.TCPAddr:
		return "tcp"
	}
	return "udp"
}

// Family returns the family of the transport, which is either [IPv4Family] or [IPv6Family] as defined by IANA.
func Family(w dns.ResponseWriter) int {
	var a netip.Addr
	switch t := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		a = t.AddrPort().Addr()
	case *net.TCPAddr:
		a = t.AddrPort().Addr()
	}

	if a.Is4In6() {
		return IPv4Family
	}
	if a.Is4() {
		return IPv4Family
	}
	return IPv6Family
}

// The IP address families are defined by IANA, and can be found at https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
const (
	IPv4Family = 1
	IPv6Family = 2
)
