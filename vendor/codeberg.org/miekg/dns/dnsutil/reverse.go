package dnsutil

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// IP4arpa is the reverse tree suffix for v4 IP addresses.
	IP4arpa = ".in-addr.arpa."
	// IP6arpa is the reverse tree suffix for v6 IP addresses.
	IP6arpa = ".ip6.arpa."
)

// IsReverse returns 0 if name is not a reverse zone. Anything > 0 indicates
// name is in a reverse zone. The returned integer will be [IPv4Family] for in-addr.arpa, (IPv4).
// and [IPv6Family] for ip6.arpa, (IPv6). see [Family]. A valid name is assumed.
func IsReverse(s string) int {
	if strings.HasSuffix(s, IP4arpa) {
		return IPv4Family
	}
	if strings.HasSuffix(s, IP6arpa) {
		return IPv6Family
	}
	return 0
}

// ReverseAddr returns the in-addr.arpa. or ip6.arpa. hostname of the IP
// address suitable for reverse DNS ([dns.PTR]) record lookups. Also see [AddrReverse].
func ReverseAddr(ip netip.Addr) (arpa string) {
	const hexDigit = "0123456789abcdef"

	if ip.Is4() {
		v4 := ip.As4()
		buf := make([]byte, 0, net.IPv4len*4+len(IP4arpa))
		// Add it, in reverse, to the buffer
		for i := len(v4) - 1; i >= 0; i-- {
			buf = strconv.AppendInt(buf, int64(v4[i]), 10)
			buf = append(buf, '.')
		}
		// Append "in-addr.arpa." and return (buf already has the final .)
		buf = append(buf, IP4arpa[1:]...)
		return string(buf)
	}
	// Must be IPv6
	buf := make([]byte, 0, net.IPv6len*4+len(IP6arpa))
	v6 := ip.As16()
	// Add it, in reverse, to the buffer
	for i := len(v6) - 1; i >= 0; i-- {
		v := v6[i]
		buf = append(buf, hexDigit[v&0xF], '.', hexDigit[v>>4], '.')
	}
	// Append "ip6.arpa." and return (buf already has the final .)
	buf = append(buf, IP6arpa[1:]...)
	return string(buf)
}

// AddrReverse turns a standard [dns.PTR] reverse record name into an IP address.
// 54.119.58.176.in-addr.arpa. becomes 176.58.119.54. If the conversion
// fails nil is returned. Also see [ReverseAddr].
func AddrReverse(s string) (ip netip.Addr) {
	switch IsReverse(s) {
	case IPv4Family:
		var v4 [4]byte
		idx := 0
		// Loop backwards through the bytes of the IPv4 address (d, c, b, a)
		// which appear in forward order in the reverse name (a.b.c.d).
		// e.g. 54.119.58.176.in-addr.arpa. -> 176.58.119.54
		// 54 (byte 3) is first, 176 (byte 0) is last.
		for i := 3; i >= 0; i-- {
			if idx >= len(s) {
				return netip.Addr{}
			}
			if s[idx] < '0' || s[idx] > '9' {
				return netip.Addr{}
			}
			n := 0
			for idx < len(s) && s[idx] >= '0' && s[idx] <= '9' {
				n = n*10 + int(s[idx]-'0')
				if n > 255 {
					return netip.Addr{}
				}
				idx++
			}
			v4[i] = byte(n)

			// Consumed number, expect a dot.
			if idx >= len(s) || s[idx] != '.' {
				return netip.Addr{}
			}
			idx++
		}
		// The remainder must be exactly "in-addr.arpa."
		if s[idx:] != "in-addr.arpa." {
			return netip.Addr{}
		}
		return netip.AddrFrom4(v4)

	case IPv6Family:
		var v6 [16]byte
		idx := 0
		// 32 nibbles.
		// Reverse name: low nibble of byte 15, high nibble of byte 15, ...
		for i := range 32 {
			if idx >= len(s) {
				return netip.Addr{}
			}
			c := s[idx]
			var val byte
			switch {
			case c >= '0' && c <= '9':
				val = c - '0'
			case c >= 'a' && c <= 'f':
				val = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				val = c - 'A' + 10
			default:
				return netip.Addr{}
			}

			// i=0 -> byte 15, low part
			// i=1 -> byte 15, high part
			// i=2 -> byte 14, low part
			pos := 15 - (i / 2)
			if i%2 == 0 {
				v6[pos] |= val
			} else {
				v6[pos] |= val << 4
			}

			idx++
			if idx >= len(s) || s[idx] != '.' {
				return netip.Addr{}
			}
			idx++
		}
		if s[idx:] != "ip6.arpa." {
			return netip.Addr{}
		}
		return netip.AddrFrom16(v6)
	default:
		return netip.Addr{}
	}
}
