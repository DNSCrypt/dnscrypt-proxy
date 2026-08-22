package main

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func usableNonLoopbackIPv4(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("unable to enumerate interface addresses: %v", err)
	}
	for _, interfaceAddr := range addrs {
		ip, _, err := net.ParseCIDR(interfaceAddr.String())
		if err == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast() {
			return ip.To4()
		}
	}
	t.Skip("host has no usable non-loopback IPv4 address")
	return nil
}

func TestOutboundSourceSocketHelpersLocalBypass(t *testing.T) {
	policy, err := parseOutboundSourcePolicy("192.0.2.10", "2001:db8::10")
	if err != nil {
		t.Fatal(err)
	}
	tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	acceptDone := make(chan error, 1)
	go func() {
		conn, err := tcpListener.Accept()
		if err == nil {
			err = conn.Close()
		}
		acceptDone <- err
	}()
	tcpConn, err := policy.dialTCP(tcpListener.Addr().(*net.TCPAddr).AddrPort(), time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !tcpConn.LocalAddr().(*net.TCPAddr).IP.IsLoopback() {
		t.Fatalf("unexpected TCP source: %s", tcpConn.LocalAddr())
	}
	tcpConn.Close()
	if err := <-acceptDone; err != nil {
		t.Fatal(err)
	}

	udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpListener.Close()
	udpConn, err := policy.dialUDP(udpListener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if !udpConn.LocalAddr().(*net.UDPAddr).IP.IsLoopback() {
		t.Fatalf("unexpected UDP source: %s", udpConn.LocalAddr())
	}
	udpConn.Close()

	ipv4Loopback := netip.MustParseAddr("127.0.0.1")
	unconnected, network, destination, err := policy.listenUDP(ipv4Loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer unconnected.Close()
	if network != "udp4" || destination != ipv4Loopback {
		t.Fatalf("got network=%s destination=%s", network, destination)
	}
}

func TestParseOutboundSourcePolicy(t *testing.T) {
	tests := []struct {
		name      string
		ipv4      string
		ipv6      string
		wantIPv4  string
		wantIPv6  string
		wantError string
	}{
		{name: "disabled"},
		{name: "IPv4", ipv4: "192.0.2.10", wantIPv4: "192.0.2.10"},
		{name: "mapped IPv4", ipv4: "::ffff:192.0.2.11", wantIPv4: "192.0.2.11"},
		{name: "IPv6", ipv6: "2001:db8::10", wantIPv6: "2001:db8::10"},
		{name: "scoped IPv6", ipv6: "fe80::1%en0", wantIPv6: "fe80::1%en0"},
		{name: "dual stack", ipv4: "192.0.2.10", ipv6: "2001:db8::10", wantIPv4: "192.0.2.10", wantIPv6: "2001:db8::10"},
		{name: "wrong IPv4 family", ipv4: "2001:db8::1", wantError: "expected an IPv4"},
		{name: "wrong IPv6 family", ipv6: "192.0.2.1", wantError: "expected an IPv6"},
		{name: "unspecified IPv4", ipv4: "0.0.0.0", wantError: "cannot be unspecified"},
		{name: "unspecified IPv6", ipv6: "::", wantError: "cannot be unspecified"},
		{name: "multicast IPv4", ipv4: "224.0.0.1", wantError: "cannot be unspecified"},
		{name: "multicast IPv6", ipv6: "ff02::1%en0", wantError: "cannot be unspecified"},
		{name: "limited broadcast", ipv4: "255.255.255.255", wantError: "cannot be unspecified"},
		{name: "CIDR", ipv4: "192.0.2.1/24", wantError: "expected an IP address literal"},
		{name: "hostname", ipv4: "example.com", wantError: "expected an IP address literal"},
		{name: "interface", ipv6: "en0", wantError: "expected an IP address literal"},
		{name: "address and port", ipv4: "192.0.2.1:53", wantError: "expected an IP address literal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := parseOutboundSourcePolicy(test.ipv4, test.ipv6)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want containing %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			gotIPv4 := ""
			if policy.ipv4.IsValid() {
				gotIPv4 = policy.ipv4.String()
			}
			gotIPv6 := ""
			if policy.ipv6.IsValid() {
				gotIPv6 = policy.ipv6.String()
			}
			if gotIPv4 != test.wantIPv4 {
				t.Fatalf("IPv4 = %q, want %q", gotIPv4, test.wantIPv4)
			}
			if gotIPv6 != test.wantIPv6 {
				t.Fatalf("IPv6 = %q, want %q", gotIPv6, test.wantIPv6)
			}
		})
	}
}

func TestOutboundSourceFor(t *testing.T) {
	policy, err := parseOutboundSourcePolicy("192.0.2.10", "2001:db8::10")
	if err != nil {
		t.Fatal(err)
	}
	mappedUnspecified := netip.MustParseAddr("::ffff:0.0.0.0")
	if mappedUnspecified.String() != "::ffff:0.0.0.0" {
		t.Fatalf("unexpected mapped unspecified representation: %s", mappedUnspecified)
	}
	tests := []struct {
		name        string
		destination netip.Addr
		wantDest    string
		wantSource  string
		wantFamily  outboundSourceFamily
		wantBind    bool
	}{
		{name: "IPv4", destination: netip.MustParseAddr("9.9.9.9"), wantDest: "9.9.9.9", wantSource: "192.0.2.10", wantFamily: outboundSourceIPv4, wantBind: true},
		{name: "mapped IPv4", destination: netip.MustParseAddr("::ffff:9.9.9.9"), wantDest: "9.9.9.9", wantSource: "192.0.2.10", wantFamily: outboundSourceIPv4, wantBind: true},
		{name: "IPv6", destination: netip.MustParseAddr("2001:4860:4860::8888"), wantDest: "2001:4860:4860::8888", wantSource: "2001:db8::10", wantFamily: outboundSourceIPv6, wantBind: true},
		{name: "loopback IPv4", destination: netip.MustParseAddr("127.0.0.1"), wantDest: "127.0.0.1", wantFamily: outboundSourceIPv4},
		{name: "mapped loopback", destination: netip.MustParseAddr("::ffff:127.0.0.1"), wantDest: "127.0.0.1", wantFamily: outboundSourceIPv4},
		{name: "loopback IPv6", destination: netip.IPv6Loopback(), wantDest: "::1", wantFamily: outboundSourceIPv6},
		{name: "unspecified IPv4", destination: netip.IPv4Unspecified(), wantDest: "0.0.0.0", wantFamily: outboundSourceIPv4},
		{name: "mapped unspecified", destination: mappedUnspecified, wantDest: "0.0.0.0", wantFamily: outboundSourceIPv4},
		{name: "unspecified IPv6", destination: netip.IPv6Unspecified(), wantDest: "::", wantFamily: outboundSourceIPv6},
		{name: "private IPv4 is covered", destination: netip.MustParseAddr("10.0.0.1"), wantDest: "10.0.0.1", wantSource: "192.0.2.10", wantFamily: outboundSourceIPv4, wantBind: true},
		{name: "ULA is covered", destination: netip.MustParseAddr("fd00::1"), wantDest: "fd00::1", wantSource: "2001:db8::10", wantFamily: outboundSourceIPv6, wantBind: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := policy.sourceFor(test.destination)
			if err != nil {
				t.Fatal(err)
			}
			gotSource := ""
			if target.source.IsValid() {
				gotSource = target.source.String()
			}
			if target.destination.String() != test.wantDest || gotSource != test.wantSource ||
				target.family != test.wantFamily || target.bound() != test.wantBind {
				t.Fatalf("got destination=%s source=%s family=%d bound=%v",
					target.destination, target.source, target.family, target.bound())
			}
		})
	}
	if _, err := policy.sourceFor(netip.Addr{}); err == nil {
		t.Fatal("invalid destination was accepted")
	}
}

func TestOutboundSourceAddressRepresentations(t *testing.T) {
	policy, err := parseOutboundSourcePolicy("192.0.2.10", "2001:db8::10")
	if err != nil {
		t.Fatal(err)
	}
	tcpResolved, err := net.ResolveTCPAddr("tcp", "9.9.9.9:53")
	if err != nil {
		t.Fatal(err)
	}
	udpResolved, err := net.ResolveUDPAddr("udp", "9.9.9.9:53")
	if err != nil {
		t.Fatal(err)
	}
	addresses := []net.IP{net.IPv4(9, 9, 9, 9), net.ParseIP("9.9.9.9"), tcpResolved.IP, udpResolved.IP}
	for _, ip := range addresses {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			t.Fatalf("unusable address %v", ip)
		}
		target, err := policy.sourceFor(addr)
		if err != nil {
			t.Fatal(err)
		}
		if target.destination.String() != "9.9.9.9" || target.source.String() != "192.0.2.10" ||
			target.family != outboundSourceIPv4 || !target.bound() {
			t.Fatalf("unexpected selection for %T(%v): %+v", ip, ip, target)
		}
		if target.destination.Is4In6() {
			t.Fatal("mapped destination reached the socket boundary")
		}
	}
}

func TestOutboundSourceDialerOptionsAndZones(t *testing.T) {
	policy, err := parseOutboundSourcePolicy("192.0.2.10", "fe80::1%en0")
	if err != nil {
		t.Fatal(err)
	}
	target, err := policy.sourceFor(netip.MustParseAddr("2001:db8::20"))
	if err != nil {
		t.Fatal(err)
	}
	if target.networkFor("tcp") != "tcp6" || target.destination.String() != "2001:db8::20" {
		t.Fatalf("unexpected target: %+v", target)
	}
	local := net.TCPAddrFromAddrPort(netip.AddrPortFrom(target.source, 0))
	if local.Port != 0 || local.Zone != "en0" || !local.IP.Equal(net.ParseIP("fe80::1")) {
		t.Fatalf("unexpected local address: %#v", local)
	}
}

func TestOutboundSourceMissingFamily(t *testing.T) {
	policy, err := parseOutboundSourcePolicy("192.0.2.10", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = policy.sourceFor(netip.MustParseAddr("2001:db8::1"))
	if err == nil || !strings.Contains(err.Error(), "outbound_source_ipv6") {
		t.Fatalf("error = %v", err)
	}
}

func TestNewDNSTransportHasIndependentDialer(t *testing.T) {
	first := newDNSTransport()
	second := newDNSTransport()
	if first.Dialer == second.Dialer {
		t.Fatal("DNS transports share a dialer")
	}
	if first.Dialer.Timeout != 5*time.Second || first.Dialer.KeepAlive != 3*time.Second {
		t.Fatalf("unexpected DNS dialer defaults: %+v", first.Dialer)
	}
	first.Dialer.Timeout = time.Second
	if second.Dialer.Timeout != 5*time.Second {
		t.Fatal("mutating one DNS dialer changed another")
	}
}

func TestConfigureDNSTransport(t *testing.T) {
	policy, err := parseOutboundSourcePolicy("192.0.2.10", "2001:db8::10")
	if err != nil {
		t.Fatal(err)
	}
	transport := newDNSTransport()
	originalDialer := transport.Dialer
	network, resolver, _, err := policy.configureDNSTransport(transport, "udp", "[::ffff:9.9.9.9]:53", true)
	if err != nil {
		t.Fatal(err)
	}
	if network != "udp4" || resolver != "9.9.9.9:53" {
		t.Fatalf("got %q %q", network, resolver)
	}
	if transport.Dialer == originalDialer {
		t.Fatal("DNS transport dialer was mutated instead of replaced")
	}
	local, ok := transport.Dialer.LocalAddr.(*net.UDPAddr)
	if !ok || !local.IP.Equal(net.ParseIP("192.0.2.10")) || local.Port != 0 {
		t.Fatalf("unexpected DNS local address: %#v", transport.Dialer.LocalAddr)
	}
}

func TestConfigureDNSTransportLocalBypass(t *testing.T) {
	policy, err := parseOutboundSourcePolicy("192.0.2.10", "2001:db8::10")
	if err != nil {
		t.Fatal(err)
	}
	transport := newDNSTransport()
	transport.Dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}
	originalDialer := transport.Dialer
	network, resolver, _, err := policy.configureDNSTransport(transport, "udp", "127.0.0.1:53", true)
	if err != nil {
		t.Fatal(err)
	}
	if network != "udp4" || resolver != "127.0.0.1:53" || transport.Dialer.LocalAddr != nil || transport.Dialer == originalDialer {
		t.Fatalf("local bypass retained binding: network=%s resolver=%s dialer=%+v", network, resolver, transport.Dialer)
	}
}

func TestOutboundSourceDNSErrorContext(t *testing.T) {
	policy, err := parseOutboundSourcePolicy("192.0.2.10", "")
	if err != nil {
		t.Fatal(err)
	}
	_, _, target, err := policy.configureDNSTransport(newDNSTransport(), "udp", "9.9.9.9:53", true)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := target.wrapDialError("udp", net.ErrClosed)
	for _, want := range []string{"outbound_source_ipv4", "192.0.2.10", "udp4", "9.9.9.9"} {
		if !strings.Contains(wrapped.Error(), want) {
			t.Fatalf("error %q does not contain %q", wrapped, want)
		}
	}
	_, _, local, err := policy.configureDNSTransport(newDNSTransport(), "udp", "127.0.0.1:53", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := local.wrapDialError("udp", net.ErrClosed); got != net.ErrClosed {
		t.Fatalf("local error was wrapped: %v", got)
	}
	var uncovered *outboundTarget
	if got := uncovered.wrapDialError("udp", net.ErrClosed); got != net.ErrClosed {
		t.Fatalf("uncovered error was wrapped: %v", got)
	}
}

func TestOutboundSourceDisabledHelpersDoNotNormalize(t *testing.T) {
	policy := outboundSourcePolicy{}
	mapped := netip.MustParseAddr("::ffff:9.9.9.9")
	conn, network, destination, err := policy.listenUDP(mapped)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if network != "udp" || destination != mapped {
		t.Fatalf("disabled UDP listener changed destination: network=%s destination=%s", network, destination)
	}
}
