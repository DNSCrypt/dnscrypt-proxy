package main

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func nonLoopbackIPv4(t *testing.T) net.IP {
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

func TestListenUDPLoopback(t *testing.T) {
	policy, err := parseOutboundSources("192.0.2.10", "2001:db8::10")
	if err != nil {
		t.Fatal(err)
	}
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

func TestOutboundSourceFor(t *testing.T) {
	policy, err := parseOutboundSources("192.0.2.10", "2001:db8::10")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		destination netip.Addr
		wantDest    string
		wantSource  string
	}{
		{name: "IPv4", destination: netip.MustParseAddr("9.9.9.9"), wantDest: "9.9.9.9", wantSource: "192.0.2.10"},
		{name: "mapped IPv4", destination: netip.MustParseAddr("::ffff:9.9.9.9"), wantDest: "9.9.9.9", wantSource: "192.0.2.10"},
		{name: "IPv6", destination: netip.MustParseAddr("2001:4860:4860::8888"), wantDest: "2001:4860:4860::8888", wantSource: "2001:db8::10"},
		{name: "loopback IPv4", destination: netip.MustParseAddr("127.0.0.1"), wantDest: "127.0.0.1"},
		{name: "mapped loopback", destination: netip.MustParseAddr("::ffff:127.0.0.1"), wantDest: "127.0.0.1"},
		{name: "loopback IPv6", destination: netip.IPv6Loopback(), wantDest: "::1"},
		{name: "unspecified IPv4", destination: netip.IPv4Unspecified(), wantDest: "0.0.0.0"},
		{name: "mapped unspecified", destination: netip.MustParseAddr("::ffff:0.0.0.0"), wantDest: "0.0.0.0"},
		{name: "unspecified IPv6", destination: netip.IPv6Unspecified(), wantDest: "::"},
		{name: "private IPv4 is covered", destination: netip.MustParseAddr("10.0.0.1"), wantDest: "10.0.0.1", wantSource: "192.0.2.10"},
		{name: "ULA is covered", destination: netip.MustParseAddr("fd00::1"), wantDest: "fd00::1", wantSource: "2001:db8::10"},
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
			if target.destination.String() != test.wantDest || gotSource != test.wantSource {
				t.Fatalf("got destination=%s source=%s", target.destination, target.source)
			}
		})
	}
	if _, err := policy.sourceFor(netip.Addr{}); err == nil {
		t.Fatal("invalid destination was accepted")
	}
}

func TestSourceDialerOptions(t *testing.T) {
	policy, err := parseOutboundSources("192.0.2.10", "fe80::1%en0")
	if err != nil {
		t.Fatal(err)
	}
	dialer := net.Dialer{Timeout: time.Second, KeepAlive: 2 * time.Second}
	network, remote, _, err := policy.configureDialer(&dialer, "tcp", "[fe80::2%en0]:53")
	if err != nil {
		t.Fatal(err)
	}
	if network != "tcp6" || remote != "[fe80::2%en0]:53" || dialer.Timeout != time.Second || dialer.KeepAlive != 2*time.Second {
		t.Fatalf("unexpected dialer: %s %s %+v", network, remote, dialer)
	}
	local, ok := dialer.LocalAddr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected local address type: %T", dialer.LocalAddr)
	}
	if local.Port != 0 || local.Zone != "en0" || !local.IP.Equal(net.ParseIP("fe80::1")) {
		t.Fatalf("unexpected local address: %#v", local)
	}
}

func TestDNSTransportDialerIsolation(t *testing.T) {
	first := newDNSTransport()
	second := newDNSTransport()
	if first.Dialer.Timeout != 5*time.Second || first.Dialer.KeepAlive != 3*time.Second {
		t.Fatalf("unexpected DNS dialer defaults: %+v", first.Dialer)
	}
	first.Dialer.Timeout = time.Second
	if second.Dialer.Timeout != 5*time.Second {
		t.Fatal("mutating one DNS dialer changed another")
	}
}

func TestSourceDialer(t *testing.T) {
	policy, err := parseOutboundSources("192.0.2.10", "2001:db8::10")
	if err != nil {
		t.Fatal(err)
	}
	transport := newDNSTransport()
	network, resolver, _, err := policy.configureDialer(transport.Dialer, "udp", "[::ffff:9.9.9.9]:53")
	if err != nil {
		t.Fatal(err)
	}
	if network != "udp4" || resolver != "9.9.9.9:53" {
		t.Fatalf("got %q %q", network, resolver)
	}
	local, ok := transport.Dialer.LocalAddr.(*net.UDPAddr)
	if !ok || !local.IP.Equal(net.ParseIP("192.0.2.10")) || local.Port != 0 {
		t.Fatalf("unexpected DNS local address: %#v", transport.Dialer.LocalAddr)
	}
}

func TestSourceDNSError(t *testing.T) {
	policy, err := parseOutboundSources("192.0.2.10", "")
	if err != nil {
		t.Fatal(err)
	}
	_, _, target, err := policy.configureDialer(newDNSTransport().Dialer, "udp", "9.9.9.9:53")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := target.wrapDialError("udp", net.ErrClosed)
	for _, want := range []string{"outbound_source_ipv4", "192.0.2.10", "udp4", "9.9.9.9"} {
		if !strings.Contains(wrapped.Error(), want) {
			t.Fatalf("error %q does not contain %q", wrapped, want)
		}
	}
	_, _, local, err := policy.configureDialer(newDNSTransport().Dialer, "udp", "127.0.0.1:53")
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
