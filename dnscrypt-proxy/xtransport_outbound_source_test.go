package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func TestXTransportOutboundSourceDial(t *testing.T) {
	sourceIP := usableNonLoopbackIPv4(t)
	policy, err := parseOutboundSourcePolicy(sourceIP.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peerCh := make(chan net.IP, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err == nil {
			peerCh <- conn.RemoteAddr().(*net.TCPAddr).IP
			_ = conn.Close()
		}
	}()

	xTransport := NewXTransport(&policy)
	xTransport.timeout = time.Second
	xTransport.saveCachedIPs("ordered.test", []net.IP{
		net.ParseIP("127.0.0.2"),
		net.ParseIP(sourceIP.String()),
	}, time.Hour)
	xTransport.rebuildTransport()
	port := listener.Addr().(*net.TCPAddr).Port
	conn, err := xTransport.transport.DialContext(context.Background(), "tcp", net.JoinHostPort("ordered.test", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if peer := <-peerCh; !peer.Equal(sourceIP) {
		t.Fatalf("peer source = %s, want %s", peer, sourceIP)
	}
}

func TestXTransportOutboundSourceMissingFamily(t *testing.T) {
	policy, err := parseOutboundSourcePolicy("192.0.2.10", "")
	if err != nil {
		t.Fatal(err)
	}
	xTransport := NewXTransport(&policy)
	xTransport.rebuildTransport()
	_, err = xTransport.transport.DialContext(context.Background(), "tcp", "[2001:db8::1]:443")
	if err == nil || !strings.Contains(err.Error(), "outbound_source_ipv6") {
		t.Fatalf("error = %v", err)
	}
}

func TestSourceAwareProxyForwardDialer(t *testing.T) {
	sourceIP := usableNonLoopbackIPv4(t)
	policy, err := parseOutboundSourcePolicy(sourceIP.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	xTransport := NewXTransport(&policy)
	xTransport.timeout = time.Second
	forward := &sourceAwareProxyForwardDialer{xTransport: xTransport}

	t.Run("remote", func(t *testing.T) {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		peerCh := make(chan net.IP, 1)
		go func() {
			conn, err := listener.AcceptTCP()
			if err == nil {
				peerCh <- conn.RemoteAddr().(*net.TCPAddr).IP
				_ = conn.Close()
			}
		}()
		port := listener.Addr().(*net.TCPAddr).Port
		conn, err := forward.DialContext(context.Background(), "tcp", net.JoinHostPort(sourceIP.String(), strconv.Itoa(port)))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if peer := <-peerCh; !peer.Equal(sourceIP) {
			t.Fatalf("peer source = %s, want %s", peer, sourceIP)
		}
	})

	t.Run("local bypass", func(t *testing.T) {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			conn, err := listener.AcceptTCP()
			if err == nil {
				_ = conn.Close()
			}
		}()
		conn, err := forward.DialContext(context.Background(), "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if !conn.LocalAddr().(*net.TCPAddr).IP.IsLoopback() {
			t.Fatalf("local proxy used configured source: %s", conn.LocalAddr())
		}
		_ = conn.Close()
	})

	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := forward.DialContext(ctx, "tcp", net.JoinHostPort(sourceIP.String(), "9"))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context canceled", err)
		}
	})
}

func TestXTransportResolverOutboundSource(t *testing.T) {
	sourceIP := usableNonLoopbackIPv4(t)
	policy, err := parseOutboundSourcePolicy(sourceIP.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	xTransport := NewXTransport(&policy)
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			resolver, peerCh, closeServer := startResolvingDNSServer(t, proto, sourceIP)
			defer closeServer()
			ips, _, err := xTransport.resolveUsingResolver(proto, "example.org", resolver, true, true, false)
			if err != nil {
				t.Fatal(err)
			}
			if len(ips) != 1 || !ips[0].Equal(net.ParseIP("203.0.113.5")) {
				t.Fatalf("resolved IPs = %v", ips)
			}
			if peer := <-peerCh; !peer.Equal(sourceIP) {
				t.Fatalf("resolver peer source = %s, want %s", peer, sourceIP)
			}
		})
	}
}

func startResolvingDNSServer(t *testing.T, proto string, destinationIP net.IP) (string, <-chan net.IP, func()) {
	t.Helper()
	peerCh := make(chan net.IP, 1)
	respond := func(packet []byte) []byte {
		msg := dns.Msg{Data: packet}
		if msg.Unpack() != nil {
			return nil
		}
		msg.Response = true
		msg.Answer = []dns.RR{&dns.A{
			Hdr: dns.Header{Name: "example.org.", Class: dns.ClassINET, TTL: 60},
			A:   rdata.A{Addr: netip.MustParseAddr("203.0.113.5")},
		}}
		if msg.Pack() != nil {
			return nil
		}
		return msg.Data
	}
	if proto == "udp" {
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			packet := make([]byte, MaxDNSPacketSize)
			length, peer, err := listener.ReadFromUDP(packet)
			if err == nil {
				peerCh <- peer.IP
				_, _ = listener.WriteToUDP(respond(packet[:length]), peer)
			}
		}()
		port := listener.LocalAddr().(*net.UDPAddr).Port
		return net.JoinHostPort(destinationIP.String(), strconv.Itoa(port)), peerCh, func() { _ = listener.Close() }
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		defer conn.Close()
		peerCh <- conn.RemoteAddr().(*net.TCPAddr).IP
		packet, err := ReadPrefixed(conn)
		if err != nil {
			return
		}
		packet, err = PrefixWithSize(respond(packet))
		if err == nil {
			_, _ = conn.Write(packet)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	return net.JoinHostPort(destinationIP.String(), strconv.Itoa(port)), peerCh, func() { _ = listener.Close() }
}
