package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func TestXTransportSourceBinding(t *testing.T) {
	sourceIP := nonLoopbackIPv4(t)
	policy, err := parseOutboundSources(sourceIP.String(), "")
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

func TestXTransportMissingSource(t *testing.T) {
	policy, err := parseOutboundSources("192.0.2.10", "")
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

func TestProxyDialer(t *testing.T) {
	sourceIP := nonLoopbackIPv4(t)
	policy, err := parseOutboundSources(sourceIP.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	xTransport := NewXTransport(&policy)
	xTransport.timeout = time.Second
	forward := &proxyDialer{xTransport: xTransport}

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

func TestResolverSourceBinding(t *testing.T) {
	sourceIP := nonLoopbackIPv4(t)
	policy, err := parseOutboundSources(sourceIP.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	xTransport := NewXTransport(&policy)
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			resolver, peerCh, closeServer := startTestResolver(t, proto, sourceIP)
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

func startTestResolver(t *testing.T, proto string, destinationIP net.IP) (string, <-chan net.IP, func()) {
	t.Helper()
	return startTestResolverWithIP(t, proto, destinationIP, netip.MustParseAddr("203.0.113.5"))
}

func startTestResolverWithIP(t *testing.T, proto string, destinationIP net.IP, answer netip.Addr) (string, <-chan net.IP, func()) {
	t.Helper()
	addr, peers, closeServer := startTestDNS(t, proto, destinationIP, false, func(msg *dns.Msg) {
		msg.Answer = []dns.RR{&dns.A{
			Hdr: dns.Header{Name: msg.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
			A:   rdata.A{Addr: answer},
		}}
	})
	return addr.String(), peers, closeServer
}

func TestProxyResolveNoRecursion(t *testing.T) {
	for _, kind := range []string{"SOCKS", "HTTP"} {
		t.Run(kind, func(t *testing.T) {
			loopback := net.IPv4(127, 0, 0, 1)
			answer := netip.MustParseAddr("127.0.0.1")
			internal, internalQueries, closeInternal := startTestResolverWithIP(t, "udp", loopback, answer)
			defer closeInternal()
			bootstrap, bootstrapQueries, closeBootstrap := startTestResolverWithIP(t, "udp", loopback, answer)
			defer closeBootstrap()
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: loopback})
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
			policy, err := parseOutboundSources("192.0.2.10", "")
			if err != nil {
				t.Fatal(err)
			}
			xTransport := NewXTransport(&policy)
			xTransport.ignoreSystemDNS = true
			xTransport.useIPv6 = false
			xTransport.internalResolverReady.Store(true)
			xTransport.internalResolvers = []string{internal}
			xTransport.bootstrapResolvers = []string{bootstrap}
			endpoint := net.JoinHostPort("proxy.test", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var conn net.Conn
			if kind == "SOCKS" {
				forward := &proxyDialer{xTransport: xTransport}
				conn, err = forward.DialContext(ctx, "tcp", endpoint)
			} else {
				proxyURL, parseErr := url.Parse("http://" + endpoint)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				xTransport.httpProxyFunction = http.ProxyURL(proxyURL)
				xTransport.rebuildTransport()
				conn, err = xTransport.transport.DialContext(ctx, "tcp", endpoint)
			}
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			select {
			case <-internalQueries:
				t.Fatal("proxy endpoint lookup used the proxy itself, creating a circular dependency")
			default:
			}
			select {
			case <-bootstrapQueries:
			default:
				t.Fatal("proxy endpoint lookup did not use the bootstrap resolver")
			}
		})
	}
}

func TestProxyDialerIPv6Zone(t *testing.T) {
	listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.AcceptTCP()
		if err == nil {
			_ = conn.Close()
		}
	}()
	policy, err := parseOutboundSources("192.0.2.10", "")
	if err != nil {
		t.Fatal(err)
	}
	xTransport := NewXTransport(&policy)
	xTransport.ignoreSystemDNS = true
	xTransport.bootstrapResolvers = nil
	forward := &proxyDialer{xTransport: xTransport}
	endpoint := net.JoinHostPort("::1%1", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	conn, err := forward.DialContext(context.Background(), "tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}
