package main

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func TestUDPConnPool_Basic(t *testing.T) {
	pool := NewUDPConnPool()
	defer pool.Close()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	conn, err := pool.Get(addr)
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}
	if conn == nil {
		t.Fatal("Expected non-nil connection")
	}

	pool.Put(addr, conn)

	conn2, err := pool.Get(addr)
	if err != nil {
		t.Fatalf("Failed to get connection second time: %v", err)
	}
	if conn2 == nil {
		t.Fatal("Expected non-nil connection")
	}

	pool.Put(addr, conn2)

	totalConns, addrCount := pool.Stats()
	if totalConns != 1 {
		t.Errorf("Expected 1 connection in pool, got %d", totalConns)
	}
	if addrCount != 1 {
		t.Errorf("Expected 1 address in pool, got %d", addrCount)
	}
}

func TestUDPConnPool_MaxConns(t *testing.T) {
	pool := NewUDPConnPool()
	defer pool.Close()

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:53")

	var conns []*net.UDPConn
	for i := range UDPPoolMaxConnsPerAddr + 2 {
		conn, err := pool.Get(addr)
		if err != nil {
			t.Fatalf("Failed to get connection %d: %v", i, err)
		}
		conns = append(conns, conn)
	}

	for _, conn := range conns {
		pool.Put(addr, conn)
	}

	totalConns, _ := pool.Stats()
	if totalConns != UDPPoolMaxConnsPerAddr {
		t.Errorf("Expected %d connections in pool, got %d", UDPPoolMaxConnsPerAddr, totalConns)
	}
}

func TestUDPConnPool_Discard(t *testing.T) {
	pool := NewUDPConnPool()
	defer pool.Close()

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:53")

	conn, err := pool.Get(addr)
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}

	pool.Discard(conn)

	totalConns, _ := pool.Stats()
	if totalConns != 0 {
		t.Errorf("Expected 0 connections after discard, got %d", totalConns)
	}
}

func TestUDPConnPool_Concurrent(t *testing.T) {
	pool := NewUDPConnPool()
	defer pool.Close()

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:53")

	var wg sync.WaitGroup
	iterations := 100

	for range 10 {
		wg.Go(func() {
			for range iterations {
				conn, err := pool.Get(addr)
				if err != nil {
					t.Errorf("Failed to get connection: %v", err)
					return
				}
				time.Sleep(time.Microsecond)
				pool.Put(addr, conn)
			}
		})
	}

	wg.Wait()

	totalConns, _ := pool.Stats()
	if totalConns > UDPPoolMaxConnsPerAddr {
		t.Errorf("Pool exceeded max connections: %d > %d", totalConns, UDPPoolMaxConnsPerAddr)
	}
}

func TestUDPConnPool_MultipleAddresses(t *testing.T) {
	pool := NewUDPConnPool()
	defer pool.Close()

	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:53")
	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:5353")

	conn1, _ := pool.Get(addr1)
	conn2, _ := pool.Get(addr2)

	pool.Put(addr1, conn1)
	pool.Put(addr2, conn2)

	totalConns, addrCount := pool.Stats()
	if totalConns != 2 {
		t.Errorf("Expected 2 connections, got %d", totalConns)
	}
	if addrCount != 2 {
		t.Errorf("Expected 2 addresses, got %d", addrCount)
	}
}

func TestUDPConnPool_Close(t *testing.T) {
	pool := NewUDPConnPool()

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:53")

	conn, _ := pool.Get(addr)
	pool.Put(addr, conn)

	pool.Close()

	conn2, err := pool.Get(addr)
	if err != nil {
		t.Fatalf("Get after close should still work: %v", err)
	}

	pool.Put(addr, conn2)

	totalConns, _ := pool.Stats()
	if totalConns != 0 {
		t.Errorf("Expected 0 connections after close, got %d", totalConns)
	}
}

func BenchmarkUDPConnPool_GetPut(b *testing.B) {
	pool := NewUDPConnPool()
	defer pool.Close()

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:53")

	conn, _ := pool.Get(addr)
	pool.Put(addr, conn)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, _ := pool.Get(addr)
		pool.Put(addr, conn)
	}
}

func BenchmarkUDPDial_NoPool(b *testing.B) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:53")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, _ := net.DialUDP("udp", nil, addr)
		conn.Close()
	}
}

func BenchmarkUDPConnPool_Contention(b *testing.B) {
	pool := NewUDPConnPool()
	defer pool.Close()

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:53")

	conn, _ := pool.Get(addr)
	pool.Put(addr, conn)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, _ := pool.Get(addr)
			pool.Put(addr, conn)
		}
	})
}

func BenchmarkUDPConnPool_MultiAddrContention(b *testing.B) {
	pool := NewUDPConnPool()
	defer pool.Close()

	addrs := make([]*net.UDPAddr, 16)
	for i := range addrs {
		addrs[i], _ = net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", 5300+i))
		conn, _ := pool.Get(addrs[i])
		pool.Put(addrs[i], conn)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			addr := addrs[i%len(addrs)]
			conn, _ := pool.Get(addr)
			pool.Put(addr, conn)
			i++
		}
	})
}

func TestUDPListenerReplySource(t *testing.T) {
	// Queries sent to a second local address catch replies coming from the wrong one
	ipv4Targets := []string{"127.0.0.1"}
	switch runtime.GOOS {
	case "linux":
		ipv4Targets = append(ipv4Targets, "127.0.0.2")
	case "darwin":
		addrs, _ := net.InterfaceAddrs()
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil && ipNet.IP.IsGlobalUnicast() {
				ipv4Targets = append(ipv4Targets, ipNet.IP.String())
				break
			}
		}
	default:
		t.Skip("only Linux and macOS reply from the queried address for both IPv4 and IPv6")
	}
	for _, tt := range []struct {
		network, listen string
		targets         []string
	}{
		{"udp4", "0.0.0.0", ipv4Targets},
		{"udp", "::", append([]string{"::1"}, ipv4Targets...)},
		{"udp4", "127.0.0.1", []string{"127.0.0.1"}},
	} {
		for _, maxClients := range []uint32{0, 16} {
			t.Run(fmt.Sprintf("%s %s maxClients=%d", tt.network, tt.listen, maxClients), func(t *testing.T) {
				proxy := NewProxy()
				proxy.maxClients = maxClients
				proxy.questionSizeEstimator = NewQuestionSizeEstimator()
				proxy.xTransport = &XTransport{mainProto: "udp"}
				proxy.pluginBlockIPv6 = true
				if err := proxy.InitPluginsGlobals(); err != nil {
					t.Fatal(err)
				}
				listener, err := net.ListenUDP(tt.network, &net.UDPAddr{IP: net.ParseIP(tt.listen)})
				if err != nil {
					if tt.network == "udp" {
						t.Skipf("IPv6 unavailable: %v", err)
					}
					t.Fatal(err)
				}
				proxy.registerUDPListener(listener)
				done := make(chan struct{})
				go func() {
					proxy.udpListener(listener)
					close(done)
				}()
				t.Cleanup(func() {
					listener.Close()
					<-done
				})
				port := listener.LocalAddr().(*net.UDPAddr).Port

				type query struct {
					client *net.UDPConn
					server *net.UDPAddr
				}
				var queries []query
				for range 4 {
					for _, target := range tt.targets {
						server := &net.UDPAddr{IP: net.ParseIP(target), Port: port}
						clientIP := net.IPv6loopback
						if server.IP.To4() != nil {
							clientIP = net.IPv4(127, 0, 0, 1)
						}
						client, err := net.ListenUDP("udp", &net.UDPAddr{IP: clientIP})
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { client.Close() })
						client.SetDeadline(time.Now().Add(3 * time.Second))
						msg := dns.NewMsg("example.com.", dns.TypeAAAA)
						msg.ID = uint16(len(queries))
						if err := msg.Pack(); err != nil {
							t.Fatal(err)
						}
						if _, err := client.WriteToUDP(msg.Data, server); err != nil {
							t.Fatal(err)
						}
						queries = append(queries, query{client, server})
					}
				}
				for i, q := range queries {
					buffer := make([]byte, MaxDNSPacketSize)
					n, source, err := q.client.ReadFromUDP(buffer)
					if err != nil {
						t.Fatal(err)
					}
					if !source.IP.Equal(q.server.IP) || source.Port != q.server.Port {
						t.Errorf("reply from %s, want %s", source, q.server)
					}
					msg := &dns.Msg{Data: buffer[:n]}
					if err := msg.Unpack(); err != nil {
						t.Fatal(err)
					}
					if !msg.Response || msg.ID != uint16(i) || len(msg.Answer) == 0 {
						t.Errorf("unexpected response: %v", msg)
					}
				}
			})
		}
	}
}
