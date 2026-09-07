package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUDPConnPool_SourceBinding(t *testing.T) {
	sourceIP := nonLoopbackIPv4(t)
	policy, err := parseOutboundSources(sourceIP.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	destination := listener.LocalAddr().(*net.UDPAddr)
	// net.ParseIP intentionally supplies the 16-byte mapped representation.
	destination = &net.UDPAddr{IP: net.ParseIP(sourceIP.String()), Port: destination.Port}

	pool := NewUDPConnPool(&policy)
	defer pool.Close()
	conn, err := pool.Get(destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 1)
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, peer, err := listener.ReadFromUDP(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !peer.IP.Equal(sourceIP) {
		t.Fatalf("peer source = %s, want %s", peer.IP, sourceIP)
	}

	pool.Put(destination, conn)
	reused, err := pool.Get(destination)
	if err != nil {
		t.Fatal(err)
	}
	if reused != conn {
		t.Fatal("pooled connection was not reused")
	}
	pool.Discard(reused)
	replacement, err := pool.Get(destination)
	if err != nil {
		t.Fatal(err)
	}
	if replacement == reused {
		t.Fatal("discarded connection was reused")
	}
	pool.Discard(replacement)
}

func TestUDPConnPool_Loopback(t *testing.T) {
	policy, err := parseOutboundSources("192.0.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	pool := NewUDPConnPool(&policy)
	defer pool.Close()
	conn, err := pool.Get(listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Discard(conn)
	if !conn.LocalAddr().(*net.UDPAddr).IP.IsLoopback() {
		t.Fatalf("loopback destination used configured source: %s", conn.LocalAddr())
	}
}

func TestUDPConnPool_BindFailure(t *testing.T) {
	destinationIP := nonLoopbackIPv4(t)
	configured := "192.0.2.1"
	if destinationIP.Equal(net.ParseIP(configured)) {
		configured = "198.51.100.1"
	}
	policy, err := parseOutboundSources(configured, "")
	if err != nil {
		t.Fatal(err)
	}
	pool := NewUDPConnPool(&policy)
	defer pool.Close()
	_, err = pool.Get(&net.UDPAddr{IP: destinationIP, Port: 53})
	if err == nil {
		t.Skipf("host permits binding non-local test address %s", configured)
	}
	for _, want := range []string{"outbound_source_ipv4", configured, "udp4", destinationIP.String()} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}

func TestUDPConnPool_Basic(t *testing.T) {
	pool := NewUDPConnPool(nil)
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
	pool := NewUDPConnPool(nil)
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
	pool := NewUDPConnPool(nil)
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
	pool := NewUDPConnPool(nil)
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
	pool := NewUDPConnPool(nil)
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
	pool := NewUDPConnPool(nil)

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
	pool := NewUDPConnPool(nil)
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
	pool := NewUDPConnPool(nil)
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
	pool := NewUDPConnPool(nil)
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
