package main

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
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
