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

	stats := pool.Stats()
	if stats.TotalConnections != 1 {
		t.Errorf("Expected 1 connection in pool, got %d", stats.TotalConnections)
	}
	if stats.UniqueAddresses != 1 {
		t.Errorf("Expected 1 address in pool, got %d", stats.UniqueAddresses)
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

	if pool.Stats().TotalConnections != UDPPoolMaxConnsPerAddr {
		t.Errorf("Expected %d connections in pool, got %d", UDPPoolMaxConnsPerAddr, pool.Stats().TotalConnections)
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

	if pool.Stats().TotalConnections != 0 {
		t.Errorf("Expected 0 connections after discard, got %d", pool.Stats().TotalConnections)
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

	if pool.Stats().TotalConnections > UDPPoolMaxConnsPerAddr {
		t.Errorf("Pool exceeded max connections: %d > %d", pool.Stats().TotalConnections, UDPPoolMaxConnsPerAddr)
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

	stats2 := pool.Stats()
	if stats2.TotalConnections != 2 {
		t.Errorf("Expected 2 connections, got %d", stats2.TotalConnections)
	}
	if stats2.UniqueAddresses != 2 {
		t.Errorf("Expected 2 addresses, got %d", stats2.UniqueAddresses)
	}
}

func TestUDPConnPool_Close(t *testing.T) {
	pool := NewUDPConnPool()

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:53")

	conn, _ := pool.Get(addr)
	pool.Put(addr, conn)

	pool.Close()

	// After Close, Get must return ErrPoolClosed — the pool is shut down.
	_, err := pool.Get(addr)
	if err == nil {
		t.Fatal("Get after close should return an error, got nil")
	}

	if pool.Stats().TotalConnections != 0 {
		t.Errorf("Expected 0 connections after close, got %d", pool.Stats().TotalConnections)
	}
}

func TestUDPConnPool_Drain(t *testing.T) {
	pool := NewUDPConnPool()
	defer pool.Close()

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:53")

	// Put a connection in the pool.
	conn, err := pool.Get(addr)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	pool.Put(addr, conn)

	if pool.Stats().TotalConnections != 1 {
		t.Fatalf("Expected 1 connection before Drain, got %d", pool.Stats().TotalConnections)
	}

	// Drain must empty the pool without closing it.
	if err := pool.Drain(); err != nil {
		t.Fatalf("Drain returned error: %v", err)
	}

	s := pool.Stats()
	if s.TotalConnections != 0 {
		t.Errorf("Expected 0 connections after Drain, got %d", s.TotalConnections)
	}
	if s.IsClosed {
		t.Error("Pool should not be closed after Drain")
	}

	// Get must still work after Drain.
	conn2, err := pool.Get(addr)
	if err != nil {
		t.Fatalf("Get after Drain failed: %v", err)
	}
	pool.Put(addr, conn2)
}

// TestUDPConnPool_RaceDrainClose is a concurrency stress test designed to be
// run with -race.  Many goroutines issue Get/Put concurrently while Drain and
// Close are called, exercising all shutdown edge-cases.
func TestUDPConnPool_RaceDrainClose(t *testing.T) {
	pool := NewUDPConnPool()

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:53")

	const workers = 8
	const iterations = 200

	var wg sync.WaitGroup

	// Start workers that Get/Put in a tight loop.
	for range workers {
		wg.Go(func() {
			for range iterations {
				conn, err := pool.Get(addr)
				if err != nil {
					// ErrPoolClosed is expected once Close is called.
					return
				}
				pool.Put(addr, conn)
			}
		})
	}

	// Drain once in the middle.
	wg.Go(func() {
		time.Sleep(time.Millisecond)
		_ = pool.Drain()
	})

	// Close after a short pause; workers should see ErrPoolClosed.
	wg.Go(func() {
		time.Sleep(5 * time.Millisecond)
		_ = pool.Close()
	})

	wg.Wait()
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
