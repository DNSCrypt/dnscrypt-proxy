package main

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type testConn struct {
	closed atomic.Bool
}

func (c *testConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c *testConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *testConn) Close() error                       { c.closed.Store(true); return nil }
func (c *testConn) LocalAddr() net.Addr                { return &net.IPAddr{} }
func (c *testConn) RemoteAddr() net.Addr               { return &net.IPAddr{} }
func (c *testConn) SetDeadline(_ time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestPrepareForRelayWireFormat(t *testing.T) {
	proxy := &Proxy{}
	ip := net.ParseIP("2001:db8::1")
	query := []byte{1, 2, 3, 4}

	buf, err := proxy.prepareForRelay(ip, 853, query)
	if err != nil {
		t.Fatalf("prepareForRelay failed: %v", err)
	}
	defer putRelayQueryBuffer(buf)

	if len(buf) != relayHeaderLen+len(query) {
		t.Fatalf("unexpected relay packet length: got %d", len(buf))
	}
	for i := range 8 {
		if buf[i] != 0xff {
			t.Fatalf("byte %d must be 0xff", i)
		}
	}
	if buf[8] != 0 || buf[9] != 0 {
		t.Fatalf("relay padding bytes must be zero")
	}
	if !bytes.Equal(buf[10:26], ip.To16()) {
		t.Fatalf("embedded IP mismatch")
	}
	if gotPort := int(buf[26])<<8 | int(buf[27]); gotPort != 853 {
		t.Fatalf("embedded port mismatch: got %d", gotPort)
	}
	if !bytes.Equal(buf[28:], query) {
		t.Fatalf("embedded query mismatch")
	}
}

func TestPrepareForRelayLargePacketBypassesPool(t *testing.T) {
	proxy := &Proxy{}
	ip := net.ParseIP("::1")
	query := make([]byte, MaxDNSPacketSize+1)

	buf, err := proxy.prepareForRelay(ip, 53, query)
	if err != nil {
		t.Fatalf("prepareForRelay failed: %v", err)
	}

	expectedLen := relayHeaderLen + len(query)
	if len(buf) != expectedLen {
		t.Fatalf("unexpected relay packet length: got %d, expected %d", len(buf), expectedLen)
	}
	if cap(buf) != expectedLen {
		t.Fatalf("expected non-pooled exact-size buffer, got cap=%d expected=%d", cap(buf), expectedLen)
	}
}

func TestTCPConnPoolPutOverflowClosesConn(t *testing.T) {
	pool := NewTCPConnPool()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatalf("failed to resolve address: %v", err)
	}

	for range tcpMaxIdlePerAddr {
		pool.Put(addr, &testConn{})
	}
	overflow := &testConn{}
	pool.Put(addr, overflow)

	if !overflow.closed.Load() {
		t.Fatalf("overflow connection must be closed")
	}
	if got := len(pool.idle[addr.String()]); got != tcpMaxIdlePerAddr {
		t.Fatalf("idle pool size mismatch: got %d expected %d", got, tcpMaxIdlePerAddr)
	}
}
