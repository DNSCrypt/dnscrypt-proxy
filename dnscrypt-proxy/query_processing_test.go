package main

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// minimalProxy creates a Proxy value whose pluginsGlobals has an empty logging
// plugin list — sufficient for failWith / sendUDPResponse tests that must not
// panic on ApplyLoggingPlugins.
func minimalProxy() *Proxy {
	p := &Proxy{}
	p.pluginsGlobals.loggingPlugins = &[]Plugin{}
	p.questionSizeEstimator = NewQuestionSizeEstimator()
	return p
}

// minimalPluginsState returns a PluginsState suitable for sendUDPResponse tests.
func minimalPluginsState() *PluginsState {
	return &PluginsState{
		maxUnencryptedUDPSafePayloadSize: MaxDNSUDPSafePacketSize,
	}
}

// fakePacketConn is a net.PacketConn that records how many times WriteTo was
// called and always succeeds.
type fakePacketConn struct {
	net.Conn
	mu      sync.Mutex
	written int
}

func (f *fakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	f.written++
	f.mu.Unlock()
	return len(b), nil
}

func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) { return 0, nil, nil }
func (f *fakePacketConn) SetDeadline(t time.Time) error            { return nil }
func (f *fakePacketConn) SetReadDeadline(t time.Time) error        { return nil }
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error       { return nil }
func (f *fakePacketConn) LocalAddr() net.Addr                      { return &net.UDPAddr{} }
func (f *fakePacketConn) Close() error                             { return nil }

// ── sendUDPResponse tests ─────────────────────────────────────────────────────

// TestSendUDPResponse_NilClientAddr verifies that sendUDPResponse returns
// gracefully (no panic, no WriteTo call) when clientAddr is nil.  This covers
// the nil-deref fix applied to the *net.Addr dereference on the write path.
func TestSendUDPResponse_NilClientAddr(t *testing.T) {
	proxy := minimalProxy()
	pluginsState := minimalPluginsState()
	fpc := &fakePacketConn{}

	// Build a minimal valid DNS response (12-byte header, all zeros).
	resp := make([]byte, MinDNSPacketSize)

	// Must not panic.
	sendUDPResponse(proxy, pluginsState, resp, nil, fpc)

	if fpc.written != 0 {
		t.Errorf("WriteTo called %d times with nil clientAddr; want 0", fpc.written)
	}
}

// TestSendUDPResponse_ValidAddr verifies that a well-formed UDP response is
// delivered when clientAddr is non-nil.
func TestSendUDPResponse_ValidAddr(t *testing.T) {
	proxy := minimalProxy()
	pluginsState := minimalPluginsState()
	fpc := &fakePacketConn{}

	addr := net.Addr(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1053})
	resp := make([]byte, MinDNSPacketSize)

	sendUDPResponse(proxy, pluginsState, resp, &addr, fpc)

	if fpc.written != 1 {
		t.Errorf("WriteTo called %d times; want 1", fpc.written)
	}
}

// ── ODoH stampede gate tests ──────────────────────────────────────────────────

// TestODoHKeyUpdateStampedeGate verifies that multiple concurrent calls to the
// stampede gate on ServerInfo.odohKeyUpdateInProgress allow only one goroutine
// to proceed (CompareAndSwap semantics).
func TestODoHKeyUpdateStampedeGate(t *testing.T) {
	si := &ServerInfo{}

	// First CAS should succeed (false → true).
	if !si.odohKeyUpdateInProgress.CompareAndSwap(false, true) {
		t.Fatal("first CAS should succeed but didn't")
	}

	// Subsequent CAS attempts while true should all fail.
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if si.odohKeyUpdateInProgress.CompareAndSwap(false, true) {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()

	if n := allowed.Load(); n != 0 {
		t.Errorf("stampede gate allowed %d extra goroutines; want 0", n)
	}

	// After the refresh completes and resets the flag, a new CAS should work.
	si.odohKeyUpdateInProgress.Store(false)
	if !si.odohKeyUpdateInProgress.CompareAndSwap(false, true) {
		t.Error("CAS after reset should succeed but didn't")
	}
}

// TestTransportProtoTypeSafety is a compile-time check: if transportProto is a
// defined type, the constants protoUDP and protoTCP must compare equal to their
// string counterparts only after explicit conversion.  The test itself just
// ensures the constants have the expected string values.
func TestTransportProtoConstants(t *testing.T) {
	if string(protoUDP) != "udp" {
		t.Errorf("protoUDP = %q; want %q", protoUDP, "udp")
	}
	if string(protoTCP) != "tcp" {
		t.Errorf("protoTCP = %q; want %q", protoTCP, "tcp")
	}
}
