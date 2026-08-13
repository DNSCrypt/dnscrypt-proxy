package main

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestNewOutgoingSourceEmpty(t *testing.T) {
	source, err := newOutgoingSource("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source != nil {
		t.Fatal("expected a nil source when unconfigured")
	}
	if source.localIP(net.ParseIP("192.0.2.1")) != nil {
		t.Fatal("expected a nil local address from a nil source")
	}
}

func TestNewOutgoingSourceLiteralV4(t *testing.T) {
	source, err := newOutgoingSource("192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := source.localIP(net.ParseIP("198.51.100.1")); !got.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("expected 192.0.2.10, got %v", got)
	}
	if got := source.localIP(net.ParseIP("2001:db8::1")); got != nil {
		t.Fatalf("expected no IPv6 source, got %v", got)
	}
}

func TestNewOutgoingSourceLiteralV6(t *testing.T) {
	source, err := newOutgoingSource("2001:db8::10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := source.localIP(net.ParseIP("2001:db8::1")); !got.Equal(net.ParseIP("2001:db8::10")) {
		t.Fatalf("expected 2001:db8::10, got %v", got)
	}
	if got := source.localIP(net.ParseIP("198.51.100.1")); got != nil {
		t.Fatalf("expected no IPv4 source, got %v", got)
	}
}

func TestLocalIPUnknownDestinationFamily(t *testing.T) {
	v4Source, err := newOutgoingSource("192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := v4Source.localIP(nil); !got.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("expected 192.0.2.10, got %v", got)
	}

	v6Source, err := newOutgoingSource("2001:db8::10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := v6Source.localIP(nil); !got.Equal(net.ParseIP("2001:db8::10")) {
		t.Fatalf("expected 2001:db8::10, got %v", got)
	}

	both, err := newOutgoingSource("192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	both.resolved.Store(&outgoingAddrs{v4: net.ParseIP("192.0.2.10").To4(), v6: net.ParseIP("2001:db8::10")})
	if got := both.localIP(nil); !got.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("expected IPv4 to win for an unknown destination family, got %v", got)
	}
}

func TestNewOutgoingSourceUnknownInterface(t *testing.T) {
	if _, err := newOutgoingSource("zzz-no-such-interface"); err == nil {
		t.Fatal("expected an error for an unknown interface")
	}
}

func TestPickOutgoingAddrs(t *testing.T) {
	_, linkLocal, _ := net.ParseCIDR("fe80::1/64")
	linkLocal.IP = net.ParseIP("fe80::1")
	_, loopback, _ := net.ParseCIDR("127.0.0.1/8")
	loopback.IP = net.ParseIP("127.0.0.1")
	_, v4, _ := net.ParseCIDR("192.0.2.10/24")
	v4.IP = net.ParseIP("192.0.2.10")
	_, v4Second, _ := net.ParseCIDR("192.0.2.11/24")
	v4Second.IP = net.ParseIP("192.0.2.11")
	_, v6, _ := net.ParseCIDR("2001:db8::10/64")
	v6.IP = net.ParseIP("2001:db8::10")

	picked := pickOutgoingAddrs([]net.Addr{loopback, linkLocal, v4, v4Second, v6})
	if !picked.v4.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("expected the first global unicast IPv4, got %v", picked.v4)
	}
	if !picked.v6.Equal(net.ParseIP("2001:db8::10")) {
		t.Fatalf("expected the global unicast IPv6, got %v", picked.v6)
	}
}

func TestPickOutgoingAddrsNoUsableAddress(t *testing.T) {
	_, loopback, _ := net.ParseCIDR("127.0.0.1/8")
	loopback.IP = net.ParseIP("127.0.0.1")
	picked := pickOutgoingAddrs([]net.Addr{loopback})
	if picked.v4 != nil || picked.v6 != nil {
		t.Fatal("expected no usable address")
	}
}

func TestIsBindError(t *testing.T) {
	bindErr := &net.OpError{Op: "dial", Err: os.NewSyscallError("bind", errors.New("cannot assign requested address"))}
	if !isBindError(bindErr) {
		t.Fatal("expected a bind error to be recognised")
	}
	connectErr := &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", errors.New("connection refused"))}
	if isBindError(connectErr) {
		t.Fatal("expected a connect error not to be recognised")
	}
	if isBindError(errors.New("unrelated")) {
		t.Fatal("expected an unrelated error not to be recognised")
	}
}

func TestUDPConnPoolFlushClosesConns(t *testing.T) {
	pool := NewUDPConnPool()
	defer pool.Close()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	conn, err := pool.Get(addr, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pool.Put(addr, conn)
	if total, _ := pool.Stats(); total != 1 {
		t.Fatalf("expected 1 pooled connection, got %d", total)
	}
	pool.Flush()
	if total, addrCount := pool.Stats(); total != 0 || addrCount != 0 {
		t.Fatalf("expected an empty pool after Flush, got %d conns across %d addrs", total, addrCount)
	}
	if _, err := conn.Write([]byte{0}); err == nil {
		t.Fatal("expected the pooled connection to be closed by Flush")
	}
}

func TestUdpLocalForUnsetSourceIsNotAnError(t *testing.T) {
	var source *outgoingSource
	laddr, err := source.udpLocalFor(net.ParseIP("2001:db8::1"))
	if err != nil {
		t.Fatalf("an unset source must never fail: %v", err)
	}
	if laddr != nil {
		t.Fatalf("expected no local address, got %v", laddr)
	}
}

func TestUdpLocalForMissingFamilyFails(t *testing.T) {
	source, err := newOutgoingSource("192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := source.udpLocalFor(net.ParseIP("2001:db8::1")); !errors.Is(err, errNoOutgoingAddr) {
		t.Fatalf("expected errNoOutgoingAddr, got %v", err)
	}
	laddr, err := source.udpLocalFor(net.ParseIP("198.51.100.1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !laddr.IP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("expected 192.0.2.10, got %v", laddr)
	}
}

func TestLoopbackDestinationIsNeverBoundV4(t *testing.T) {
	source, err := newOutgoingSource("192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	laddr, err := source.udpLocalFor(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("a loopback destination must never fail: %v", err)
	}
	if laddr != nil {
		t.Fatalf("expected no local address for a loopback destination, got %v", laddr)
	}
}

func TestLoopbackDestinationIsNeverBoundV6(t *testing.T) {
	source, err := newOutgoingSource("2001:db8::10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	laddr, err := source.udpLocalFor(net.ParseIP("::1"))
	if err != nil {
		t.Fatalf("a loopback destination must never fail: %v", err)
	}
	if laddr != nil {
		t.Fatalf("expected no local address for a loopback destination, got %v", laddr)
	}
}

func TestLoopbackDestinationSkipsMissingFamilyError(t *testing.T) {
	// A v4-only source would normally fail closed for an IPv6 destination;
	// loopback destinations must bypass that check entirely.
	source, err := newOutgoingSource("192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := source.udpLocalFor(net.ParseIP("::1")); err != nil {
		t.Fatalf("a loopback destination must never fail: %v", err)
	}

	v6Source, err := newOutgoingSource("2001:db8::10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := v6Source.udpLocalFor(net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("a loopback destination must never fail: %v", err)
	}
}

func TestUnspecifiedDestinationIsNeverBoundV4(t *testing.T) {
	source, err := newOutgoingSource("192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	laddr, err := source.udpLocalFor(net.ParseIP("0.0.0.0"))
	if err != nil {
		t.Fatalf("an unspecified destination must never fail: %v", err)
	}
	if laddr != nil {
		t.Fatalf("expected no local address for an unspecified destination, got %v", laddr)
	}
}

func TestUnspecifiedDestinationIsNeverBoundV6(t *testing.T) {
	source, err := newOutgoingSource("2001:db8::10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	laddr, err := source.udpLocalFor(net.ParseIP("::"))
	if err != nil {
		t.Fatalf("an unspecified destination must never fail: %v", err)
	}
	if laddr != nil {
		t.Fatalf("expected no local address for an unspecified destination, got %v", laddr)
	}
}

func TestUnspecifiedDestinationSkipsMissingFamilyError(t *testing.T) {
	// A v4-only source would normally fail closed for an IPv6 destination;
	// unspecified destinations must bypass that check entirely.
	source, err := newOutgoingSource("192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := source.udpLocalFor(net.ParseIP("::")); err != nil {
		t.Fatalf("an unspecified destination must never fail: %v", err)
	}

	v6Source, err := newOutgoingSource("2001:db8::10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := v6Source.udpLocalFor(net.ParseIP("0.0.0.0")); err != nil {
		t.Fatalf("an unspecified destination must never fail: %v", err)
	}
}

func TestApplyToErrMissingFamilyFails(t *testing.T) {
	source, err := newOutgoingSource("2001:db8::10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dialer := &net.Dialer{}
	if err := source.applyToErr(dialer, "tcp", net.ParseIP("198.51.100.1")); !errors.Is(err, errNoOutgoingAddr) {
		t.Fatalf("expected errNoOutgoingAddr, got %v", err)
	}
	if dialer.LocalAddr != nil {
		t.Fatal("expected LocalAddr to stay unset when the family is missing")
	}
}

func TestApplyToErrUnknownDestinationFamilyIsNotAnError(t *testing.T) {
	source, err := newOutgoingSource("192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dialer := &net.Dialer{}
	if err := source.applyToErr(dialer, "tcp", nil); err != nil {
		t.Fatalf("an unknown destination family must not fail: %v", err)
	}
	if dialer.LocalAddr == nil {
		t.Fatal("expected the v4 source to be applied for an unknown destination family")
	}
}

func TestApplyToErrNilSourceIsNotAnError(t *testing.T) {
	var source *outgoingSource
	dialer := &net.Dialer{}
	if err := source.applyToErr(dialer, "udp", net.ParseIP("198.51.100.1")); err != nil {
		t.Fatalf("a nil source must never fail: %v", err)
	}
	if dialer.LocalAddr != nil {
		t.Fatal("expected LocalAddr to stay nil for a nil source")
	}
}

func TestApplyToErrSetsUDPAddrForUDPNetwork(t *testing.T) {
	source, err := newOutgoingSource("192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dialer := &net.Dialer{}
	if err := source.applyToErr(dialer, "udp", net.ParseIP("198.51.100.1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	udpAddr, ok := dialer.LocalAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected a *net.UDPAddr LocalAddr for a udp network, got %T", dialer.LocalAddr)
	}
	if !udpAddr.IP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("expected 192.0.2.10, got %v", udpAddr.IP)
	}
}

func TestApplyToErrSetsTCPAddrForTCPNetwork(t *testing.T) {
	source, err := newOutgoingSource("192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dialer := &net.Dialer{}
	if err := source.applyToErr(dialer, "tcp", net.ParseIP("198.51.100.1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tcpAddr, ok := dialer.LocalAddr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected a *net.TCPAddr LocalAddr for a tcp network, got %T", dialer.LocalAddr)
	}
	if !tcpAddr.IP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("expected 192.0.2.10, got %v", tcpAddr.IP)
	}
}

func twoDistinctNonLoopbackIPv4s(t *testing.T) (dest, src net.IP) {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("cannot enumerate addresses: %v", err)
	}
	var found []net.IP
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil || !ipNet.IP.IsGlobalUnicast() {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			found = append(found, ip4)
		}
	}
	if len(found) < 2 {
		t.Skip("need two distinct non-loopback IPv4 addresses on the host to exercise a real bind")
	}
	return found[0], found[1]
}

func TestDialTimeoutUDPWithConfiguredSourceSucceeds(t *testing.T) {
	// dest and src must differ: dialing a destination that happens to equal
	// the local address makes the kernel pick that address as the source
	// via the local routing table even without an explicit bind, which
	// would make this test pass whether or not dialTimeout actually binds.
	dest, src := twoDistinctNonLoopbackIPv4s(t)

	source, err := newOutgoingSource(src.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: dest})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer listener.Close()
	conn, err := source.dialTimeout("udp", listener.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatalf("expected a udp dial with a configured source to succeed, got: %v", err)
	}
	defer conn.Close()
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected a *net.UDPAddr local address, got %T", conn.LocalAddr())
	}
	if !udpAddr.IP.Equal(src) {
		t.Fatalf("expected the dial to bind the configured source %v, got %v", src, udpAddr.IP)
	}
}

func TestDialTimeoutNilSourceDialsBothProtocols(t *testing.T) {
	var source *outgoingSource

	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer udpListener.Close()
	udpConn, err := source.dialTimeout("udp", udpListener.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatalf("expected a udp dial with a nil source to succeed, got: %v", err)
	}
	udpConn.Close()

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer tcpListener.Close()
	tcpConn, err := source.dialTimeout("tcp", tcpListener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("expected a tcp dial with a nil source to succeed, got: %v", err)
	}
	tcpConn.Close()
}

func TestHostIP(t *testing.T) {
	cases := []struct {
		name    string
		address string
		want    net.IP
	}{
		{"ipv4 with port", "1.2.3.4:53", net.ParseIP("1.2.3.4")},
		{"ipv6 with port", "[2001:db8::1]:53", net.ParseIP("2001:db8::1")},
		{"hostname with port", "example.com:443", nil},
		{"ipv6 with zone", "[fe80::1%eth0]:53", nil},
		{"no port", "1.2.3.4", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hostIP(c.address)
			if c.want == nil {
				if got != nil {
					t.Fatalf("expected nil, got %v", got)
				}
				return
			}
			if !got.Equal(c.want) {
				t.Fatalf("expected %v, got %v", c.want, got)
			}
		})
	}
}

func TestRefreshLockedWaitsForInProgressRefresh(t *testing.T) {
	source, err := newOutgoingSource("192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	locked := make(chan struct{})
	release := make(chan struct{})
	go func() {
		source.refreshMu.Lock()
		close(locked)
		<-release
		source.refreshMu.Unlock()
	}()
	<-locked

	done := make(chan error, 1)
	go func() { done <- source.refreshLocked() }()

	select {
	case <-done:
		t.Fatal("expected refreshLocked to wait for the in-progress refresh instead of dropping it")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func firstUsableInterfaceName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		if picked := pickOutgoingAddrs(addrs); picked.v4 != nil || picked.v6 != nil {
			return iface.Name
		}
	}
	t.Skip("no interface with a usable address found")
	return ""
}

func TestNoteDialErrorReleasesFlagAfterSuccess(t *testing.T) {
	source, err := newOutgoingSource(firstUsableInterfaceName(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	called := make(chan struct{}, 1)
	source.onRefresh = func() { called <- struct{}{} }
	bindErr := &net.OpError{Op: "dial", Err: os.NewSyscallError("bind", errors.New("cannot assign requested address"))}

	source.noteDialError(bindErr)
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("expected onRefresh to fire after the bind-error refresh")
	}

	deadline := time.Now().Add(time.Second)
	for source.refreshing.Load() {
		if time.Now().After(deadline) {
			t.Fatal("expected the refreshing flag to be released after a successful refresh, future refreshes would be silently disabled otherwise")
		}
		time.Sleep(time.Millisecond)
	}
}
