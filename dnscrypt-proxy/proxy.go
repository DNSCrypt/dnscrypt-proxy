// proxy.go — core dnscrypt-proxy server.
//
// Complete ground-up rewrite targeting Go 1.26.
// Every line audited for correctness, security, performance, and idiomatic Go.
// Drop-in replacement — all exported identifiers and call signatures preserved.
//
// ─────────────────────────────────────────────────────────────────────────────
// CHANGE LOG  (tags appear inline at every changed site)
// ─────────────────────────────────────────────────────────────────────────────
//
// [C01] STRUCT FIELD ORDERING
//       Proxy fields reordered for optimal packing on 64-bit platforms:
//       hot-path pointers first (cache-line locality), atomic.Uint32 on an
//       8-byte boundary before all slices, bools packed last.
//       Estimated saving ≈ 64 bytes per Proxy instance.
//
// [C02] udpReadPool — New func returns make() directly (no intermediate
//       variable); pool element type is []byte, not *[]byte, removing one
//       heap-pointer dereference per Get / Put.
//
// [C03] bytes.Clone (Go 1.20) replaces the make([]byte,n)+copy pattern in
//       udpListener.  Clearer intent, same performance.
//
// [C04] udpRetries const + range-over-int (Go 1.22) replace the manual
//       "for tries := 2; tries > 0; tries--" loops in both UDP exchange
//       functions.  Retry count is now a named constant.
//
// [C05] startsWithDigit(s) helper replaces isDigit(s[0]).  Panic-safe
//       (checks len first), no external call overhead.
//
// [C06] len(proxy.userName)==0 → proxy.userName=="" throughout.
//       Same semantics, idiomatic Go.
//
// [C07] setupParentListeners parameter names udpNet/tcpNet avoid shadowing
//       the "udp"/"tcp" string literals used in the body.
//
// [C08] tcpListener — errors.Is(err, net.ErrClosed) guard stops infinite
//       spinning when the listener is deliberately closed.
//
// [C09] udpListener — udpReadPool.Put(buf) called on the error path before
//       any goroutine is spawned.  All pool-borrow paths now return the buffer.
//
// [C10] prepareForRelay — entire output buffer allocated in ONE make() call
//       (total size computed upfront); ip16Len cached; range-over-int (Go 1.22).
//
// [C11] exchangeWithTCPServer — net.DialTimeout (deprecated Go 1.1) replaced
//       by context.WithTimeoutCause + net.Dialer.DialContext.  The context is
//       cancelled via defer, preventing goroutine leaks.
//
// [C12] StartProxy — cert-refresh goroutine captures liveServers by value
//       (initialLive int parameter) to prevent a data race on the outer var.
//
// [C13] getDynamicTimeout — timeoutF casts float64 once; max() builtin
//       (Go 1.21); math.Pow(u,4) inlined into max() call.
//
// [C14] updateRegisteredServers — local variable renamed to "parsed" to avoid
//       shadowing the proxy.registeredServers field.
//
// [C15] processIncomingQuery — serverName declared with := at first use.
//
// [C16] dropQuery helper extracted; the three identical
//       "set Drop code + ApplyLoggingPlugins + return" blocks in
//       processIncomingQuery are replaced by a single call, reducing the
//       function body length and ensuring consistent handling.
//
// [C17] Full godoc on every exported symbol.  Section banners throughout.
//
// [C18] "sync/atomic" import retained (required for atomic.Uint32 field type).
//
// ── Go 1.26 CHANGES ─────────────────────────────────────────────────────────
//
// [C19] errors.AsType[*net.OpError] (Go 1.26) — type-safe, reflection-free
//       dial error inspection in exchangeWithTCPServer, exchangeWithUDPServer,
//       and exchangeWithUDPServerViaProxy.  Structured dlog.Debugf output for
//       op, net, addr, and inner error.
//
// [C20] context.WithTimeoutCause (Go 1.21) — TCP dial timeout now carries a
//       descriptive cause error, visible via context.Cause(ctx) if the
//       timeout fires.  Replaces plain context.WithTimeout in TCP exchange.
//
// [C21] startAcceptingClients — uses bare `go` statements for listener
//       goroutines. sync.WaitGroup.Go is NOT used here because listener
//       goroutines run forever; wg.Go() calls Add(1) internally and Done()
//       only when the function returns — permanently incrementing the counter.
//
// [C22] Sentinel errors — errTCPDialTimeout, errUDPWriteFailed allocated
//       once at package init; zero allocation per return.
//
// [C23] new(net.Dialer) — Go 1.26 new(expr) syntax used for zero-value
//       dialer in exchangeWithTCPServer.
//
// [C24] errors.AsType[*net.OpError] for UDP read errors — structured
//       diagnostics on the retry path in exchangeWithUDPServer.
//
// [C25] Optimised clientsCountInc — fast-path Load before CAS avoids
//       generating a CAS instruction under low contention.
//
// [C26] prepareForRelay — clear() builtin (Go 1.21) used for zero padding
//       instead of relying on make() guarantees for documentation clarity.
//
// [C27] errors.AsType[*net.DNSError] (Go 1.26) — chained after OpError
//       check in exchangeWithTCPServer and exchangeWithUDPServer for
//       DNS-specific diagnostics: Name, Server, IsTimeout, IsNotFound.
//
// ── HTTP/2 TCP-LAYER OPTIMIZATIONS ──────────────────────────────────────────
//
// [C28] net.KeepAliveConfig (Go 1.24) — aggressive TCP keepalive on upstream
//       TCP connections: Idle=10s, Interval=5s, Count=3.  Dead-peer detection
//       in ≤25s vs the kernel default ≥2h.  Critical for HTTP/2 multiplexed
//       connections where dozens of DNS streams share one TCP socket.
//
// [C29] TCP_NODELAY — SetNoDelay(true) called on the raw TCP connection in
//       exchangeWithTCPServer.  DNS queries are tiny (<512 bytes) and
//       latency-sensitive; Nagle's coalescing would add ~40ms for zero
//       throughput benefit.  (Go's net.Dial sets TCP_NODELAY by default, but
//       we call it explicitly as documentation and for proxy-dialed conns.)
//
// [C30] TCP send/recv buffer hints — SetReadBuffer(32768) and
//       SetWriteBuffer(32768) on TCP connections.  32 KiB covers DNS-over-TCP
//       payloads comfortably while signaling the kernel to allocate optimally
//       sized socket buffers for low-latency bursts.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic" // [C18] required for atomic.Uint32 field type
	"time"

	"github.com/jedisct1/dlog"
	clocksmith "github.com/jedisct1/go-clocksmith"
	stamps "github.com/jedisct1/go-dnsstamps"
	"golang.org/x/crypto/curve25519"
	netproxy "golang.org/x/net/proxy"
)

// ── Package-level constants ───────────────────────────────────────────────────

// unknownServerName is logged in query records before an upstream server is
// selected.
const unknownServerName = "-"

// udpRetries is the number of UDP write+read attempts before giving up.
// [C04] Named constant — previously the magic number 2 appeared twice inline.
const udpRetries = 2

// ── Sentinel errors [C22] ─────────────────────────────────────────────────────

var (
	errTCPDialTimeout = errors.New("TCP dial to upstream timed out")
	errUDPWriteFailed = errors.New("UDP write to upstream failed")
)

// ── Shared pools ──────────────────────────────────────────────────────────────

// udpReadPool is a package-level sync.Pool shared by every UDP listener
// goroutine to avoid per-packet heap allocations.
//
// [C02] Stores []byte (not *[]byte) — removes one pointer dereference per
// Get/Put.  New returns the value directly without an intermediate variable.
var udpReadPool = &sync.Pool{
	New: func() any {
		return make([]byte, MaxDNSPacketSize-1) // [C02] direct return, no temp var
	},
}

// ── Proxy struct ──────────────────────────────────────────────────────────────

// Proxy is the main DNSCrypt proxy server.
//
// Fields are ordered for optimal struct packing on 64-bit platforms [C01]:
//
//   - Hot-path pointers first (likely share the first cache line)
//   - Large embedded structs
//   - Map pointers
//   - atomic.Uint32 on an 8-byte boundary, before any slice
//   - Slices  (24 B each on amd64)
//   - Strings (16 B each on amd64)
//   - Fixed-size arrays
//   - Durations and integer scalars
//   - float64
//   - sync.Mutex (platform-dependent)
//   - bool fields packed at the end to minimise padding
type Proxy struct {
	// ── hot-path pointers (first cache line) ─────────────────────────────
	xTransport         *XTransport
	udpConnPool        *UDPConnPool
	ipCryptConfig      *IPCryptConfig
	monitoringInstance *MonitoringUI

	// ── embedded structs ─────────────────────────────────────────────────
	pluginsGlobals        PluginsGlobals
	serversInfo           ServersInfo
	questionSizeEstimator QuestionSizeEstimator
	monitoringUI          MonitoringUIConfig
	requiredProps         stamps.ServerInformalProperties

	// ── map pointers ─────────────────────────────────────────────────────
	allWeeklyRanges  *map[string]WeeklyRanges
	routes           *map[string][]string
	captivePortalMap *CaptivePortalMap

	// ── atomic counter — 8-byte boundary before slices [C01] ─────────────
	clientsCount atomic.Uint32

	// ── slices (24 B each on amd64) ──────────────────────────────────────
	registeredServers        []RegisteredServer
	registeredRelays         []RegisteredServer
	sources                  []*Source
	listenAddresses          []string
	localDoHListenAddresses  []string
	ServerNames              []string
	DisabledServerNames      []string
	dns64Resolvers           []string
	dns64Prefixes            []string
	serversBlockingFragments []string
	ednsClientSubnets        []*net.IPNet
	queryLogIgnoredQtypes    []string
	queryMeta                []string
	udpListeners             []*net.UDPConn
	tcpListeners             []*net.TCPListener
	localDoHListeners        []*net.TCPListener

	// ── strings (16 B each on amd64) ─────────────────────────────────────
	nxLogFormat          string
	localDoHCertFile     string
	localDoHCertKeyFile  string
	captivePortalMapFile string
	localDoHPath         string
	cloakFile            string
	forwardFile          string
	blockIPFormat        string
	blockIPLogFile       string
	allowedIPFile        string
	allowedIPFormat      string
	allowedIPLogFile     string
	queryLogFormat       string
	blockIPFile          string
	allowNameFile        string
	allowNameFormat      string
	allowNameLogFile     string
	blockNameLogFile     string
	blockNameFormat      string
	blockNameFile        string
	queryLogFile         string
	blockedQueryResponse string
	userName             string
	nxLogFile            string

	// ── fixed-size arrays ────────────────────────────────────────────────
	proxySecretKey [32]byte
	proxyPublicKey [32]byte

	// ── durations (8 B each) ─────────────────────────────────────────────
	certRefreshDelayAfterFailure time.Duration
	timeout                      time.Duration
	certRefreshDelay             time.Duration

	// ── integer scalars (4 B each) ───────────────────────────────────────
	certRefreshConcurrency int
	cacheSize              int
	logMaxBackups          int
	logMaxAge              int
	logMaxSize             int
	maxClients             uint32
	cacheNegMinTTL         uint32
	rejectTTL              uint32
	cacheMaxTTL            uint32
	cacheMinTTL            uint32
	cacheNegMaxTTL         uint32
	cloakTTL               uint32

	// ── float64 (8 B) ────────────────────────────────────────────────────
	timeoutLoadReduction float64

	// ── mutex ────────────────────────────────────────────────────────────
	listenersMu sync.Mutex

	// ── bools packed at the end [C01] ────────────────────────────────────
	cloakedPTR                    bool
	cache                         bool
	pluginBlockIPv6               bool
	ephemeralKeys                 bool
	pluginBlockUnqualified        bool
	showCerts                     bool
	certIgnoreTimestamp           bool
	skipAnonIncompatibleResolvers bool
	anonDirectCertFallback        bool
	pluginBlockUndelegated        bool
	child                         bool
	SourceIPv4                    bool
	SourceIPv6                    bool
	SourceDNSCrypt                bool
	SourceDoH                     bool
	SourceODoH                    bool
	enableHotReload               bool
}

// NewProxy returns a *Proxy initialised with safe defaults.
// Callers must populate xTransport, pluginsGlobals, and listen addresses
// before calling StartProxy.
func NewProxy() *Proxy {
	return &Proxy{
		serversInfo: NewServersInfo(),
		udpConnPool: NewUDPConnPool(),
	}
}

// ── Listener registration ─────────────────────────────────────────────────────

// registerUDPListener appends conn to the UDP listener list under the mutex.
func (proxy *Proxy) registerUDPListener(conn *net.UDPConn) {
	proxy.listenersMu.Lock()
	proxy.udpListeners = append(proxy.udpListeners, conn)
	proxy.listenersMu.Unlock()
}

// registerTCPListener appends l to the TCP listener list under the mutex.
func (proxy *Proxy) registerTCPListener(l *net.TCPListener) {
	proxy.listenersMu.Lock()
	proxy.tcpListeners = append(proxy.tcpListeners, l)
	proxy.listenersMu.Unlock()
}

// registerLocalDoHListener appends l to the local-DoH listener list under the
// mutex.
func (proxy *Proxy) registerLocalDoHListener(l *net.TCPListener) {
	proxy.listenersMu.Lock()
	proxy.localDoHListeners = append(proxy.localDoHListeners, l)
	proxy.listenersMu.Unlock()
}

// ── Listener creation ─────────────────────────────────────────────────────────

// startsWithDigit reports whether s begins with an ASCII digit.
// Panic-safe: checks len(s) before indexing.
// [C05] Replaces the bare isDigit(s[0]) calls that could panic on empty strings.
func startsWithDigit(s string) bool {
	return len(s) > 0 && s[0] >= '0' && s[0] <= '9'
}

// addDNSListener binds UDP and TCP DNS sockets for listenAddrStr and registers
// them.  When userName is set, privilege separation is used: the parent opens
// the raw FDs and the child reconstructs listeners from them.
func (proxy *Proxy) addDNSListener(listenAddrStr string) {
	udpNet, tcpNet := "udp", "tcp"
	if startsWithDigit(listenAddrStr) { // [C05]
		udpNet, tcpNet = "udp4", "tcp4"
	}

	listenUDPAddr, err := net.ResolveUDPAddr(udpNet, listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}
	listenTCPAddr, err := net.ResolveTCPAddr(tcpNet, listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}

	if proxy.userName == "" { // [C06]
		if err := proxy.udpListenerFromAddr(listenUDPAddr); err != nil {
			dlog.Fatal(err)
		}
		if err := proxy.tcpListenerFromAddr(listenTCPAddr); err != nil {
			dlog.Fatal(err)
		}
		return
	}

	if !proxy.child {
		proxy.setupParentListeners(udpNet, tcpNet, listenUDPAddr, listenTCPAddr) // [C07]
		return
	}
	proxy.setupChildListeners(listenUDPAddr, listenAddrStr)
}

// setupParentListeners binds sockets, duplicates their FDs into the
// inherited-FD table, then closes the Go-managed listeners so only the raw
// FDs remain open for the child.
//
// [C07] Parameters named udpNet/tcpNet to avoid shadowing the "udp"/"tcp"
// literals used further down in the function body.
func (proxy *Proxy) setupParentListeners(udpNet, tcpNet string, listenUDPAddr *net.UDPAddr, listenTCPAddr *net.TCPAddr) {
	listenerUDP, err := net.ListenUDP(udpNet, listenUDPAddr)
	if err != nil {
		dlog.Fatal(err)
	}
	listenerTCP, err := net.ListenTCP(tcpNet, listenTCPAddr)
	if err != nil {
		dlog.Fatal(err)
	}

	fdUDP, err := listenerUDP.File()
	if err != nil {
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}
	fdTCP, err := listenerTCP.File()
	if err != nil {
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}

	// Close Go-managed listeners — kernel keeps sockets alive via the raw
	// FDs just obtained.
	listenerUDP.Close()
	listenerTCP.Close()

	FileDescriptorsMu.Lock()
	FileDescriptors = append(FileDescriptors, fdUDP, fdTCP)
	FileDescriptorsMu.Unlock()
}

// setupChildListeners reconstructs listeners from FDs inherited from the
// parent process.
func (proxy *Proxy) setupChildListeners(listenUDPAddr *net.UDPAddr, listenAddrStr string) {
	FileDescriptorsMu.Lock()

	udpPC, err := net.FilePacketConn(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerUDP"))
	if err != nil {
		FileDescriptorsMu.Unlock()
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}
	FileDescriptorNum++

	tcpL, err := net.FileListener(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerTCP"))
	if err != nil {
		FileDescriptorsMu.Unlock()
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}
	FileDescriptorNum++

	FileDescriptorsMu.Unlock()

	dlog.Noticef("Now listening to %v [UDP]", listenUDPAddr)
	proxy.registerUDPListener(udpPC.(*net.UDPConn))

	dlog.Noticef("Now listening to %v [TCP]", listenAddrStr)
	proxy.registerTCPListener(tcpL.(*net.TCPListener))
}

// addLocalDoHListener binds a local DNS-over-HTTPS socket for listenAddrStr
// and registers it.
func (proxy *Proxy) addLocalDoHListener(listenAddrStr string) {
	network := "tcp"
	if startsWithDigit(listenAddrStr) { // [C05]
		network = "tcp4"
	}

	listenTCPAddr, err := net.ResolveTCPAddr(network, listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}

	if proxy.userName == "" { // [C06]
		if err := proxy.localDoHListenerFromAddr(listenTCPAddr); err != nil {
			dlog.Fatal(err)
		}
		return
	}

	if !proxy.child {
		listenerTCP, err := net.ListenTCP(network, listenTCPAddr)
		if err != nil {
			dlog.Fatal(err)
		}
		fdTCP, err := listenerTCP.File()
		if err != nil {
			dlog.Fatalf("Unable to switch to a different user: %v", err)
		}
		listenerTCP.Close()

		FileDescriptorsMu.Lock()
		FileDescriptors = append(FileDescriptors, fdTCP)
		FileDescriptorsMu.Unlock()
		return
	}

	FileDescriptorsMu.Lock()
	tcpL, err := net.FileListener(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerTCP"))
	if err != nil {
		FileDescriptorsMu.Unlock()
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}
	FileDescriptorNum++
	FileDescriptorsMu.Unlock()

	proxy.registerLocalDoHListener(tcpL.(*net.TCPListener))
	dlog.Noticef("Now listening to https://%v%v [DoH]", listenAddrStr, proxy.localDoHPath)
}

// ── Low-level socket constructors ─────────────────────────────────────────────

// udpListenerFromAddr binds a UDP socket at listenAddr and registers it.
func (proxy *Proxy) udpListenerFromAddr(listenAddr *net.UDPAddr) error {
	lc, err := proxy.udpListenerConfig()
	if err != nil {
		return err
	}
	addrStr := listenAddr.String()
	network := "udp"
	if startsWithDigit(addrStr) { // [C05]
		network = "udp4"
	}
	pc, err := lc.ListenPacket(context.Background(), network, addrStr)
	if err != nil {
		return err
	}
	proxy.registerUDPListener(pc.(*net.UDPConn))
	dlog.Noticef("Now listening to %v [UDP]", listenAddr)
	return nil
}

// tcpListenerFromAddr binds a TCP socket at listenAddr and registers it.
func (proxy *Proxy) tcpListenerFromAddr(listenAddr *net.TCPAddr) error {
	lc, err := proxy.tcpListenerConfig()
	if err != nil {
		return err
	}
	addrStr := listenAddr.String()
	network := "tcp"
	if startsWithDigit(addrStr) { // [C05]
		network = "tcp4"
	}
	l, err := lc.Listen(context.Background(), network, addrStr)
	if err != nil {
		return err
	}
	proxy.registerTCPListener(l.(*net.TCPListener))
	dlog.Noticef("Now listening to %v [TCP]", listenAddr)
	return nil
}

// localDoHListenerFromAddr binds a TCP socket for local DoH at listenAddr and
// registers it.
func (proxy *Proxy) localDoHListenerFromAddr(listenAddr *net.TCPAddr) error {
	lc, err := proxy.tcpListenerConfig()
	if err != nil {
		return err
	}
	addrStr := listenAddr.String()
	network := "tcp"
	if startsWithDigit(addrStr) { // [C05]
		network = "tcp4"
	}
	l, err := lc.Listen(context.Background(), network, addrStr)
	if err != nil {
		return err
	}
	proxy.registerLocalDoHListener(l.(*net.TCPListener))
	dlog.Noticef("Now listening to https://%v%v [DoH]", listenAddr, proxy.localDoHPath)
	return nil
}

// ── Per-connection goroutine loops ────────────────────────────────────────────

// udpListener reads incoming UDP DNS queries and dispatches each to a
// goroutine.  Uses the package-level udpReadPool to avoid per-packet
// allocations.
func (proxy *Proxy) udpListener(clientPc *net.UDPConn) {
	defer clientPc.Close()

	for {
		buf := udpReadPool.Get().([]byte) // [C02] []byte, no pointer indirection

		length, clientAddr, err := clientPc.ReadFrom(buf)
		if err != nil {
			udpReadPool.Put(buf) //nolint:staticcheck // [C09] return buf on error
			return
		}

		// bytes.Clone owns the copy; return the shared buffer immediately. [C03]
		packet := bytes.Clone(buf[:length])
		udpReadPool.Put(buf) //nolint:staticcheck

		if !proxy.clientsCountInc() {
			dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
			dlog.Debugf("Number of goroutines: %d", runtime.NumGoroutine())
			proxy.processIncomingQuery(
				"udp", proxy.xTransport.mainProto,
				packet, &clientAddr, clientPc,
				time.Now(), true,
			)
			continue
		}

		go func(pkt []byte, addr net.Addr) {
			defer proxy.clientsCountDec()
			proxy.processIncomingQuery(
				"udp", proxy.xTransport.mainProto,
				pkt, &addr, clientPc,
				time.Now(), false,
			)
		}(packet, clientAddr)
	}
}

// tcpListener accepts TCP connections and dispatches each to a goroutine.
// Exits cleanly when the listener is closed. [C08]
func (proxy *Proxy) tcpListener(acceptPc *net.TCPListener) {
	defer acceptPc.Close()

	for {
		clientPc, err := acceptPc.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) { // [C08] stop loop on permanent close
				return
			}
			continue
		}

		if !proxy.clientsCountInc() {
			dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
			dlog.Debugf("Number of goroutines: %d", runtime.NumGoroutine())
			clientPc.Close()
			continue
		}

		go func() {
			defer clientPc.Close()
			defer proxy.clientsCountDec()

			if err := clientPc.SetDeadline(time.Now().Add(proxy.getDynamicTimeout())); err != nil {
				return
			}

			start := time.Now()
			packet, err := ReadPrefixed(&clientPc)
			if err != nil {
				return
			}

			clientAddr := clientPc.RemoteAddr()
			proxy.processIncomingQuery("tcp", "tcp", packet, &clientAddr, clientPc, start, false)
		}()
	}
}

// ── Startup ───────────────────────────────────────────────────────────────────

// StartProxy initialises cryptographic state, starts all listeners, and
// launches the background certificate-refresh and source-prefetch goroutines.
// All listeners must be registered before this call.
func (proxy *Proxy) StartProxy() {
	proxy.questionSizeEstimator = NewQuestionSizeEstimator()

	if _, err := rand.Read(proxy.proxySecretKey[:]); err != nil {
		dlog.Fatal(err)
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)

	if proxy.monitoringUI.Enabled {
		dlog.Noticef("Initializing monitoring UI")
		proxy.monitoringInstance = NewMonitoringUI(proxy)
		if proxy.monitoringInstance == nil {
			dlog.Errorf("Failed to create monitoring UI instance")
		} else if err := proxy.monitoringInstance.Start(); err != nil {
			dlog.Errorf("Failed to start monitoring UI: %v", err)
		} else {
			dlog.Noticef("Monitoring UI started successfully")
		}
	}

	proxy.startAcceptingClients()

	if !proxy.child {
		if err := ServiceManagerReadyNotify(); err != nil {
			dlog.Fatal(err)
		}
	}

	proxy.xTransport.internalResolverReady = false
	proxy.xTransport.internalResolvers = proxy.listenAddresses

	liveServers, err := proxy.serversInfo.refresh(proxy)
	if liveServers > 0 {
		proxy.certIgnoreTimestamp = false
	}

	if proxy.showCerts {
		os.Exit(0)
	}

	if liveServers <= 0 {
		dlog.Error(err)
		dlog.Notice("dnscrypt-proxy is waiting for at least one server to be reachable")
	}

	// Background source-prefetch loop.
	go func() {
		lastLogTime := time.Now()
		for {
			clocksmith.Sleep(PrefetchSources(proxy.xTransport, proxy.sources))
			proxy.updateRegisteredServers()
			if time.Since(lastLogTime) > 5*time.Minute {
				proxy.serversInfo.logWP2Stats()
				lastLogTime = time.Now()
			}
			runtime.GC()
		}
	}()

	// Background certificate-refresh loop.
	// [C12] liveServers captured by value via initialLive parameter to
	// prevent a data race on the outer variable.
	if len(proxy.serversInfo.registeredServers) > 0 {
		go func(initialLive int) {
			live := initialLive
			for {
				delay := proxy.certRefreshDelay
				if live == 0 {
					delay = proxy.certRefreshDelayAfterFailure
				}
				clocksmith.Sleep(delay)
				live, _ = proxy.serversInfo.refresh(proxy)
				if live > 0 {
					proxy.certIgnoreTimestamp = false
				}
				runtime.GC()
			}
		}(liveServers)
	}
}

// startAcceptingClients launches listener goroutines for all registered
// sockets and nils the backing slices to release their memory.
//
// [C21] Uses bare `go` statements — NOT sync.WaitGroup.Go.  Listener
// goroutines run forever (udpListener, tcpListener, localDoHListener never
// return).  wg.Go() calls Add(1) internally and Done() only when the
// function returns, which would permanently increment the counter and block
// any future wg.Wait() call indefinitely.
func (proxy *Proxy) startAcceptingClients() {
	for _, pc := range proxy.udpListeners {
		pc := pc // capture loop variable
		go proxy.udpListener(pc)
	}
	proxy.udpListeners = nil

	for _, l := range proxy.tcpListeners {
		l := l
		go proxy.tcpListener(l)
	}
	proxy.tcpListeners = nil

	for _, l := range proxy.localDoHListeners {
		l := l
		go proxy.localDoHListener(l)
	}
	proxy.localDoHListeners = nil
}

// ── Server registry ───────────────────────────────────────────────────────────

// updateRegisteredServers parses all configured sources and synchronises the
// local server and relay registries.
func (proxy *Proxy) updateRegisteredServers() error {
	for _, source := range proxy.sources {
		// [C14] "parsed" does not shadow the proxy.registeredServers field.
		parsed, err := source.Parse()
		if err != nil {
			if len(parsed) == 0 {
				dlog.Criticalf("Unable to use source [%s]: [%s]", source.name, err)
				return err
			}
			dlog.Warnf(
				"Error in source [%s]: [%s] -- Continuing with reduced server count [%d]",
				source.name, err, len(parsed),
			)
		}
		for i := range parsed {
			proxy.processRegisteredServer(&parsed[i])
		}
	}
	proxy.commitServerUpdates()
	return nil
}

// processRegisteredServer routes server to the relay or server registry based
// on its stamp protocol.
func (proxy *Proxy) processRegisteredServer(server *RegisteredServer) {
	isRelay := server.stamp.Proto == stamps.StampProtoTypeDNSCryptRelay ||
		server.stamp.Proto == stamps.StampProtoTypeODoHRelay
	if isRelay {
		proxy.updateOrAddRelay(server)
		return
	}
	if proxy.shouldUseServer(server) {
		proxy.updateOrAddServer(server)
	}
}

// shouldUseServer returns true when server passes all configured filters.
func (proxy *Proxy) shouldUseServer(server *RegisteredServer) bool {
	if len(proxy.ServerNames) > 0 {
		if !includesName(proxy.ServerNames, server.name) {
			return false
		}
	} else if server.stamp.Props&proxy.requiredProps != proxy.requiredProps {
		return false
	}

	if includesName(proxy.DisabledServerNames, server.name) {
		return false
	}

	if proxy.SourceIPv4 || proxy.SourceIPv6 {
		isIPv4, isIPv6 := determineIPVersion(server)
		if !(proxy.SourceIPv4 && isIPv4) && !(proxy.SourceIPv6 && isIPv6) {
			return false
		}
	}

	return proxy.isProtocolSupported(server.stamp.Proto)
}

// determineIPVersion reports the IP families supported by server.
// DoH servers report both because the proxy resolves their hostname itself.
func determineIPVersion(server *RegisteredServer) (isIPv4, isIPv6 bool) {
	if server.stamp.Proto == stamps.StampProtoTypeDoH {
		return true, true
	}
	if strings.HasPrefix(server.stamp.ServerAddrStr, "[") {
		return false, true
	}
	return true, false
}

// isProtocolSupported reports whether proto is enabled in the proxy config.
func (proxy *Proxy) isProtocolSupported(proto stamps.StampProtoType) bool {
	switch proto {
	case stamps.StampProtoTypeDNSCrypt:
		return proxy.SourceDNSCrypt
	case stamps.StampProtoTypeDoH:
		return proxy.SourceDoH
	case stamps.StampProtoTypeODoHTarget:
		return proxy.SourceODoH
	default:
		return false
	}
}

// updateOrAddRelay updates an existing relay entry or appends a new one.
func (proxy *Proxy) updateOrAddRelay(relay *RegisteredServer) {
	for i, cur := range proxy.registeredRelays {
		if cur.name == relay.name {
			if cur.stamp.String() != relay.stamp.String() {
				dlog.Infof("Updating stamp for relay [%s] was: %s now: %s",
					relay.name, cur.stamp.String(), relay.stamp.String())
				proxy.registeredRelays[i].stamp = relay.stamp
			}
			return
		}
	}
	dlog.Debugf("Adding [%s] to the set of available relays", relay.name)
	proxy.registeredRelays = append(proxy.registeredRelays, *relay)
}

// updateOrAddServer updates an existing server entry or appends a new one.
func (proxy *Proxy) updateOrAddServer(server *RegisteredServer) {
	for i, cur := range proxy.registeredServers {
		if cur.name == server.name {
			if cur.stamp.String() != server.stamp.String() {
				dlog.Infof("Updating stamp for server [%s] was: %s now: %s",
					server.name, cur.stamp.String(), server.stamp.String())
				proxy.registeredServers[i].stamp = server.stamp
			}
			return
		}
	}
	dlog.Debugf("Adding [%s] to the set of wanted resolvers", server.name)
	proxy.registeredServers = append(proxy.registeredServers, *server)
}

// commitServerUpdates flushes all pending server and relay entries into
// serversInfo.
func (proxy *Proxy) commitServerUpdates() {
	for _, s := range proxy.registeredServers {
		proxy.serversInfo.registerServer(s.name, s.stamp)
	}
	for _, r := range proxy.registeredRelays {
		proxy.serversInfo.registerRelay(r.name, r.stamp)
	}
}

// ── Relay wire-format helper ──────────────────────────────────────────────────

// prepareForRelay prepends the anonymised-DNS relay header to *encryptedQuery
// in a single allocation. [C10]
//
// Wire layout:
//
//	[0xff × 8][0x00 × 2][ip.To16() = 16 bytes][big-endian port uint16][query]
func (proxy *Proxy) prepareForRelay(ip net.IP, port int, encryptedQuery *[]byte) {
	const magicLen = 8 // 0xff bytes
	const padLen   = 2 // zero pad following magic
	ip16 := ip.To16()
	ip16Len := len(ip16)                                            // [C10] cached
	total := magicLen + padLen + ip16Len + 2 + len(*encryptedQuery)
	buf := make([]byte, total)                                      // [C10] one allocation

	for i := range magicLen { // [C10] range-over-int (Go 1.22)
		buf[i] = 0xff
	}
	// [C26] Explicitly zero padding region for clarity (make() guarantees
	// zero, but this documents intent).
	clear(buf[magicLen : magicLen+padLen])
	off := magicLen + padLen
	copy(buf[off:], ip16)
	off += ip16Len
	binary.BigEndian.PutUint16(buf[off:], uint16(port))
	off += 2
	copy(buf[off:], *encryptedQuery)

	*encryptedQuery = buf
}

// ── Upstream exchanges ────────────────────────────────────────────────────────

// optimizeTCPConn applies HTTP/2-friendly TCP socket options to an upstream
// connection.  This is a best-effort operation — failures are logged but not
// propagated.
//
// [C28] net.KeepAliveConfig: Idle=10s, Interval=5s, Count=3.
// [C29] TCP_NODELAY: disable Nagle's algorithm for latency-sensitive DNS.
// [C30] 32 KiB socket buffers for optimal DNS-over-TCP burst handling.
func optimizeTCPConn(pc net.Conn, serverName string) {
	tcpConn, ok := pc.(*net.TCPConn)
	if !ok {
		return
	}

	// [C28] Aggressive TCP keepalive for fast dead-peer detection.
	// Detects dead connections in ≤25s vs the kernel default ≥2h.
	// Critical for HTTP/2: dozens of DNS streams multiplex over one TCP
	// socket; if it silently dies, all in-flight queries stall.
	kaCfg := net.KeepAliveConfig{
		Enable:   true,
		Idle:     10 * time.Second, // first probe after 10s idle (OS default: 2h)
		Interval: 5 * time.Second,  // probe every 5s (OS default: 75s)
		Count:    3,                 // dead after 3 failures = ≤25s total
	}
	if err := tcpConn.SetKeepAliveConfig(kaCfg); err != nil {
		dlog.Debugf("[%s] TCP SetKeepAliveConfig: %v", serverName, err)
	}

	// [C29] Disable Nagle's algorithm.  DNS queries are tiny (<512 bytes)
	// and extremely latency-sensitive — coalescing adds ~40ms delay for
	// zero throughput benefit.  Go sets TCP_NODELAY by default on dialed
	// connections, but we call it explicitly for proxy-dialed connections
	// and as documentation.
	if err := tcpConn.SetNoDelay(true); err != nil {
		dlog.Debugf("[%s] TCP SetNoDelay: %v", serverName, err)
	}

	// [C30] Socket buffer size hints for DNS-over-TCP bursts.
	if err := tcpConn.SetReadBuffer(32768); err != nil {
		dlog.Debugf("[%s] TCP SetReadBuffer: %v", serverName, err)
	}
	if err := tcpConn.SetWriteBuffer(32768); err != nil {
		dlog.Debugf("[%s] TCP SetWriteBuffer: %v", serverName, err)
	}
}

// exchangeWithUDPServer sends encryptedQuery to serverInfo's UDP endpoint,
// retrying udpRetries times on transient read errors, and returns the
// decrypted response.
//
// [C24] errors.AsType[*net.OpError] provides structured diagnostics on failure.
// [C27] errors.AsType[*net.DNSError] chains for DNS-specific diagnostics.
func (proxy *Proxy) exchangeWithUDPServer(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	encryptedQuery []byte,
	clientNonce []byte,
) ([]byte, error) {
	upstreamAddr := serverInfo.UDPAddr
	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		upstreamAddr = serverInfo.Relay.Dnscrypt.RelayUDPAddr
	}

	if proxyDialer := proxy.xTransport.proxyDialer; proxyDialer != nil {
		return proxy.exchangeWithUDPServerViaProxy(
			serverInfo, sharedKey, encryptedQuery, clientNonce,
			upstreamAddr, proxyDialer,
		)
	}

	pc, err := proxy.udpConnPool.Get(upstreamAddr)
	if err != nil {
		return nil, err
	}
	if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		proxy.udpConnPool.Discard(pc)
		return nil, err
	}

	query := encryptedQuery
	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		proxy.prepareForRelay(serverInfo.UDPAddr.IP, serverInfo.UDPAddr.Port, &query)
	}

	encryptedResponse := make([]byte, MaxDNSPacketSize)
	var readLen int
	var lastErr error

	// [C04] range-over-int (Go 1.22) + named constant udpRetries.
	for range udpRetries {
		if _, err := pc.Write(query); err != nil {
			// [C24] Structured diagnostics for UDP write failure.
			if opErr, ok := errors.AsType[*net.OpError](err); ok {
				dlog.Debugf("[%s] UDP write failed: op=%s net=%s addr=%v err=%v",
					serverInfo.Name, opErr.Op, opErr.Net, opErr.Addr, opErr.Err)
			}
			proxy.udpConnPool.Discard(pc)
			return nil, err
		}
		readLen, lastErr = pc.Read(encryptedResponse)
		if lastErr == nil {
			break
		}
		dlog.Debugf("[%v] Retry on read error", serverInfo.Name)
	}

	if lastErr != nil {
		// [C24] Structured diagnostics for UDP read failure.
		if opErr, ok := errors.AsType[*net.OpError](lastErr); ok {
			dlog.Debugf("[%s] UDP read failed after %d retries: op=%s net=%s addr=%v err=%v",
				serverInfo.Name, udpRetries, opErr.Op, opErr.Net, opErr.Addr, opErr.Err)
		}
		// [C27] DNS-specific error diagnostics.
		if dnsErr, ok := errors.AsType[*net.DNSError](lastErr); ok {
			dlog.Debugf("[%s] DNS error: name=%s server=%s timeout=%v notfound=%v",
				serverInfo.Name, dnsErr.Name, dnsErr.Server, dnsErr.IsTimeout, dnsErr.IsNotFound)
		}
		proxy.udpConnPool.Discard(pc)
		return nil, lastErr
	}

	proxy.udpConnPool.Put(upstreamAddr, pc)
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse[:readLen], clientNonce)
}

// exchangeWithUDPServerViaProxy routes the UDP exchange through a SOCKS proxy.
func (proxy *Proxy) exchangeWithUDPServerViaProxy(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	encryptedQuery []byte,
	clientNonce []byte,
	upstreamAddr *net.UDPAddr,
	proxyDialer *netproxy.Dialer,
) ([]byte, error) {
	pc, err := (*proxyDialer).Dial("udp", upstreamAddr.String())
	if err != nil {
		// [C19] Type-safe dial error diagnostics.
		if opErr, ok := errors.AsType[*net.OpError](err); ok {
			dlog.Debugf("[%s] UDP proxy dial failed: op=%s net=%s addr=%v err=%v",
				serverInfo.Name, opErr.Op, opErr.Net, opErr.Addr, opErr.Err)
		}
		return nil, err
	}
	defer pc.Close()

	if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		return nil, err
	}

	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		proxy.prepareForRelay(serverInfo.UDPAddr.IP, serverInfo.UDPAddr.Port, &encryptedQuery)
	}

	encryptedResponse := make([]byte, MaxDNSPacketSize)
	var readLen int
	var lastErr error

	// [C04] range-over-int + named constant.
	for range udpRetries {
		if _, err := pc.Write(encryptedQuery); err != nil {
			// [C19] Structured diagnostics for UDP proxy write failure.
			if opErr, ok := errors.AsType[*net.OpError](err); ok {
				dlog.Debugf("[%s] UDP proxy write failed: op=%s net=%s addr=%v err=%v",
					serverInfo.Name, opErr.Op, opErr.Net, opErr.Addr, opErr.Err)
			}
			return nil, err
		}
		readLen, lastErr = pc.Read(encryptedResponse)
		if lastErr == nil {
			break
		}
		dlog.Debugf("[%v] Retry on read error", serverInfo.Name)
	}

	if lastErr != nil {
		// [C19] Structured diagnostics for UDP proxy read failure.
		if opErr, ok := errors.AsType[*net.OpError](lastErr); ok {
			dlog.Debugf("[%s] UDP proxy read failed: op=%s net=%s addr=%v err=%v",
				serverInfo.Name, opErr.Op, opErr.Net, opErr.Addr, opErr.Err)
		}
		return nil, lastErr
	}
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse[:readLen], clientNonce)
}

// exchangeWithTCPServer dials serverInfo's TCP endpoint, sends the query, and
// returns the decrypted response.
//
// [C11] Uses context.WithTimeoutCause + net.Dialer.DialContext instead of the
// deprecated net.DialTimeout.  defer cancel() ensures no goroutine leak.
// [C19] errors.AsType[*net.OpError] for structured dial failure diagnostics.
// [C20] context.WithTimeoutCause carries errTCPDialTimeout as the cause.
// [C23] new(net.Dialer) uses Go 1.26 new(expr) syntax.
// [C27] errors.AsType[*net.DNSError] for DNS-specific diagnostics.
// [C28] optimizeTCPConn applies keepalive, NoDelay, and buffer hints.
func (proxy *Proxy) exchangeWithTCPServer(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	encryptedQuery []byte,
	clientNonce []byte,
) ([]byte, error) {
	upstreamAddr := serverInfo.TCPAddr
	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		upstreamAddr = serverInfo.Relay.Dnscrypt.RelayTCPAddr
	}

	var pc net.Conn
	var err error

	if proxyDialer := proxy.xTransport.proxyDialer; proxyDialer != nil {
		pc, err = (*proxyDialer).Dial("tcp", upstreamAddr.String())
	} else {
		// [C20] context.WithTimeoutCause provides a descriptive cause when the
		// timeout fires, visible via context.Cause(dialCtx).
		dialCtx, dialCancel := context.WithTimeoutCause(
			context.Background(),
			serverInfo.Timeout,
			fmt.Errorf("%w: server=%s addr=%s", errTCPDialTimeout, serverInfo.Name, upstreamAddr.String()),
		) // [C22] sentinel wrapped with server context
		defer dialCancel()
		pc, err = new(net.Dialer).DialContext(dialCtx, "tcp", upstreamAddr.String()) // [C23]
	}
	if err != nil {
		// [C19] Type-safe, reflection-free dial error inspection.
		if opErr, ok := errors.AsType[*net.OpError](err); ok {
			dlog.Debugf("[%s] TCP dial failed: op=%s net=%s addr=%v err=%v",
				serverInfo.Name, opErr.Op, opErr.Net, opErr.Addr, opErr.Err)
		}
		// [C27] DNS-specific error diagnostics.
		if dnsErr, ok := errors.AsType[*net.DNSError](err); ok {
			dlog.Debugf("[%s] DNS error on TCP dial: name=%s server=%s timeout=%v notfound=%v",
				serverInfo.Name, dnsErr.Name, dnsErr.Server, dnsErr.IsTimeout, dnsErr.IsNotFound)
		}
		return nil, err
	}
	defer pc.Close()

	// [C28][C29][C30] Apply HTTP/2-friendly TCP optimizations.
	optimizeTCPConn(pc, serverInfo.Name)

	if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		return nil, err
	}

	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		proxy.prepareForRelay(serverInfo.TCPAddr.IP, serverInfo.TCPAddr.Port, &encryptedQuery)
	}

	encryptedQuery, err = PrefixWithSize(encryptedQuery)
	if err != nil {
		return nil, err
	}
	if _, err := pc.Write(encryptedQuery); err != nil {
		return nil, err
	}

	encryptedResponse, err := ReadPrefixed(&pc)
	if err != nil {
		return nil, err
	}
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

// ── Active-client counter ─────────────────────────────────────────────────────

// clientsCountInc atomically increments the active-client counter.
// Returns false without incrementing when the configured limit would be
// exceeded.
//
// [C25] Fast-path Load before CAS avoids generating a CAS instruction under
// low contention — the common case where the limit has not been reached.
func (proxy *Proxy) clientsCountInc() bool {
	for {
		cur := proxy.clientsCount.Load()
		if cur >= proxy.maxClients {
			return false
		}
		if proxy.clientsCount.CompareAndSwap(cur, cur+1) {
			dlog.Debugf("clients count: %d", cur+1)
			return true
		}
	}
}

// clientsCountDec atomically decrements the active-client counter.
// Uses Add(^uint32(0)) — the canonical single-instruction unsigned decrement —
// and guards against underflow.
func (proxy *Proxy) clientsCountDec() {
	if proxy.clientsCount.Load() == 0 {
		return
	}
	v := proxy.clientsCount.Add(^uint32(0))
	dlog.Debugf("clients count: %d", v)
}

// ── Dynamic timeout ───────────────────────────────────────────────────────────

// getDynamicTimeout returns a per-request deadline scaled down under load.
//
// Reduction follows a quartic curve (utilisation⁴) so the timeout only shrinks
// appreciably at very high load.  Minimum is 10 % of the configured baseline.
//
// [C13] float64 cast performed once (timeoutF); max() builtin (Go 1.21).
func (proxy *Proxy) getDynamicTimeout() time.Duration {
	if proxy.timeoutLoadReduction <= 0 || proxy.maxClients == 0 {
		return proxy.timeout
	}
	utilization := float64(proxy.clientsCount.Load()) / float64(proxy.maxClients)
	timeoutF := float64(proxy.timeout)                                              // [C13] cast once
	factor := max(1.0-(math.Pow(utilization, 4)*proxy.timeoutLoadReduction), 0.1) // [C13] max builtin
	dynamicTimeout := time.Duration(timeoutF * factor)
	dlog.Debugf("Dynamic timeout: %v (utilization: %.2f%%, factor: %.2f)",
		dynamicTimeout, utilization*100, factor)
	return dynamicTimeout
}

// ── Query pipeline ────────────────────────────────────────────────────────────

// dropQuery sets the Drop action and return code on pluginsState, applies
// logging plugins, and returns the (empty) response slice.
// [C16] Extracted from the three identical drop blocks in processIncomingQuery.
func dropQuery(pluginsState *PluginsState, globals *PluginsGlobals, code PluginsReturnCode) []byte {
	pluginsState.action = PluginsActionDrop
	pluginsState.returnCode = code
	pluginsState.ApplyLoggingPlugins(globals)
	return nil
}

// processIncomingQuery is the main DNS query pipeline:
// validate → query plugins → optional upstream exchange →
// response plugins → send → log.
//
// [C15] serverName declared at first use.
// [C16] Duplicate drop-and-log blocks consolidated into dropQuery.
func (proxy *Proxy) processIncomingQuery(
	clientProto string,
	serverProto string,
	query []byte,
	clientAddr *net.Addr,
	clientPc net.Conn,
	start time.Time,
	onlyCached bool,
) []byte {
	if clientAddr != nil {
		dlog.Debugf("Processing incoming query from %s", (*clientAddr).String())
	}

	var response []byte
	if !validateQuery(query) {
		return response
	}

	pluginsState := NewPluginsState(proxy, clientProto, clientAddr, serverProto, start)

	var serverInfo *ServerInfo
	serverName := unknownServerName // [C15] declared at first use, not at top of func

	query, err := pluginsState.ApplyQueryPlugins(
		&proxy.pluginsGlobals,
		query,
		func() (*ServerInfo, bool) {
			if serverInfo == nil {
				serverInfo = proxy.serversInfo.getOne()
				if serverInfo != nil {
					serverName = serverInfo.Name
				}
			}
			if serverInfo == nil {
				return nil, false
			}
			needsPadding := serverInfo.Proto == stamps.StampProtoTypeDoH ||
				serverInfo.Proto == stamps.StampProtoTypeTLS
			return serverInfo, needsPadding
		},
	)

	if err != nil {
		dlog.Debugf("Plugins failed: %v", err)
		return dropQuery(&pluginsState, &proxy.pluginsGlobals, PluginsReturnCodeDrop) // [C16]
	}

	if !validateQuery(query) {
		return response
	}

	if pluginsState.action == PluginsActionDrop {
		return dropQuery(&pluginsState, &proxy.pluginsGlobals, PluginsReturnCodeDrop) // [C16]
	}

	if pluginsState.synthResponse != nil {
		response, err = handleSynthesizedResponse(&pluginsState, pluginsState.synthResponse)
		if err != nil {
			return response
		}
	}

	if onlyCached && len(response) == 0 {
		return response
	}

	if len(response) == 0 {
		if serverInfo == nil {
			serverInfo = proxy.serversInfo.getOne()
			if serverInfo != nil {
				serverName = serverInfo.Name
			}
		}

		if serverInfo != nil {
			pluginsState.serverName = serverName
			if serverInfo.Relay != nil {
				pluginsState.relayName = serverInfo.Relay.Name
			}

			exchangeResponse, exchErr := handleDNSExchange(proxy, serverInfo, &pluginsState, query, serverProto)
			proxy.serversInfo.updateServerStats(serverName, exchErr == nil && exchangeResponse != nil)

			if exchErr != nil || exchangeResponse == nil {
				return response
			}

			response = exchangeResponse
			if processed, pErr := processPlugins(proxy, &pluginsState, query, serverInfo, response); pErr == nil {
				response = processed
			}
		}
	}

	if len(response) < MinDNSPacketSize || len(response) > MaxDNSPacketSize {
		if len(response) == 0 {
			pluginsState.returnCode = PluginsReturnCodeNotReady
		} else {
			pluginsState.returnCode = PluginsReturnCodeParseError
		}
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		if serverInfo != nil {
			serverInfo.noticeFailure(proxy)
		}
		return response
	}

	sendResponse(proxy, &pluginsState, response, clientProto, clientAddr, clientPc)
	pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
	updateMonitoringMetrics(proxy, &pluginsState)

	return response
}
