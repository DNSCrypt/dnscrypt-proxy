package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	"golang.org/x/crypto/curve25519"
	netproxy "golang.org/x/net/proxy"
)

// unknownServerName is logged in query records before an upstream server is
// selected.
const unknownServerName = "-"

// udpRetries is the number of UDP write+read attempts before giving up.
const udpRetries = 2

const parkedTimerDuration = time.Duration(1<<63 - 1)

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

// encryptedResponsePool is a package-level sync.Pool for upstream response
// read buffers, shared by exchangeWithUDPServer and exchangeWithUDPServerViaProxy.
//
// [P01] Eliminates one make([]byte, MaxDNSPacketSize) heap allocation per
// upstream UDP exchange.  The caller must bytes.Clone the relevant prefix and
// return the full-capacity buffer to the pool immediately after.
var encryptedResponsePool = &sync.Pool{
	New: func() any {
		return make([]byte, MaxDNSPacketSize) // [P01]
	},
}

// ── TCPConnPool ───────────────────────────────────────────────────────────────

// tcpMaxIdlePerAddr is the maximum number of idle connections held per unique
// upstream address.  Connections returned via Put beyond this cap are closed
// immediately rather than pooled.
//
// [P07] Bounding the pool prevents unbounded file-descriptor and memory growth
// when an upstream is slow or unreachable and many requests pile up.
const tcpMaxIdlePerAddr = 4

// tcpIdleTimeout is the maximum duration a connection may sit idle in the pool.
// Connections older than this are closed and discarded on the next Get so that
// NAT-timed-out or half-open sockets are not handed to a caller.
//
// [P07] Explicit idle expiry is healthier than relying solely on TCP keepalive,
// because NAT entries can disappear without triggering a keepalive reset.
const tcpIdleTimeout = 60 * time.Second

// tcpIdleEntry holds an idle upstream TCP connection with the wall-clock time
// at which it was last returned to the pool.
//
// [P07] lastUsed is compared against tcpIdleTimeout in Get to discard stale
// entries before handing them to a caller.
type tcpIdleEntry struct {
	conn     net.Conn
	lastUsed time.Time
}

// TCPConnPool is a bounded pool of idle upstream TCP connections keyed by
// address string.  It mirrors the UDPConnPool pattern already used for UDP.
//
// [P02] Reusing persistent connections avoids a full TCP (+TLS/DNSCrypt)
// handshake for every query, which is the dominant latency contributor on the
// TCP path.
//
// [P07] Pool is now bounded (tcpMaxIdlePerAddr per address) and applies idle
// expiry (tcpIdleTimeout) on every Get.
type TCPConnPool struct {
	mu   sync.Mutex
	idle map[string][]tcpIdleEntry
}

// NewTCPConnPool allocates an empty TCPConnPool.
func NewTCPConnPool() *TCPConnPool {
	return &TCPConnPool{idle: make(map[string][]tcpIdleEntry)}
}

// Get returns a non-expired idle connection for addr if one exists; stale
// entries (older than tcpIdleTimeout) are closed and skipped.  Falls back to
// dialling a fresh TCP connection with TCP_NODELAY and KeepAlive applied.
//
// [P07] Idle expiry prevents handing the caller a half-open or NAT-expired
// socket.
func (p *TCPConnPool) Get(addr *net.TCPAddr, timeout time.Duration) (net.Conn, error) {
	key := addr.String()
	now := time.Now()
	p.mu.Lock()
	entries := p.idle[key]
	for len(entries) > 0 {
		e := entries[len(entries)-1]
		entries = entries[:len(entries)-1]
		if now.Sub(e.lastUsed) <= tcpIdleTimeout {
			p.idle[key] = entries
			p.mu.Unlock()
			return e.conn, nil
		}
		// Entry is stale; close it and try the next candidate.
		e.conn.Close()
	}
	p.idle[key] = entries
	p.mu.Unlock()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), timeout)
	defer dialCancel()
	conn, err := new(net.Dialer).DialContext(dialCtx, "tcp", key)
	if err != nil {
		return nil, err
	}
	applyTCPOpts(conn)
	return conn, nil
}

// Put returns a healthy connection to the pool for future reuse.
// Connections beyond tcpMaxIdlePerAddr for the same address are closed
// immediately to prevent unbounded growth.
//
// [P07] The caller must clear any deadlines on conn before calling Put so that
// the next borrower starts with a clean state (done in exchangeWithTCPServer).
func (p *TCPConnPool) Put(addr *net.TCPAddr, conn net.Conn) {
	key := addr.String()
	p.mu.Lock()
	entries := p.idle[key]
	if len(entries) >= tcpMaxIdlePerAddr {
		p.mu.Unlock()
		conn.Close() // [P07] cap enforced — discard rather than pool
		return
	}
	p.idle[key] = append(entries, tcpIdleEntry{conn: conn, lastUsed: time.Now()})
	p.mu.Unlock()
}

// Discard closes and discards a connection that experienced an error.
func (p *TCPConnPool) Discard(conn net.Conn) {
	conn.Close()
}

// applyTCPOpts sets TCP_NODELAY and an aggressive KeepAlive on conn when it
// is a *net.TCPConn.  Called on every new connection from the TCP pool.
//
// [P02] TCP_NODELAY eliminates Nagle buffering for latency-sensitive DNS.
// KeepAlive detects dead peers before a query is sent to them.
//
// [P06] For devices without hardware AES (OpenWrt/ARM/MIPS), also configure
// the TLS layer to prefer TLS_CHACHA20_POLY1305_SHA256 via XTransport's
// TLS config — see note in exchangeWithTCPServer.
func applyTCPOpts(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcpConn.SetNoDelay(true)
	_ = tcpConn.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     10 * time.Second,
		Interval: 5 * time.Second,
		Count:    3,
	})
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
	tcpConnPool        *TCPConnPool // [P02] upstream TCP connection pool
	ipCryptConfig      *IPCryptConfig
	monitoringInstance *MonitoringUI

	// ── graceful-shutdown context ─────────────────────────────────────────
	// shutdownCtx is cancelled by StopProxy to signal background goroutines
	// (source prefetch and cert refresh loops) to exit cleanly.
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

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

	// ── sharded listener mutexes [P03] ───────────────────────────────────
	// Three independent mutexes replace the original single listenersMu.
	// This eliminates false sharing between the three listener slices on
	// multi-core platforms where registration goroutines may run concurrently.
	udpListenersMu sync.Mutex
	tcpListenersMu sync.Mutex
	doHListenersMu sync.Mutex

	// ── bools packed at the end [C01] ────────────────────────────────────
	cloakedPTR             bool
	cache                  bool
	pluginBlockIPv6        bool
	ephemeralKeys          bool
	pluginBlockUnqualified bool
	showCerts              bool
	// certIgnoreTimestamp controls whether certificate timestamp validation is
	// skipped. Stored as atomic.Bool because it is written from the cert-refresh
	// background goroutine and read from query-processing goroutines concurrently.
	certIgnoreTimestamp           atomic.Bool
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
	ctx, cancel := context.WithCancel(context.Background())
	return &Proxy{
		serversInfo:    NewServersInfo(),
		udpConnPool:    NewUDPConnPool(),
		tcpConnPool:    NewTCPConnPool(), // [P02]
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
	}
}

// StopProxy cancels the shutdown context, signalling all background goroutines
// (source prefetch and cert refresh loops) started by StartProxy to exit
// cleanly. It is safe to call more than once.
func (proxy *Proxy) StopProxy() {
	proxy.shutdownCancel()
}

// ── Listener registration ─────────────────────────────────────────────────────

// registerUDPListener appends conn to the UDP listener list under its own mutex.
// [P03] Uses udpListenersMu instead of the former shared listenersMu.
func (proxy *Proxy) registerUDPListener(conn *net.UDPConn) {
	proxy.udpListenersMu.Lock()
	proxy.udpListeners = append(proxy.udpListeners, conn)
	proxy.udpListenersMu.Unlock()
}

// registerTCPListener appends l to the TCP listener list under its own mutex.
// [P03] Uses tcpListenersMu instead of the former shared listenersMu.
func (proxy *Proxy) registerTCPListener(l *net.TCPListener) {
	proxy.tcpListenersMu.Lock()
	proxy.tcpListeners = append(proxy.tcpListeners, l)
	proxy.tcpListenersMu.Unlock()
}

// registerLocalDoHListener appends l to the local-DoH listener list under its
// own mutex.
// [P03] Uses doHListenersMu instead of the former shared listenersMu.
func (proxy *Proxy) registerLocalDoHListener(l *net.TCPListener) {
	proxy.doHListenersMu.Lock()
	proxy.localDoHListeners = append(proxy.localDoHListeners, l)
	proxy.doHListenersMu.Unlock()
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
	defer FileDescriptorsMu.Unlock() // unlock on function exit, covering all error paths

	udpPC, err := net.FilePacketConn(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerUDP"))
	if err != nil {
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}
	FileDescriptorNum++

	tcpL, err := net.FileListener(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerTCP"))
	if err != nil {
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}
	FileDescriptorNum++

	udpConn, ok := udpPC.(*net.UDPConn)
	if !ok {
		dlog.Fatal("setupChildListeners: inherited UDP file conn is not a *net.UDPConn")
	}
	dlog.Noticef("Now listening to %v [UDP]", listenUDPAddr)
	proxy.registerUDPListener(udpConn)

	tcpListener, ok := tcpL.(*net.TCPListener)
	if !ok {
		dlog.Fatal("setupChildListeners: inherited TCP file listener is not a *net.TCPListener")
	}
	dlog.Noticef("Now listening to %v [TCP]", listenAddrStr)
	proxy.registerTCPListener(tcpListener)
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
	defer FileDescriptorsMu.Unlock() // unlock on function exit, covering all error paths
	tcpL, err := net.FileListener(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerTCP"))
	if err != nil {
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}
	FileDescriptorNum++

	tcpListener, ok := tcpL.(*net.TCPListener)
	if !ok {
		dlog.Fatal("addLocalDoHListener: inherited TCP file listener is not a *net.TCPListener")
	}
	proxy.registerLocalDoHListener(tcpListener)
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
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return errors.New("udpListenerFromAddr: ListenPacket did not return a *net.UDPConn")
	}
	proxy.registerUDPListener(udpConn)
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
	tcpListener, ok := l.(*net.TCPListener)
	if !ok {
		_ = l.Close()
		return errors.New("tcpListenerFromAddr: Listen did not return a *net.TCPListener")
	}
	proxy.registerTCPListener(tcpListener)
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
	tcpListener, ok := l.(*net.TCPListener)
	if !ok {
		_ = l.Close()
		return errors.New("localDoHListenerFromAddr: Listen did not return a *net.TCPListener")
	}
	proxy.registerLocalDoHListener(tcpListener)
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
		proxy.certIgnoreTimestamp.Store(false)
	}

	if proxy.showCerts {
		os.Exit(0)
	}

	if liveServers <= 0 {
		dlog.Error(err)
		dlog.Notice("dnscrypt-proxy is waiting for at least one server to be reachable")
	}

	go proxy.startSourcePrefetchLoop()
	if len(proxy.serversInfo.registeredServers) > 0 {
		go proxy.startCertificateRefreshLoop(liveServers)
	}
}

func resetTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

func (proxy *Proxy) startSourcePrefetchLoop() {
	lastLogTime := time.Now()
	timer := time.NewTimer(parkedTimerDuration)
	defer timer.Stop()
	for {
		d := PrefetchSources(proxy.xTransport, proxy.sources)
		resetTimer(timer, d)
		select {
		case <-proxy.shutdownCtx.Done():
			return
		case <-timer.C:
		}
		proxy.updateRegisteredServers()
		if time.Since(lastLogTime) > 5*time.Minute {
			proxy.serversInfo.logWP2Stats()
			lastLogTime = time.Now()
		}
	}
}

func (proxy *Proxy) startCertificateRefreshLoop(initialLive int) {
	live := initialLive
	timer := time.NewTimer(parkedTimerDuration)
	defer timer.Stop()
	for {
		delay := proxy.certRefreshDelay
		if live == 0 {
			delay = proxy.certRefreshDelayAfterFailure
		}
		resetTimer(timer, delay)
		select {
		case <-proxy.shutdownCtx.Done():
			return
		case <-timer.C:
		}
		live, _ = proxy.serversInfo.refresh(proxy)
		if live > 0 {
			proxy.certIgnoreTimestamp.Store(false)
		}
	}
}

// startAcceptingClients launches listener goroutines for all registered
// sockets and nils the backing slices to release their memory.
func (proxy *Proxy) startAcceptingClients() {
	for _, pc := range proxy.udpListeners {
		go proxy.udpListener(pc)
	}
	proxy.udpListeners = nil

	for _, l := range proxy.tcpListeners {
		go proxy.tcpListener(l)
	}
	proxy.tcpListeners = nil

	for _, l := range proxy.localDoHListeners {
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

// prepareForRelay constructs and returns the anonymised-DNS relay header
// prepended to encryptedQuery in a single allocation.
//
// Wire layout:
//
//	[0xff × 8][0x00 × 2][ip.To16() = 16 bytes][big-endian port uint16][query]
//
// Returns an error when ip.To16() is nil (invalid or unspecified IP address).
func (proxy *Proxy) prepareForRelay(ip net.IP, port int, encryptedQuery []byte) ([]byte, error) {
	const magicLen = 8 // 0xff bytes
	const padLen = 2   // zero pad following magic
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, errors.New("prepareForRelay: ip.To16() returned nil; IP address may be invalid or unspecified")
	}
	ip16Len := len(ip16)
	total := magicLen + padLen + ip16Len + 2 + len(encryptedQuery)
	buf := make([]byte, total)

	for i := range magicLen {
		buf[i] = 0xff
	}
	// [magicLen : magicLen+padLen] is already zero from make.
	off := magicLen + padLen
	copy(buf[off:], ip16)
	off += ip16Len
	binary.BigEndian.PutUint16(buf[off:], uint16(port))
	off += 2
	copy(buf[off:], encryptedQuery)

	return buf, nil
}

// ── Upstream exchanges ────────────────────────────────────────────────────────

// exchangeWithUDPServer sends encryptedQuery to serverInfo's UDP endpoint,
// retrying udpRetries times on transient read errors, and returns the
// decrypted response.
//
// [P01] encryptedResponsePool eliminates the per-call make([]byte, MaxDNSPacketSize).
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
		var relayErr error
		query, relayErr = proxy.prepareForRelay(serverInfo.UDPAddr.IP, serverInfo.UDPAddr.Port, query)
		if relayErr != nil {
			proxy.udpConnPool.Discard(pc)
			return nil, relayErr
		}
	}

	// [P01] Borrow a pooled buffer; return it unconditionally after use.
	encryptedResponse := encryptedResponsePool.Get().([]byte)
	var readLen int
	var lastErr error

	// [C04] Named constant udpRetries; counted loop for attempt number in log.
	for i := 0; i < udpRetries; i++ {
		if _, err := pc.Write(query); err != nil {
			proxy.udpConnPool.Discard(pc)
			encryptedResponsePool.Put(encryptedResponse) //nolint:staticcheck // [P01]
			return nil, err
		}
		readLen, lastErr = pc.Read(encryptedResponse)
		if lastErr == nil {
			break
		}
		dlog.Debugf("[%v] Retry %d/%d on read error: %v", serverInfo.Name, i+1, udpRetries, lastErr)
	}

	if lastErr != nil {
		proxy.udpConnPool.Discard(pc)
		encryptedResponsePool.Put(encryptedResponse) //nolint:staticcheck // [P01]
		return nil, lastErr
	}

	proxy.udpConnPool.Put(upstreamAddr, pc)

	// Clone only the live bytes before returning the full-capacity buffer. [P01]
	responseSlice := bytes.Clone(encryptedResponse[:readLen])
	encryptedResponsePool.Put(encryptedResponse) //nolint:staticcheck
	return proxy.Decrypt(serverInfo, sharedKey, responseSlice, clientNonce)
}

// exchangeWithUDPServerViaProxy routes the UDP exchange through a SOCKS proxy.
//
// [P01] encryptedResponsePool used here as well.
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
		return nil, err
	}
	defer pc.Close()

	applyTCPOpts(pc) // [P02] TCP_NODELAY + KeepAlive when dialer returns a TCPConn

	if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		return nil, err
	}

	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		var relayErr error
		encryptedQuery, relayErr = proxy.prepareForRelay(serverInfo.UDPAddr.IP, serverInfo.UDPAddr.Port, encryptedQuery)
		if relayErr != nil {
			return nil, relayErr
		}
	}

	// [P01] Borrow a pooled buffer.
	encryptedResponse := encryptedResponsePool.Get().([]byte)
	var readLen int
	var lastErr error

	// [C04] Named constant udpRetries; counted loop for attempt number in log.
	for i := 0; i < udpRetries; i++ {
		if _, err := pc.Write(encryptedQuery); err != nil {
			encryptedResponsePool.Put(encryptedResponse) //nolint:staticcheck
			return nil, err
		}
		readLen, lastErr = pc.Read(encryptedResponse)
		if lastErr == nil {
			break
		}
		dlog.Debugf("[%v] Retry %d/%d on read error: %v", serverInfo.Name, i+1, udpRetries, lastErr)
	}

	if lastErr != nil {
		encryptedResponsePool.Put(encryptedResponse) //nolint:staticcheck // [P01]
		return nil, lastErr
	}

	responseSlice := bytes.Clone(encryptedResponse[:readLen])
	encryptedResponsePool.Put(encryptedResponse) //nolint:staticcheck // [P01]
	return proxy.Decrypt(serverInfo, sharedKey, responseSlice, clientNonce)
}

// exchangeWithTCPServer obtains an upstream TCP connection from the pool,
// sends the query, and returns the decrypted response.  On success the
// connection is returned to the pool; on error it is discarded.
//
// [P02] TCPConnPool replaces the per-query dial path, eliminating the TCP+TLS
// handshake latency on every upstream exchange.
//
// [C11] context.WithTimeout is used when dialling a new connection (inside
// TCPConnPool.Get) instead of the deprecated net.DialTimeout.
//
// [P06] NOTE: For OpenWrt/ARM/MIPS deployments without hardware AES, set
// XTransport's TLS config CipherSuites to prefer
// tls.TLS_CHACHA20_POLY1305_SHA256 to reduce CPU overhead on the encryption
// path by up to 3–5×.
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
		if err != nil {
			return nil, err
		}
		applyTCPOpts(pc) // [P02] TCP_NODELAY + KeepAlive
		defer pc.Close()
	} else {
		// [P02] Get from pool (dials on miss with context timeout internally).
		pc, err = proxy.tcpConnPool.Get(upstreamAddr, serverInfo.Timeout)
		if err != nil {
			return nil, err
		}
	}

	// [P07] Use per-direction deadlines to avoid deadline leakage on pooled
	// connections.  SetDeadline sets both read and write; splitting them lets
	// us clear each one independently and makes the intent explicit.
	deadline := time.Now().Add(serverInfo.Timeout)
	if err := pc.SetWriteDeadline(deadline); err != nil {
		proxy.tcpConnPool.Discard(pc)
		return nil, err
	}

	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		var relayErr error
		encryptedQuery, relayErr = proxy.prepareForRelay(serverInfo.TCPAddr.IP, serverInfo.TCPAddr.Port, encryptedQuery)
		if relayErr != nil {
			proxy.tcpConnPool.Discard(pc)
			return nil, relayErr
		}
	}

	encryptedQuery, err = PrefixWithSize(encryptedQuery)
	if err != nil {
		proxy.tcpConnPool.Discard(pc)
		return nil, err
	}
	if _, err := pc.Write(encryptedQuery); err != nil {
		proxy.tcpConnPool.Discard(pc)
		return nil, err
	}

	if err := pc.SetReadDeadline(deadline); err != nil {
		proxy.tcpConnPool.Discard(pc)
		return nil, err
	}
	encryptedResponse, err := ReadPrefixed(&pc)
	if err != nil {
		proxy.tcpConnPool.Discard(pc)
		return nil, err
	}

	// Return healthy connection to pool when not going via a proxy dialer.
	// [P07] Clear deadlines before pooling so the next borrower starts clean.
	// If clearing the deadline fails, discard the connection rather than risk
	// returning a conn with stale timeouts to the pool.
	if proxy.xTransport.proxyDialer == nil {
		if err := pc.SetDeadline(time.Time{}); err != nil {
			proxy.tcpConnPool.Discard(pc)
		} else {
			proxy.tcpConnPool.Put(upstreamAddr, pc)
		}
	}

	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

// ── Active-client counter ─────────────────────────────────────────────────────

// clientsCountInc atomically increments the active-client counter.
// Returns false without incrementing when the configured limit would be
// exceeded.
//
// [P07] Debug log removed — this runs on every incoming connection and
// dlog.Debugf string formatting is not free even at non-debug log levels.
func (proxy *Proxy) clientsCountInc() bool {
	for {
		cur := proxy.clientsCount.Load()
		if cur >= proxy.maxClients {
			return false
		}
		if proxy.clientsCount.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// clientsCountDec atomically decrements the active-client counter.
// Uses a CAS loop to avoid the race window between Load and Add that the
// former Load+Add(^uint32(0)) pattern had.  Guards against underflow.
//
// [P07] Debug log removed — same hot-path reasoning as clientsCountInc.
func (proxy *Proxy) clientsCountDec() {
	for {
		cur := proxy.clientsCount.Load()
		if cur == 0 {
			return
		}
		if proxy.clientsCount.CompareAndSwap(cur, cur-1) {
			return
		}
	}
}

// ── Dynamic timeout ───────────────────────────────────────────────────────────

// getDynamicTimeout returns a per-request deadline scaled down under load.
//
// Reduction follows a quartic curve (utilisation⁴) so the timeout only shrinks
// appreciably at very high load.  Minimum is 10 % of the configured baseline.
func (proxy *Proxy) getDynamicTimeout() time.Duration {
	if proxy.timeoutLoadReduction <= 0 || proxy.maxClients == 0 {
		return proxy.timeout
	}
	utilization := float64(proxy.clientsCount.Load()) / float64(proxy.maxClients)
	timeoutF := float64(proxy.timeout)
	u2 := utilization * utilization
	u4 := u2 * u2
	factor := max(1.0-(u4*proxy.timeoutLoadReduction), 0.1)
	return time.Duration(timeoutF * factor)
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
	defer pluginsState.ReleaseSessionData(&proxy.pluginsGlobals)

	// [P05] Resolve serverInfo once upfront when we know we'll need an upstream
	// exchange (i.e. not cache-only mode), so the plugin callback and the
	// post-synth-response branch share the same pre-resolved value.
	var serverInfo *ServerInfo
	serverName := unknownServerName // [C15] declared at first use, not at top of func
	if !onlyCached {
		serverInfo = proxy.serversInfo.getOne()
		if serverInfo != nil {
			serverName = serverInfo.Name
		}
	}

	query, err := pluginsState.ApplyQueryPlugins(
		&proxy.pluginsGlobals,
		query,
		func() (*ServerInfo, bool) {
			// [P05] serverInfo already resolved above; lazy-init only as fallback.
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
		// [P05] serverInfo already resolved; the nil guard below only fires in
		// the unlikely case the plugin callback was never invoked.
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

			exchangeResponse, exchErr := handleDNSExchange(proxy, serverInfo, &pluginsState, query, transportProto(serverProto))
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
		// Explicit typed assignment avoids inference as plain int. [FIX-01]
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

	sendResponse(proxy, &pluginsState, response, transportProto(clientProto), clientAddr, clientPc)
	pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
	updateMonitoringMetrics(proxy, &pluginsState)

	return response
}
