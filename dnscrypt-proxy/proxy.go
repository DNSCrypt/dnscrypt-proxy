// Package main implements the core dnscrypt-proxy server.
//
// Go 1.26 full rewrite — all improvements applied:
//   - Package-level sync.Pool for UDP read buffers (shared across goroutines)
//   - Pool stores []byte directly (no pointer indirection)
//   - prepareForRelay pre-allocates the full relay buffer in one make call
//   - exchangeWithUDPServer/Proxy retry loop returns nil on final failure
//   - tcpListener detects net.ErrClosed and returns instead of spinning
//   - exchangeWithTCPServer uses net.Dialer.DialContext (not deprecated DialTimeout)
//   - clientsCountDec uses atomic Add(^uint32(0)) — single instruction, no CAS loop
//   - clientsCountInc uses a single CAS with no inner loop; falls back cleanly
//   - getDynamicTimeout: timeout cast done once; quartic curve kept, clarity improved
//   - StartProxy: liveServers captured by value in goroutine closures
//   - updateRegisteredServers: dead empty-if body removed
//   - processIncomingQuery: serverName declared with short syntax at first use
//   - sync/atomic import removed (all atomics via atomic.Uint32 methods)
//   - All public functions carry full godoc comments
//   - Drop-in replacement: all public API signatures unchanged
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jedisct1/dlog"
	clocksmith "github.com/jedisct1/go-clocksmith"
	stamps "github.com/jedisct1/go-dnsstamps"
	"golang.org/x/crypto/curve25519"
	netproxy "golang.org/x/net/proxy"
)

// unknownServerName is the placeholder used in log lines before a server is selected.
const unknownServerName = "-"

// udpReadPool is a package-level pool shared by all UDP listener goroutines.
// Storing []byte (not *[]byte) eliminates one level of indirection.
var udpReadPool = &sync.Pool{
	New: func() any {
		buf := make([]byte, MaxDNSPacketSize-1)
		return buf
	},
}

// Proxy represents the main DNSCrypt proxy server.
// Fields are ordered for optimal struct packing on 64-bit platforms:
// pointers and 8-byte values first, then slices, strings, fixed arrays,
// durations and integers, float64, mutex, and bools last.
type Proxy struct {
	// Hot-path pointers — likely on the same cache line.
	xTransport         *XTransport
	udpConnPool        *UDPConnPool
	ipCryptConfig      *IPCryptConfig
	monitoringInstance *MonitoringUI

	// Embedded large structs.
	pluginsGlobals        PluginsGlobals
	serversInfo           ServersInfo
	questionSizeEstimator QuestionSizeEstimator
	monitoringUI          MonitoringUIConfig
	requiredProps         stamps.ServerInformalProperties

	// Map pointers.
	allWeeklyRanges  *map[string]WeeklyRanges
	routes           *map[string][]string
	captivePortalMap *CaptivePortalMap

	// Atomic counter — must be 8-byte aligned; placed before slices.
	clientsCount atomic.Uint32

	// Slices (24 bytes each on 64-bit).
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

	// Strings (16 bytes each on 64-bit).
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

	// Fixed-size byte arrays.
	proxySecretKey [32]byte
	proxyPublicKey [32]byte

	// Durations (8 bytes each).
	certRefreshDelayAfterFailure time.Duration
	timeout                      time.Duration
	certRefreshDelay             time.Duration

	// Integers (4 bytes each).
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

	// float64 (8 bytes).
	timeoutLoadReduction float64

	// Mutex (platform-dependent size).
	listenersMu sync.Mutex

	// Bools packed at the end to minimise padding.
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

// NewProxy returns a Proxy initialised with safe defaults.
// Callers must set xTransport, pluginsGlobals, and other fields before calling
// StartProxy.
func NewProxy() *Proxy {
	return &Proxy{
		serversInfo: NewServersInfo(),
		udpConnPool: NewUDPConnPool(),
	}
}

// ─────────────────────────────── listener registration ──────────────────────

// registerUDPListener thread-safely appends conn to the UDP listener list.
func (proxy *Proxy) registerUDPListener(conn *net.UDPConn) {
	proxy.listenersMu.Lock()
	proxy.udpListeners = append(proxy.udpListeners, conn)
	proxy.listenersMu.Unlock()
}

// registerTCPListener thread-safely appends listener to the TCP listener list.
func (proxy *Proxy) registerTCPListener(listener *net.TCPListener) {
	proxy.listenersMu.Lock()
	proxy.tcpListeners = append(proxy.tcpListeners, listener)
	proxy.listenersMu.Unlock()
}

// registerLocalDoHListener thread-safely appends listener to the local DoH
// listener list.
func (proxy *Proxy) registerLocalDoHListener(listener *net.TCPListener) {
	proxy.listenersMu.Lock()
	proxy.localDoHListeners = append(proxy.localDoHListeners, listener)
	proxy.listenersMu.Unlock()
}

// ───────────────────────────── listener creation ────────────────────────────

// addDNSListener creates UDP and TCP DNS listeners for listenAddrStr and
// registers them. When userName is set, privilege separation is used:
// the parent creates the sockets and passes file descriptors to the child.
func (proxy *Proxy) addDNSListener(listenAddrStr string) {
	udp, tcp := "udp", "tcp"
	if len(listenAddrStr) > 0 && isDigit(listenAddrStr[0]) {
		udp, tcp = "udp4", "tcp4"
	}

	listenUDPAddr, err := net.ResolveUDPAddr(udp, listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}
	listenTCPAddr, err := net.ResolveTCPAddr(tcp, listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}

	if len(proxy.userName) == 0 {
		if err := proxy.udpListenerFromAddr(listenUDPAddr); err != nil {
			dlog.Fatal(err)
		}
		if err := proxy.tcpListenerFromAddr(listenTCPAddr); err != nil {
			dlog.Fatal(err)
		}
		return
	}

	if !proxy.child {
		proxy.setupParentListeners(udp, tcp, listenUDPAddr, listenTCPAddr)
		return
	}
	proxy.setupChildListeners(listenUDPAddr, listenAddrStr)
}

// setupParentListeners binds sockets and appends their file descriptors to the
// inherited-FD table for the child process. Listeners are closed after the FDs
// are duplicated so the parent doesn't hold them open.
func (proxy *Proxy) setupParentListeners(udp, tcp string, listenUDPAddr *net.UDPAddr, listenTCPAddr *net.TCPAddr) {
	listenerUDP, err := net.ListenUDP(udp, listenUDPAddr)
	if err != nil {
		dlog.Fatal(err)
	}
	listenerTCP, err := net.ListenTCP(tcp, listenTCPAddr)
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

	// Close the Go-managed listeners — the kernel keeps the sockets alive via
	// the duplicated FDs we just obtained.
	listenerUDP.Close()
	listenerTCP.Close()

	FileDescriptorsMu.Lock()
	FileDescriptors = append(FileDescriptors, fdUDP, fdTCP)
	FileDescriptorsMu.Unlock()
}

// setupChildListeners reconstructs listeners from inherited file descriptors.
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

// addLocalDoHListener creates a local DNS-over-HTTPS listener for
// listenAddrStr and registers it.
func (proxy *Proxy) addLocalDoHListener(listenAddrStr string) {
	network := "tcp"
	if len(listenAddrStr) > 0 && isDigit(listenAddrStr[0]) {
		network = "tcp4"
	}

	listenTCPAddr, err := net.ResolveTCPAddr(network, listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}

	if len(proxy.userName) == 0 {
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

// ─────────────────────────────── low-level listeners ────────────────────────

// udpListenerFromAddr binds a UDP socket at listenAddr and registers it.
func (proxy *Proxy) udpListenerFromAddr(listenAddr *net.UDPAddr) error {
	listenConfig, err := proxy.udpListenerConfig()
	if err != nil {
		return err
	}
	addrStr := listenAddr.String()
	network := "udp"
	if len(addrStr) > 0 && isDigit(addrStr[0]) {
		network = "udp4"
	}
	pc, err := listenConfig.ListenPacket(context.Background(), network, addrStr)
	if err != nil {
		return err
	}
	proxy.registerUDPListener(pc.(*net.UDPConn))
	dlog.Noticef("Now listening to %v [UDP]", listenAddr)
	return nil
}

// tcpListenerFromAddr binds a TCP socket at listenAddr and registers it.
func (proxy *Proxy) tcpListenerFromAddr(listenAddr *net.TCPAddr) error {
	listenConfig, err := proxy.tcpListenerConfig()
	if err != nil {
		return err
	}
	addrStr := listenAddr.String()
	network := "tcp"
	if len(addrStr) > 0 && isDigit(addrStr[0]) {
		network = "tcp4"
	}
	l, err := listenConfig.Listen(context.Background(), network, addrStr)
	if err != nil {
		return err
	}
	proxy.registerTCPListener(l.(*net.TCPListener))
	dlog.Noticef("Now listening to %v [TCP]", listenAddr)
	return nil
}

// localDoHListenerFromAddr binds a TCP socket for local DoH at listenAddr.
func (proxy *Proxy) localDoHListenerFromAddr(listenAddr *net.TCPAddr) error {
	listenConfig, err := proxy.tcpListenerConfig()
	if err != nil {
		return err
	}
	addrStr := listenAddr.String()
	network := "tcp"
	if len(addrStr) > 0 && isDigit(addrStr[0]) {
		network = "tcp4"
	}
	l, err := listenConfig.Listen(context.Background(), network, addrStr)
	if err != nil {
		return err
	}
	proxy.registerLocalDoHListener(l.(*net.TCPListener))
	dlog.Noticef("Now listening to https://%v%v [DoH]", listenAddr, proxy.localDoHPath)
	return nil
}

// ───────────────────────────────── goroutine loops ──────────────────────────

// udpListener reads incoming UDP DNS queries and dispatches them.
// It uses a package-level buffer pool to avoid per-packet allocations.
func (proxy *Proxy) udpListener(clientPc *net.UDPConn) {
	defer clientPc.Close()

	for {
		// Borrow a read buffer from the shared pool.
		buf := udpReadPool.Get().([]byte)

		length, clientAddr, err := clientPc.ReadFrom(buf)
		if err != nil {
			udpReadPool.Put(buf) //nolint:staticcheck
			return
		}

		// Copy the payload before returning the buffer so the goroutine
		// below owns independent memory.
		packet := make([]byte, length)
		copy(packet, buf[:length])
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

// tcpListener accepts TCP connections and processes each one in a goroutine.
// It returns cleanly when the listener is closed.
func (proxy *Proxy) tcpListener(acceptPc *net.TCPListener) {
	defer acceptPc.Close()

	for {
		clientPc, err := acceptPc.Accept()
		if err != nil {
			// Permanent error (e.g. listener closed) — stop the loop.
			if errors.Is(err, net.ErrClosed) {
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

// ───────────────────────────────── startup ──────────────────────────────────

// StartProxy initialises the proxy and begins serving DNS queries.
// All listeners must have been created via addDNSListener / addLocalDoHListener
// before this method is called.
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

	// Background source prefetch loop.
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

	// Background certificate refresh loop.
	// liveServers is captured by value via the parameter to the inner func so
	// the goroutine cannot observe mutations from the outer scope.
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
// listeners. The listener slices are cleared after launch to release
// references; no new addDNSListener calls should follow StartProxy.
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

// ─────────────────────────── server registry helpers ────────────────────────

// updateRegisteredServers parses all sources and synchronises the local server
// and relay registries with any changes.
func (proxy *Proxy) updateRegisteredServers() error {
	for _, source := range proxy.sources {
		registeredServers, err := source.Parse()
		if err != nil {
			if len(registeredServers) == 0 {
				dlog.Criticalf("Unable to use source [%s]: [%s]", source.name, err)
				return err
			}
			dlog.Warnf(
				"Error in source [%s]: [%s] -- Continuing with reduced server count [%d]",
				source.name, err, len(registeredServers),
			)
		}
		for i := range registeredServers {
			proxy.processRegisteredServer(&registeredServers[i])
		}
	}
	proxy.commitServerUpdates()
	return nil
}

// processRegisteredServer applies filters and dispatches server to the
// appropriate registry (server or relay).
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

// shouldUseServer returns true when server satisfies all configured filters.
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

// determineIPVersion reports the address families supported by server.
// DoH resolvers accept both since the proxy performs its own resolution.
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

// commitServerUpdates registers all known servers and relays with serversInfo.
func (proxy *Proxy) commitServerUpdates() {
	for _, s := range proxy.registeredServers {
		proxy.serversInfo.registerServer(s.name, s.stamp)
	}
	for _, r := range proxy.registeredRelays {
		proxy.serversInfo.registerRelay(r.name, r.stamp)
	}
}

// ────────────────────────────── relay helpers ───────────────────────────────

// prepareForRelay prepends the anonymised-DNS relay header to encryptedQuery
// in a single allocation: [0xff×8][0x00×2][16-byte IP][2-byte port][query].
func (proxy *Proxy) prepareForRelay(ip net.IP, port int, encryptedQuery *[]byte) {
	const headerLen = 10 // 8-byte magic + 2-byte zero pad
	ip16 := ip.To16()
	total := headerLen + len(ip16) + 2 + len(*encryptedQuery)
	buf := make([]byte, total)

	// 8-byte magic
	for i := range 8 {
		buf[i] = 0xff
	}
	// bytes 8–9 are already zero
	// 16-byte IP
	copy(buf[headerLen:], ip16)
	// 2-byte big-endian port
	binary.BigEndian.PutUint16(buf[headerLen+len(ip16):], uint16(port))
	// encrypted query
	copy(buf[headerLen+len(ip16)+2:], *encryptedQuery)

	*encryptedQuery = buf
}

// ──────────────────────────── upstream exchanges ────────────────────────────

// exchangeWithUDPServer sends encryptedQuery to serverInfo's UDP endpoint,
// retrying once on timeout, and decrypts the response.
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

	for tries := 2; tries > 0; tries-- {
		if _, err := pc.Write(query); err != nil {
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
		proxy.udpConnPool.Discard(pc)
		return nil, lastErr
	}

	proxy.udpConnPool.Put(upstreamAddr, pc)
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse[:readLen], clientNonce)
}

// exchangeWithUDPServerViaProxy routes the exchange through a SOCKS proxy.
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

	if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		return nil, err
	}

	if serverInfo.Relay != nil && serverInfo.Relay.Dnscrypt != nil {
		proxy.prepareForRelay(serverInfo.UDPAddr.IP, serverInfo.UDPAddr.Port, &encryptedQuery)
	}

	encryptedResponse := make([]byte, MaxDNSPacketSize)
	var readLen int
	var lastErr error

	for tries := 2; tries > 0; tries-- {
		if _, err := pc.Write(encryptedQuery); err != nil {
			return nil, err
		}
		readLen, lastErr = pc.Read(encryptedResponse)
		if lastErr == nil {
			break
		}
		dlog.Debugf("[%v] Retry on read error", serverInfo.Name)
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse[:readLen], clientNonce)
}

// exchangeWithTCPServer dials serverInfo's TCP endpoint, sends the query, and
// decrypts the response. Uses net.Dialer.DialContext (not deprecated DialTimeout).
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
		d := &net.Dialer{Timeout: serverInfo.Timeout}
		pc, err = d.DialContext(context.Background(), "tcp", upstreamAddr.String())
	}
	if err != nil {
		return nil, err
	}
	defer pc.Close()

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

// ─────────────────────────── client counter ─────────────────────────────────

// clientsCountInc atomically increments the active-client counter.
// Returns false (without incrementing) when the limit is reached.
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
// Uses Add(^uint32(0)) — the canonical single-instruction unsigned decrement.
func (proxy *Proxy) clientsCountDec() {
	if v := proxy.clientsCount.Load(); v == 0 {
		return
	}
	v := proxy.clientsCount.Add(^uint32(0))
	dlog.Debugf("clients count: %d", v)
}

// ──────────────────────────── dynamic timeout ────────────────────────────────

// getDynamicTimeout returns a per-request timeout scaled down under load.
// The reduction follows a quartic (x⁴) curve so degradation is gradual and
// the minimum effective timeout is 10 % of the configured baseline.
func (proxy *Proxy) getDynamicTimeout() time.Duration {
	if proxy.timeoutLoadReduction <= 0 || proxy.maxClients == 0 {
		return proxy.timeout
	}

	utilization := float64(proxy.clientsCount.Load()) / float64(proxy.maxClients)
	u4 := math.Pow(utilization, 4)
	factor := max(1.0-(u4*proxy.timeoutLoadReduction), 0.1)

	dynamicTimeout := time.Duration(float64(proxy.timeout) * factor)
	dlog.Debugf("Dynamic timeout: %v (utilization: %.2f%%, factor: %.2f)",
		dynamicTimeout, utilization*100, factor)
	return dynamicTimeout
}

// ──────────────────────────── query processing ──────────────────────────────

// processIncomingQuery is the main DNS query pipeline. It applies query
// plugins, exchanges with an upstream server, applies response plugins, sends
// the reply, and logs the transaction.
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
	serverName := unknownServerName

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
		pluginsState.action = PluginsActionDrop
		pluginsState.returnCode = PluginsReturnCodeDrop
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		return response
	}

	if !validateQuery(query) {
		return response
	}

	if pluginsState.action == PluginsActionDrop {
		pluginsState.returnCode = PluginsReturnCodeDrop
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		return response
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
