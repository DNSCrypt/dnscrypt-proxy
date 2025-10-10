package main

import (
	"context"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedisct1/dlog"
	clocksmith "github.com/jedisct1/go-clocksmith"
	stamps "github.com/jedisct1/go-dnsstamps"
	"golang.org/x/crypto/curve25519"
)

type Proxy struct {
	pluginsGlobals                PluginsGlobals
	serversInfo                   ServersInfo
	questionSizeEstimator         QuestionSizeEstimator
	registeredServers             []RegisteredServer
	dns64Resolvers                []string
	dns64Prefixes                 []string
	serversBlockingFragments      []string
	ednsClientSubnets             []*net.IPNet
	queryLogIgnoredQtypes         []string
	localDoHListeners             []*net.TCPListener
	queryMeta                     []string
	enableHotReload               bool
	udpListeners                  []*net.UDPConn
	sources                       []*Source
	tcpListeners                  []*net.TCPListener
	registeredRelays              []RegisteredServer
	listenAddresses               []string
	localDoHListenAddresses       []string
	monitoringUI                  MonitoringUIConfig
	monitoringInstance            *MonitoringUI
	xTransport                    *XTransport
	allWeeklyRanges               *map[string]WeeklyRanges
	routes                        *map[string][]string
	captivePortalMap              *CaptivePortalMap
	nxLogFormat                   string
	localDoHCertFile              string
	localDoHCertKeyFile           string
	captivePortalMapFile          string
	localDoHPath                  string
	mainProto                     string
	cloakFile                     string
	forwardFile                   string
	blockIPFormat                 string
	blockIPLogFile                string
	allowedIPFile                 string
	allowedIPFormat               string
	allowedIPLogFile              string
	queryLogFormat                string
	blockIPFile                   string
	allowNameFile                 string
	allowNameFormat               string
	allowNameLogFile              string
	blockNameLogFile              string
	blockNameFormat               string
	blockNameFile                 string
	queryLogFile                  string
	blockedQueryResponse          string
	userName                      string
	nxLogFile                     string
	proxySecretKey                [32]byte
	proxyPublicKey                [32]byte
	ServerNames                   []string
	DisabledServerNames           []string
	requiredProps                 stamps.ServerInformalProperties
	certRefreshDelayAfterFailure  time.Duration
	timeout                       time.Duration
	certRefreshDelay              time.Duration
	certRefreshConcurrency        int
	cacheSize                     int
	logMaxBackups                 int
	logMaxAge                     int
	logMaxSize                    int
	cacheNegMinTTL                uint32
	rejectTTL                     uint32
	cacheMaxTTL                   uint32
	clientsCount                  uint32
	maxClients                    uint32
	cacheMinTTL                   uint32
	cacheNegMaxTTL                uint32
	cloakTTL                      uint32
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
	listenersMu                   sync.Mutex
	ipCryptConfig                 *IPCryptConfig
}

func (proxy *Proxy) registerUDPListener(conn *net.UDPConn) {
	proxy.listenersMu.Lock()
	proxy.udpListeners = append(proxy.udpListeners, conn)
	proxy.listenersMu.Unlock()
}

func (proxy *Proxy) registerTCPListener(listener *net.TCPListener) {
	proxy.listenersMu.Lock()
	proxy.tcpListeners = append(proxy.tcpListeners, listener)
	proxy.listenersMu.Unlock()
}

func (proxy *Proxy) registerLocalDoHListener(listener *net.TCPListener) {
	proxy.listenersMu.Lock()
	proxy.localDoHListeners = append(proxy.localDoHListeners, listener)
	proxy.listenersMu.Unlock()
}

func (proxy *Proxy) addDNSListener(listenAddrStr string) {
	udp := "udp"
	tcp := "tcp"
	isIPv4 := len(listenAddrStr) > 0 && isDigit(listenAddrStr[0])
	if isIPv4 {
		udp = "udp4"
		tcp = "tcp4"
	}
	listenUDPAddr, err := net.ResolveUDPAddr(udp, listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}
	listenTCPAddr, err := net.ResolveTCPAddr(tcp, listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}

	// if 'userName' is not set, continue as before
	if len(proxy.userName) <= 0 {
		if err := proxy.udpListenerFromAddr(listenUDPAddr); err != nil {
			dlog.Fatal(err)
		}
		if err := proxy.tcpListenerFromAddr(listenTCPAddr); err != nil {
			dlog.Fatal(err)
		}
		return
	}

	// if 'userName' is set and we are the parent process
	if !proxy.child {
		// parent
		listenerUDP, err := net.ListenUDP(udp, listenUDPAddr)
		if err != nil {
			dlog.Fatal(err)
		}
		listenerTCP, err := net.ListenTCP(tcp, listenTCPAddr)
		if err != nil {
			dlog.Fatal(err)
		}

		fdUDP, err := listenerUDP.File() // On Windows, the File method of UDPConn is not implemented.
		if err != nil {
			dlog.Fatalf("Unable to switch to a different user: %v", err)
		}
		fdTCP, err := listenerTCP.File() // On Windows, the File method of TCPListener is not implemented.
		if err != nil {
			dlog.Fatalf("Unable to switch to a different user: %v", err)
		}
		defer listenerUDP.Close()
		defer listenerTCP.Close()
		FileDescriptorsMu.Lock()
		FileDescriptors = append(FileDescriptors, fdUDP)
		FileDescriptors = append(FileDescriptors, fdTCP)
		FileDescriptorsMu.Unlock()
		return
	}

	// child
	FileDescriptorsMu.Lock()
	listenerUDP, err := net.FilePacketConn(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerUDP"))
	if err != nil {
		FileDescriptorsMu.Unlock()
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}
	FileDescriptorNum++

	listenerTCP, err := net.FileListener(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerTCP"))
	if err != nil {
		FileDescriptorsMu.Unlock()
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}
	FileDescriptorNum++
	FileDescriptorsMu.Unlock()

	dlog.Noticef("Now listening to %v [UDP]", listenUDPAddr)
	proxy.registerUDPListener(listenerUDP.(*net.UDPConn))

	dlog.Noticef("Now listening to %v [TCP]", listenAddrStr)
	proxy.registerTCPListener(listenerTCP.(*net.TCPListener))
}

func (proxy *Proxy) addLocalDoHListener(listenAddrStr string) {
	network := "tcp"
	isIPv4 := len(listenAddrStr) > 0 && isDigit(listenAddrStr[0])
	if isIPv4 {
		network = "tcp4"
	}
	listenTCPAddr, err := net.ResolveTCPAddr(network, listenAddrStr)
	if err != nil {
		dlog.Fatal(err)
	}

	// if 'userName' is not set, continue as before
	if len(proxy.userName) <= 0 {
		if err := proxy.localDoHListenerFromAddr(listenTCPAddr); err != nil {
			dlog.Fatal(err)
		}
		return
	}

	// if 'userName' is set and we are the parent process
	if !proxy.child {
		// parent
		listenerTCP, err := net.ListenTCP(network, listenTCPAddr)
		if err != nil {
			dlog.Fatal(err)
		}
		fdTCP, err := listenerTCP.File() // On Windows, the File method of TCPListener is not implemented.
		if err != nil {
			dlog.Fatalf("Unable to switch to a different user: %v", err)
		}
		defer listenerTCP.Close()
		FileDescriptors = append(FileDescriptors, fdTCP)
		return
	}

	// child

	listenerTCP, err := net.FileListener(os.NewFile(InheritedDescriptorsBase+FileDescriptorNum, "listenerTCP"))
	if err != nil {
		dlog.Fatalf("Unable to switch to a different user: %v", err)
	}
	FileDescriptorNum++

	proxy.registerLocalDoHListener(listenerTCP.(*net.TCPListener))
	dlog.Noticef("Now listening to https://%v%v [DoH]", listenAddrStr, proxy.localDoHPath)
}

func (proxy *Proxy) StartProxy() {
	proxy.questionSizeEstimator = NewQuestionSizeEstimator()
	if _, err := crypto_rand.Read(proxy.proxySecretKey[:]); err != nil {
		dlog.Fatal(err)
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)

	// Initialize and start the monitoring UI if enabled
	if proxy.monitoringUI.Enabled {
		dlog.Noticef("Initializing monitoring UI")
		proxy.monitoringInstance = NewMonitoringUI(proxy)
		if proxy.monitoringInstance == nil {
			dlog.Errorf("Failed to create monitoring UI instance")
		} else {
			dlog.Noticef("Starting monitoring UI")
			if err := proxy.monitoringInstance.Start(); err != nil {
				dlog.Errorf("Failed to start monitoring UI: %v", err)
			} else {
				dlog.Noticef("Monitoring UI started successfully")
			}
		}
	}

	proxy.startAcceptingClients()
	if !proxy.child {
		// Notify the service manager that dnscrypt-proxy is ready. dnscrypt-proxy manages itself in case
		// servers are not immediately live/reachable. The service manager may assume it is initialized and
		// functioning properly. Note that the service manager 'Ready' signal is delayed if netprobe
		// cannot reach the internet during start-up.
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
	go func() {
		lastLogTime := time.Now()
		for {
			clocksmith.Sleep(PrefetchSources(proxy.xTransport, proxy.sources))
			proxy.updateRegisteredServers()

			// Log WP2 statistics every 5 minutes if debug logging is enabled
			if time.Since(lastLogTime) > 5*time.Minute {
				proxy.serversInfo.logWP2Stats()
				lastLogTime = time.Now()
			}

			runtime.GC()
		}
	}()
	if len(proxy.serversInfo.registeredServers) > 0 {
		go func() {
			for {
				delay := proxy.certRefreshDelay
				if liveServers == 0 {
					delay = proxy.certRefreshDelayAfterFailure
				}
				clocksmith.Sleep(delay)
				liveServers, _ = proxy.serversInfo.refresh(proxy)
				if liveServers > 0 {
					proxy.certIgnoreTimestamp = false
				}
				runtime.GC()
			}
		}()
	}
}

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
				source.name,
				err,
				len(registeredServers),
			)
		}
		for _, registeredServer := range registeredServers {
			if registeredServer.stamp.Proto != stamps.StampProtoTypeDNSCryptRelay &&
				registeredServer.stamp.Proto != stamps.StampProtoTypeODoHRelay {
				if len(proxy.ServerNames) > 0 {
					if !includesName(proxy.ServerNames, registeredServer.name) {
						continue
					}
				} else if registeredServer.stamp.Props&proxy.requiredProps != proxy.requiredProps {
					continue
				}
			}
			if includesName(proxy.DisabledServerNames, registeredServer.name) {
				continue
			}
			if proxy.SourceIPv4 || proxy.SourceIPv6 {
				isIPv4, isIPv6 := true, false
				if registeredServer.stamp.Proto == stamps.StampProtoTypeDoH {
					isIPv4, isIPv6 = true, true
				}
				if strings.HasPrefix(registeredServer.stamp.ServerAddrStr, "[") {
					isIPv4, isIPv6 = false, true
				}
				if !(proxy.SourceIPv4 == isIPv4 || proxy.SourceIPv6 == isIPv6) {
					continue
				}
			}
			if registeredServer.stamp.Proto == stamps.StampProtoTypeDNSCryptRelay ||
				registeredServer.stamp.Proto == stamps.StampProtoTypeODoHRelay {
				var found bool
				for i, currentRegisteredRelay := range proxy.registeredRelays {
					if currentRegisteredRelay.name == registeredServer.name {
						found = true
						if currentRegisteredRelay.stamp.String() != registeredServer.stamp.String() {
							dlog.Infof(
								"Updating stamp for [%s] was: %s now: %s",
								registeredServer.name,
								currentRegisteredRelay.stamp.String(),
								registeredServer.stamp.String(),
							)
							proxy.registeredRelays[i].stamp = registeredServer.stamp
							dlog.Debugf("Total count of registered relays %v", len(proxy.registeredRelays))
						}
					}
				}
				if !found {
					dlog.Debugf("Adding [%s] to the set of available relays", registeredServer.name)
					proxy.registeredRelays = append(proxy.registeredRelays, registeredServer)
				}
			} else {
				if !((proxy.SourceDNSCrypt && registeredServer.stamp.Proto == stamps.StampProtoTypeDNSCrypt) ||
					(proxy.SourceDoH && registeredServer.stamp.Proto == stamps.StampProtoTypeDoH) ||
					(proxy.SourceODoH && registeredServer.stamp.Proto == stamps.StampProtoTypeODoHTarget)) {
					continue
				}
				var found bool
				for i, currentRegisteredServer := range proxy.registeredServers {
					if currentRegisteredServer.name == registeredServer.name {
						found = true
						if currentRegisteredServer.stamp.String() != registeredServer.stamp.String() {
							dlog.Infof("Updating stamp for [%s] was: %s now: %s", registeredServer.name, currentRegisteredServer.stamp.String(), registeredServer.stamp.String())
							proxy.registeredServers[i].stamp = registeredServer.stamp
						}
					}
				}
				if !found {
					dlog.Debugf("Adding [%s] to the set of wanted resolvers", registeredServer.name)
					proxy.registeredServers = append(proxy.registeredServers, registeredServer)
					dlog.Debugf("Total count of registered servers %v", len(proxy.registeredServers))
				}
			}
		}
	}
	for _, registeredServer := range proxy.registeredServers {
		proxy.serversInfo.registerServer(registeredServer.name, registeredServer.stamp)
	}
	for _, registeredRelay := range proxy.registeredRelays {
		proxy.serversInfo.registerRelay(registeredRelay.name, registeredRelay.stamp)
	}
	return nil
}

func (proxy *Proxy) udpListener(clientPc *net.UDPConn) {
	defer clientPc.Close()
	for {
		buffer := make([]byte, MaxDNSPacketSize-1)
		length, clientAddr, err := clientPc.ReadFrom(buffer)
		if err != nil {
			return
		}
		packet := buffer[:length]
		if !proxy.clientsCountInc() {
			dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
			proxy.processIncomingQuery(
				"udp",
				proxy.mainProto,
				packet,
				&clientAddr,
				clientPc,
				time.Now(),
				true,
			) // respond synchronously, but only to cached/synthesized queries
			continue
		}
		go func() {
			defer proxy.clientsCountDec()
			proxy.processIncomingQuery("udp", proxy.mainProto, packet, &clientAddr, clientPc, time.Now(), false)
		}()
	}
}

func (proxy *Proxy) tcpListener(acceptPc *net.TCPListener) {
	defer acceptPc.Close()
	for {
		clientPc, err := acceptPc.Accept()
		if err != nil {
			continue
		}
		if !proxy.clientsCountInc() {
			dlog.Warnf("Too many incoming connections (max=%d)", proxy.maxClients)
			clientPc.Close()
			continue
		}
		go func() {
			defer clientPc.Close()
			defer proxy.clientsCountDec()
			if err := clientPc.SetDeadline(time.Now().Add(proxy.timeout)); err != nil {
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

func (proxy *Proxy) udpListenerFromAddr(listenAddr *net.UDPAddr) error {
	listenConfig, err := proxy.udpListenerConfig()
	if err != nil {
		return err
	}
	listenAddrStr := listenAddr.String()
	network := "udp"
	isIPv4 := isDigit(listenAddrStr[0])
	if isIPv4 {
		network = "udp4"
	}
	clientPc, err := listenConfig.ListenPacket(context.Background(), network, listenAddrStr)
	if err != nil {
		return err
	}
	proxy.registerUDPListener(clientPc.(*net.UDPConn))
	dlog.Noticef("Now listening to %v [UDP]", listenAddr)
	return nil
}

func (proxy *Proxy) tcpListenerFromAddr(listenAddr *net.TCPAddr) error {
	listenConfig, err := proxy.tcpListenerConfig()
	if err != nil {
		return err
	}
	listenAddrStr := listenAddr.String()
	network := "tcp"
	isIPv4 := isDigit(listenAddrStr[0])
	if isIPv4 {
		network = "tcp4"
	}
	acceptPc, err := listenConfig.Listen(context.Background(), network, listenAddrStr)
	if err != nil {
		return err
	}
	proxy.registerTCPListener(acceptPc.(*net.TCPListener))
	dlog.Noticef("Now listening to %v [TCP]", listenAddr)
	return nil
}

func (proxy *Proxy) localDoHListenerFromAddr(listenAddr *net.TCPAddr) error {
	listenConfig, err := proxy.tcpListenerConfig()
	if err != nil {
		return err
	}
	listenAddrStr := listenAddr.String()
	network := "tcp"
	isIPv4 := isDigit(listenAddrStr[0])
	if isIPv4 {
		network = "tcp4"
	}
	acceptPc, err := listenConfig.Listen(context.Background(), network, listenAddrStr)
	if err != nil {
		return err
	}
	proxy.registerLocalDoHListener(acceptPc.(*net.TCPListener))
	dlog.Noticef("Now listening to https://%v%v [DoH]", listenAddr, proxy.localDoHPath)
	return nil
}

func (proxy *Proxy) startAcceptingClients() {
	for _, clientPc := range proxy.udpListeners {
		go proxy.udpListener(clientPc)
	}
	proxy.udpListeners = nil
	for _, acceptPc := range proxy.tcpListeners {
		go proxy.tcpListener(acceptPc)
	}
	proxy.tcpListeners = nil
	for _, acceptPc := range proxy.localDoHListeners {
		go proxy.localDoHListener(acceptPc)
	}
	proxy.localDoHListeners = nil
}

func (proxy *Proxy) prepareForRelay(ip net.IP, port int, encryptedQuery *[]byte) {
	anonymizedDNSHeader := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00}
	relayedQuery := append(anonymizedDNSHeader, ip.To16()...)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[0:2], uint16(port))
	relayedQuery = append(relayedQuery, tmp[:]...)
	relayedQuery = append(relayedQuery, *encryptedQuery...)
	*encryptedQuery = relayedQuery
}

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
	var err error
	var pc net.Conn
	proxyDialer := proxy.xTransport.proxyDialer
	if proxyDialer == nil {
		pc, err = net.DialTimeout("udp", upstreamAddr.String(), serverInfo.Timeout)
	} else {
		pc, err = (*proxyDialer).Dial("udp", upstreamAddr.String())
	}
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
	for tries := 2; tries > 0; tries-- {
		if _, err := pc.Write(encryptedQuery); err != nil {
			return nil, err
		}
		length, err := pc.Read(encryptedResponse)
		if err == nil {
			encryptedResponse = encryptedResponse[:length]
			break
		}
		dlog.Debugf("[%v] Retry on timeout", serverInfo.Name)
	}
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

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
	var err error
	var pc net.Conn
	proxyDialer := proxy.xTransport.proxyDialer
	if proxyDialer == nil {
		pc, err = net.DialTimeout("tcp", upstreamAddr.String(), serverInfo.Timeout)
	} else {
		pc, err = (*proxyDialer).Dial("tcp", upstreamAddr.String())
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

func (proxy *Proxy) clientsCountInc() bool {
	for {
		count := atomic.LoadUint32(&proxy.clientsCount)
		if count >= proxy.maxClients {
			return false
		}
		if atomic.CompareAndSwapUint32(&proxy.clientsCount, count, count+1) {
			dlog.Debugf("clients count: %d", count+1)
			return true
		}
	}
}

func (proxy *Proxy) clientsCountDec() {
	for {
		count := atomic.LoadUint32(&proxy.clientsCount)
		if count == 0 {
			// Already at zero, nothing to do
			break
		}
		if atomic.CompareAndSwapUint32(&proxy.clientsCount, count, count-1) {
			dlog.Debugf("clients count: %d", count-1)
			break
		}
		// CAS failed, retry with updated count
	}
}

func (proxy *Proxy) processIncomingQuery(
	clientProto string,
	serverProto string,
	query []byte,
	clientAddr *net.Addr,
	clientPc net.Conn,
	start time.Time,
	onlyCached bool,
) []byte {
	// Initialize metrics for this query
	clientAddrStr := "unknown"
	if clientAddr != nil {
		clientAddrStr = (*clientAddr).String()
	}
	dlog.Debugf("Processing incoming query from %s", clientAddrStr)

	// Validate the query
	var response []byte
	if !validateQuery(query) {
		return response
	}

	// Initialize plugin state
	pluginsState := NewPluginsState(proxy, clientProto, clientAddr, serverProto, start)

	var serverInfo *ServerInfo
	var serverName string = "-"

	// Apply query plugins with lazy server selection
	query, _ = pluginsState.ApplyQueryPlugins(
		&proxy.pluginsGlobals,
		query,
		func() (*ServerInfo, bool) {
			// Only get server info once when actually needed
			if serverInfo == nil {
				serverInfo = proxy.serversInfo.getOne()
				if serverInfo != nil {
					serverName = serverInfo.Name
				}
			}
			if serverInfo == nil {
				return nil, false
			}
			needsPadding := (serverInfo.Proto == stamps.StampProtoTypeDoH ||
				serverInfo.Proto == stamps.StampProtoTypeTLS)
			return serverInfo, needsPadding
		},
	)
	if !validateQuery(query) {
		return response
	}

	// Handle query plugin actions
	if pluginsState.action == PluginsActionDrop {
		pluginsState.returnCode = PluginsReturnCodeDrop
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		return response
	}

	// Handle synthesized responses from plugins
	var err error
	if pluginsState.synthResponse != nil {
		response, err = handleSynthesizedResponse(&pluginsState, pluginsState.synthResponse)
		if err != nil {
			return response
		}
	}

	// Return early if only cached results are requested
	if onlyCached {
		if len(response) == 0 {
			return response
		}
		serverInfo = nil
	}

	// Process query with a DNS server if there's no cached response
	// Note: if serverInfo is still nil here, we need to get it
	if len(response) == 0 {
		if serverInfo == nil {
			serverInfo = proxy.serversInfo.getOne()
			if serverInfo != nil {
				serverName = serverInfo.Name
			}
		}
		if serverInfo != nil {
			pluginsState.serverName = serverName

			exchangeResponse, err := handleDNSExchange(proxy, serverInfo, &pluginsState, query, serverProto)

			// Update server statistics for WP2 strategy
			success := (err == nil && exchangeResponse != nil)
			proxy.serversInfo.updateServerStats(serverName, success)

			if err != nil || exchangeResponse == nil {
				return response
			}

			response = exchangeResponse

			// Process the response through plugins
			processedResponse, err := processPlugins(proxy, &pluginsState, query, serverInfo, response)
			if err != nil {
				return response
			}

			response = processedResponse
		}
	}

	// Validate the response before sending
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

	// Send the response back to the client
	sendResponse(proxy, &pluginsState, response, clientProto, clientAddr, clientPc)

	// Apply logging plugins
	pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)

	// Update monitoring metrics
	updateMonitoringMetrics(proxy, &pluginsState)

	return response
}

func NewProxy() *Proxy {
	return &Proxy{
		serversInfo: NewServersInfo(),
	}
}
