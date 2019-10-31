package dnscrypt

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"io"
	"io/ioutil"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/jedisct1/dlog"
	clocksmith "github.com/jedisct1/go-clocksmith"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"golang.org/x/crypto/curve25519"
)

type Proxy struct {
	UserName                     string
	Child                        bool
	proxyPublicKey               [32]byte
	proxySecretKey               [32]byte
	EphemeralKeys                bool
	questionSizeEstimator        QuestionSizeEstimator
	ServersInfo                  ServersInfo
	Timeout                      time.Duration
	CertRefreshDelay             time.Duration
	CertRefreshDelayAfterFailure time.Duration
	CertIgnoreTimestamp          bool
	MainProto                    string
	ListenAddresses              []string
	Daemonize                    bool
	RegisteredServers            []RegisteredServer
	RegisteredRelays             []RegisteredServer
	PluginBlockIPv6              bool
	Cache                        bool
	CacheSize                    int
	CacheNegMinTTL               uint32
	CacheNegMaxTTL               uint32
	CacheMinTTL                  uint32
	CacheMaxTTL                  uint32
	RejectTTL                    uint32
	CloakTTL                     uint32
	QueryLogFile                 string
	QueryLogFormat               string
	QueryLogIgnoredQtypes        []string
	NXLogFile                    string
	NXLogFormat                  string
	BlockNameFile                string
	WhitelistNameFile            string
	BlockNameLogFile             string
	WhitelistNameLogFile         string
	BlockNameFormat              string
	WhitelistNameFormat          string
	BlockIPFile                  string
	BlockIPLogFile               string
	BlockIPFormat                string
	ForwardFile                  string
	CloakFile                    string
	pluginsGlobals               PluginsGlobals
	URLsToPrefetch               []*URLToPrefetch
	clientsCount                 uint32
	MaxClients                   uint32
	XTransport                   *XTransport
	AllWeeklyRanges              *map[string]WeeklyRanges
	LogMaxSize                   int
	LogMaxAge                    int
	LogMaxBackups                int
	BlockedQueryResponse         string
	QueryMeta                    []string
	Routes                       *map[string][]string
	ShowCerts                    bool
}

func (proxy *Proxy) StartProxy(quit <-chan struct{}) {
	proxy.questionSizeEstimator = NewQuestionSizeEstimator()
	if _, err := crypto_rand.Read(proxy.proxySecretKey[:]); err != nil {
		dlog.Fatal(err)
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)
	for _, registeredServer := range proxy.RegisteredServers {
		proxy.ServersInfo.registerServer(registeredServer.Name, registeredServer.Stamp)
	}

	for _, listenAddrStr := range proxy.ListenAddresses {
		listenUDPAddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
		if err != nil {
			dlog.Fatal(err)
		}
		listenTCPAddr, err := net.ResolveTCPAddr("tcp", listenAddrStr)
		if err != nil {
			dlog.Fatal(err)
		}

		// if 'userName' is not set, continue as before
		if !(len(proxy.UserName) > 0) {
			udpCloser, err := proxy.udpListenerFromAddr(listenUDPAddr)
			if err != nil {
				dlog.Fatal(err)
			}
			tcpCloser, err := proxy.tcpListenerFromAddr(listenTCPAddr)
			if err != nil {
				dlog.Fatal(err)
			}
			defer udpCloser.Close()
			defer tcpCloser.Close()
		} else {
			// if 'userName' is set and we are the parent process
			if !proxy.Child {
				// parent
				listenerUDP, err := net.ListenUDP("udp", listenUDPAddr)
				if err != nil {
					dlog.Fatal(err)
				}
				listenerTCP, err := net.ListenTCP("tcp", listenTCPAddr)
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
				FileDescriptors = append(FileDescriptors, fdUDP)
				FileDescriptors = append(FileDescriptors, fdTCP)

				// if 'userName' is set and we are the child process
			} else {
				// child
				listenerUDP, err := net.FilePacketConn(os.NewFile(uintptr(3+FileDescriptorNum), "listenerUDP"))
				if err != nil {
					dlog.Fatalf("Unable to switch to a different user: %v", err)
				}
				FileDescriptorNum++

				listenerTCP, err := net.FileListener(os.NewFile(uintptr(3+FileDescriptorNum), "listenerTCP"))
				if err != nil {
					dlog.Fatalf("Unable to switch to a different user: %v", err)
				}
				FileDescriptorNum++

				dlog.Noticef("Now listening to %v [UDP]", listenUDPAddr)
				go proxy.udpListener(listenerUDP.(*net.UDPConn))

				dlog.Noticef("Now listening to %v [TCP]", listenAddrStr)
				go proxy.tcpListener(listenerTCP.(*net.TCPListener))
			}
		}
	}

	// if 'userName' is set and we are the parent process drop privilege and exit
	if len(proxy.UserName) > 0 && !proxy.Child {
		proxy.dropPrivilege(proxy.UserName, FileDescriptors)
	}
	sdc, err := proxy.SystemDListeners()
	if err != nil {
		dlog.Fatal(err)
	}
	defer sdc.Close()
	liveServers, err := proxy.ServersInfo.refresh(proxy)
	if liveServers > 0 {
		proxy.CertIgnoreTimestamp = false
	}
	if proxy.ShowCerts {
		os.Exit(0)
	}
	if liveServers > 0 {
		dlog.Noticef("dnscrypt-proxy is ready - live servers: %d", liveServers)
		if !proxy.Child {
			if err := ServiceManagerReadyNotify(); err != nil {
				dlog.Fatal(err)
			}
		}
	} else if err != nil {
		dlog.Error(err)
		dlog.Notice("dnscrypt-proxy is waiting for at least one server to be reachable")
	}
	go proxy.prefetcher()
	if len(proxy.ServersInfo.registeredServers) > 0 {
		go func() {
			for {
				delay := proxy.CertRefreshDelay
				if liveServers == 0 {
					delay = proxy.CertRefreshDelayAfterFailure
				}
				clocksmith.Sleep(delay)
				liveServers, _ = proxy.ServersInfo.refresh(proxy)
				if liveServers > 0 {
					proxy.CertIgnoreTimestamp = false
				}
			}
		}()
	}
	<-quit
}

func (proxy *Proxy) prefetcher() {
	for {
		now := time.Now()
		for _, urlToPrefetch := range proxy.URLsToPrefetch {
			if now.After(urlToPrefetch.when) {
				dlog.Debugf("Prefetching [%s]", urlToPrefetch.url)
				if err := PrefetchSourceURL(proxy.XTransport, urlToPrefetch); err != nil {
					dlog.Debugf("Prefetching [%s] failed: %s", urlToPrefetch.url, err)
				} else {
					dlog.Debugf("Prefetching [%s] succeeded. Next refresh scheduled for %v", urlToPrefetch.url, urlToPrefetch.when)
				}
			}
		}
		clocksmith.Sleep(60 * time.Second)
	}
}

func (proxy *Proxy) udpListener(clientPc *net.UDPConn) {
	for {
		buffer := make([]byte, MaxDNSPacketSize-1)
		length, clientAddr, err := clientPc.ReadFrom(buffer)
		if err != nil {
			return
		}
		packet := buffer[:length]
		go func() {
			start := time.Now()
			if !proxy.clientsCountInc() {
				dlog.Warnf("Too many connections (max=%d)", proxy.MaxClients)
				return
			}
			defer proxy.clientsCountDec()
			proxy.processIncomingQuery(proxy.ServersInfo.getOne(), "udp", proxy.MainProto, packet, &clientAddr, clientPc, start)
		}()
	}
}

func (proxy *Proxy) udpListenerFromAddr(listenAddr *net.UDPAddr) (io.Closer, error) {
	clientPc, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	dlog.Noticef("Now listening to %v [UDP]", listenAddr)
	go proxy.udpListener(clientPc)
	return clientPc, nil
}

func (proxy *Proxy) tcpListener(acceptPc *net.TCPListener) {
	for {
		clientPc, err := acceptPc.Accept()
		if err != nil {
			continue
		}
		go func() {
			start := time.Now()
			defer clientPc.Close()
			if !proxy.clientsCountInc() {
				dlog.Warnf("Too many connections (max=%d)", proxy.MaxClients)
				return
			}
			defer proxy.clientsCountDec()
			clientPc.SetDeadline(time.Now().Add(proxy.Timeout))
			packet, err := ReadPrefixed(&clientPc)
			if err != nil {
				return
			}
			clientAddr := clientPc.RemoteAddr()
			proxy.processIncomingQuery(proxy.ServersInfo.getOne(), "tcp", "tcp", packet, &clientAddr, clientPc, start)
		}()
	}
}

func (proxy *Proxy) tcpListenerFromAddr(listenAddr *net.TCPAddr) (io.Closer, error) {
	acceptPc, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	dlog.Noticef("Now listening to %v [TCP]", listenAddr)
	go proxy.tcpListener(acceptPc)
	return acceptPc, nil
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

func (proxy *Proxy) exchangeWithUDPServer(serverInfo *ServerInfo, sharedKey *[32]byte, encryptedQuery []byte, clientNonce []byte) ([]byte, error) {
	upstreamAddr := serverInfo.UDPAddr
	if serverInfo.RelayUDPAddr != nil {
		upstreamAddr = serverInfo.RelayUDPAddr
	}
	pc, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(serverInfo.Timeout))
	if serverInfo.RelayUDPAddr != nil {
		proxy.prepareForRelay(serverInfo.UDPAddr.IP, serverInfo.UDPAddr.Port, &encryptedQuery)
	}
	pc.Write(encryptedQuery)
	encryptedResponse := make([]byte, MaxDNSPacketSize)
	length, err := pc.Read(encryptedResponse)
	if err != nil {
		return nil, err
	}
	encryptedResponse = encryptedResponse[:length]
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

func (proxy *Proxy) exchangeWithTCPServer(serverInfo *ServerInfo, sharedKey *[32]byte, encryptedQuery []byte, clientNonce []byte) ([]byte, error) {
	upstreamAddr := serverInfo.TCPAddr
	if serverInfo.RelayUDPAddr != nil {
		upstreamAddr = serverInfo.RelayTCPAddr
	}
	var err error
	var pc net.Conn
	proxyDialer := proxy.XTransport.ProxyDialer
	if proxyDialer == nil {
		pc, err = net.DialTCP("tcp", nil, upstreamAddr)
	} else {
		pc, err = (*proxyDialer).Dial("tcp", serverInfo.TCPAddr.String())
	}
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(serverInfo.Timeout))
	if serverInfo.RelayTCPAddr != nil {
		proxy.prepareForRelay(serverInfo.TCPAddr.IP, serverInfo.TCPAddr.Port, &encryptedQuery)
	}
	encryptedQuery, err = PrefixWithSize(encryptedQuery)
	if err != nil {
		return nil, err
	}
	pc.Write(encryptedQuery)
	encryptedResponse, err := ReadPrefixed(&pc)
	if err != nil {
		return nil, err
	}
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

func (proxy *Proxy) clientsCountInc() bool {
	for {
		count := atomic.LoadUint32(&proxy.clientsCount)
		if count >= proxy.MaxClients {
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
		if count := atomic.LoadUint32(&proxy.clientsCount); count == 0 || atomic.CompareAndSwapUint32(&proxy.clientsCount, count, count-1) {
			break
		}
	}
}

func (proxy *Proxy) processIncomingQuery(serverInfo *ServerInfo, clientProto string, serverProto string, query []byte, clientAddr *net.Addr, clientPc net.Conn, start time.Time) {
	if len(query) < MinDNSPacketSize {
		return
	}
	pluginsState := NewPluginsState(proxy, clientProto, clientAddr, start)
	defer pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
	serverName := "-"
	if serverInfo != nil {
		serverName = serverInfo.Name
	}
	query, _ = pluginsState.ApplyQueryPlugins(&proxy.pluginsGlobals, query, serverName)
	if len(query) < MinDNSPacketSize || len(query) > MaxDNSPacketSize {
		return
	}
	var response []byte
	var err error
	if pluginsState.action != PluginsActionForward {
		if pluginsState.synthResponse != nil {
			response, err = pluginsState.synthResponse.PackBuffer(response)
			if err != nil {
				pluginsState.returnCode = PluginsReturnCodeParseError
				return
			}
		}
		if pluginsState.action == PluginsActionDrop {
			pluginsState.returnCode = PluginsReturnCodeDrop
			return
		}
	} else {
		pluginsState.returnCode = PluginsReturnCodeForward
	}
	if len(response) == 0 && serverInfo != nil {
		var ttl *uint32
		if serverInfo.Proto == stamps.StampProtoTypeDNSCrypt {
			sharedKey, encryptedQuery, clientNonce, err := proxy.Encrypt(serverInfo, query, serverProto)
			if err != nil {
				pluginsState.returnCode = PluginsReturnCodeParseError
				return
			}
			serverInfo.noticeBegin(proxy)
			if serverProto == "udp" {
				response, err = proxy.exchangeWithUDPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
				if err == nil && len(response) >= MinDNSPacketSize && response[2]&0x02 == 0x02 {
					serverProto = "tcp"
					sharedKey, encryptedQuery, clientNonce, err = proxy.Encrypt(serverInfo, query, serverProto)
					if err != nil {
						pluginsState.returnCode = PluginsReturnCodeParseError
						return
					}
					response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
				}
			} else {
				response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
			}
			if err != nil {
				if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
					pluginsState.returnCode = PluginsReturnCodeServerTimeout
				} else {
					pluginsState.returnCode = PluginsReturnCodeServerError
				}
				serverInfo.noticeFailure(proxy)
				return
			}
		} else if serverInfo.Proto == stamps.StampProtoTypeDoH {
			tid := TransactionID(query)
			SetTransactionID(query, 0)
			serverInfo.noticeBegin(proxy)
			resp, _, err := proxy.XTransport.DoHQuery(serverInfo.useGet, serverInfo.URL, query, proxy.Timeout)
			SetTransactionID(query, tid)
			if err != nil {
				pluginsState.returnCode = PluginsReturnCodeServerError
				serverInfo.noticeFailure(proxy)
				return
			}
			response, err = ioutil.ReadAll(io.LimitReader(resp.Body, int64(MaxDNSPacketSize)))
			if err != nil {
				pluginsState.returnCode = PluginsReturnCodeServerError
				serverInfo.noticeFailure(proxy)
				return
			}
			if len(response) >= MinDNSPacketSize {
				SetTransactionID(response, tid)
			}
		} else {
			dlog.Fatal("Unsupported protocol")
		}
		if len(response) < MinDNSPacketSize || len(response) > MaxDNSPacketSize {
			pluginsState.returnCode = PluginsReturnCodeParseError
			serverInfo.noticeFailure(proxy)
			return
		}
		response, err = pluginsState.ApplyResponsePlugins(&proxy.pluginsGlobals, response, ttl)
		if err != nil {
			pluginsState.returnCode = PluginsReturnCodeParseError
			serverInfo.noticeFailure(proxy)
			return
		}
		if rcode := Rcode(response); rcode == dns.RcodeServerFailure { // SERVFAIL
			dlog.Infof("Server [%v] returned temporary error code [%v] -- Upstream server may be experiencing connectivity issues", serverInfo.Name, rcode)
			serverInfo.noticeFailure(proxy)
		} else {
			serverInfo.noticeSuccess(proxy)
		}
	}
	if len(response) < MinDNSPacketSize || len(response) > MaxDNSPacketSize {
		pluginsState.returnCode = PluginsReturnCodeParseError
		if serverInfo != nil {
			serverInfo.noticeFailure(proxy)
		}
		return
	}
	if clientProto == "udp" {
		if len(response) > pluginsState.maxUnencryptedUDPSafePayloadSize {
			response, err = TruncatedResponse(response)
			if err != nil {
				pluginsState.returnCode = PluginsReturnCodeParseError
				return
			}
		}
		clientPc.(net.PacketConn).WriteTo(response, *clientAddr)
		if HasTCFlag(response) {
			proxy.questionSizeEstimator.blindAdjust()
		} else {
			proxy.questionSizeEstimator.adjust(ResponseOverhead + len(response))
		}
	} else {
		response, err = PrefixWithSize(response)
		if err != nil {
			pluginsState.returnCode = PluginsReturnCodeParseError
			if serverInfo != nil {
				serverInfo.noticeFailure(proxy)
			}
			return
		}
		clientPc.Write(response)
	}
}

func NewProxy() *Proxy {
	return &Proxy{
		ServersInfo: NewServersInfo(),
	}
}
