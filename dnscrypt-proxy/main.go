package main

import (
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/jedisct1/dlog"
	"golang.org/x/crypto/curve25519"
)

type Proxy struct {
	proxyPublicKey        [32]byte
	proxySecretKey        [32]byte
	questionSizeEstimator QuestionSizeEstimator
	serversInfo           ServersInfo
	timeout               time.Duration
	certRefreshDelay      time.Duration
	mainProto             string
	listenAddresses       []string
	daemonize             bool
	registeredServers     []RegisteredServer
	pluginBlockIPv6       bool
	cache                 bool
	cacheSize             int
	cacheNegTTL           uint32
	cacheMinTTL           uint32
	cacheMaxTTL           uint32
	queryLogFile          string
	queryLogFormat        string
	pluginsGlobals        PluginsGlobals
}

func main() {
	dlog.Init("dnscrypt-proxy", dlog.SeverityNotice)
	cdLocal()
	proxy := Proxy{}
	if err := ConfigLoad(&proxy, "dnscrypt-proxy.toml"); err != nil {
		dlog.Fatal(err)
	}
	if err := InitPluginsGlobals(&proxy.pluginsGlobals, &proxy); err != nil {
		dlog.Fatal(err)
	}
	if proxy.daemonize {
		Daemonize()
	}
	proxy.StartProxy()
}

func cdLocal() {
	ex, err := os.Executable()
	if err != nil {
		dlog.Critical(err)
		return
	}
	exPath := filepath.Dir(ex)
	os.Chdir(exPath)
}

func (proxy *Proxy) StartProxy() {
	proxy.questionSizeEstimator = NewQuestionSizeEstimator()
	if _, err := rand.Read(proxy.proxySecretKey[:]); err != nil {
		dlog.Fatal(err)
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)
	for _, registeredServer := range proxy.registeredServers {
		proxy.serversInfo.registerServer(proxy, registeredServer.name, registeredServer.stamp)
	}
	for _, listenAddrStr := range proxy.listenAddresses {
		listenUDPAddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
		if err != nil {
			dlog.Fatal(err)
		}
		listenTCPAddr, err := net.ResolveTCPAddr("tcp", listenAddrStr)
		if err != nil {
			dlog.Fatal(err)
		}
		if err := proxy.udpListener(listenUDPAddr); err != nil {
			dlog.Fatal(err)
		}
		if err := proxy.tcpListener(listenTCPAddr); err != nil {
			dlog.Fatal(err)
		}
	}
	dlog.Notice("dnscrypt-proxy is ready")
	for {
		time.Sleep(proxy.certRefreshDelay)
		proxy.serversInfo.refresh(proxy)
	}
}

func (proxy *Proxy) udpListener(listenAddr *net.UDPAddr) error {
	clientPc, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return err
	}
	go func() {
		defer clientPc.Close()
		dlog.Noticef("Now listening to %v [UDP]", listenAddr)
		for {
			buffer := make([]byte, MaxDNSPacketSize-1)
			length, clientAddr, err := clientPc.ReadFrom(buffer)
			if err != nil {
				return
			}
			packet := buffer[:length]
			go func() {
				proxy.processIncomingQuery(proxy.serversInfo.getOne(), "udp", proxy.mainProto, packet, &clientAddr, clientPc)
			}()
		}
	}()
	return nil
}

func (proxy *Proxy) tcpListener(listenAddr *net.TCPAddr) error {
	acceptPc, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return err
	}
	go func() {
		defer acceptPc.Close()
		dlog.Noticef("Now listening to %v [TCP]", listenAddr)
		for {
			clientPc, err := acceptPc.Accept()
			if err != nil {
				continue
			}
			go func() {
				defer clientPc.Close()
				clientPc.SetDeadline(time.Now().Add(proxy.timeout))
				packet, err := ReadPrefixed(clientPc.(*net.TCPConn))
				if err != nil || len(packet) < MinDNSPacketSize {
					return
				}
				clientAddr := clientPc.RemoteAddr()
				proxy.processIncomingQuery(proxy.serversInfo.getOne(), "tcp", "tcp", packet, &clientAddr, clientPc)
			}()
		}
	}()
	return nil
}

func (proxy *Proxy) exchangeWithUDPServer(serverInfo *ServerInfo, encryptedQuery []byte, clientNonce []byte) ([]byte, error) {
	pc, err := net.DialUDP("udp", nil, serverInfo.UDPAddr)
	if err != nil {
		return nil, err
	}
	pc.SetDeadline(time.Now().Add(serverInfo.Timeout))
	pc.Write(encryptedQuery)
	encryptedResponse := make([]byte, MaxDNSPacketSize)
	length, err := pc.Read(encryptedResponse)
	pc.Close()
	if err != nil {
		return nil, err
	}
	encryptedResponse = encryptedResponse[:length]
	return proxy.Decrypt(serverInfo, encryptedResponse, clientNonce)
}

func (proxy *Proxy) exchangeWithTCPServer(serverInfo *ServerInfo, encryptedQuery []byte, clientNonce []byte) ([]byte, error) {
	pc, err := net.DialTCP("tcp", nil, serverInfo.TCPAddr)
	if err != nil {
		return nil, err
	}
	pc.SetDeadline(time.Now().Add(serverInfo.Timeout))
	encryptedQuery, err = PrefixWithSize(encryptedQuery)
	if err != nil {
		return nil, err
	}
	pc.Write(encryptedQuery)

	encryptedResponse, err := ReadPrefixed(pc)
	pc.Close()
	if err != nil {
		return nil, err
	}
	return proxy.Decrypt(serverInfo, encryptedResponse, clientNonce)
}

func (proxy *Proxy) processIncomingQuery(serverInfo *ServerInfo, clientProto string, serverProto string, query []byte, clientAddr *net.Addr, clientPc net.Conn) {
	if len(query) < MinDNSPacketSize || serverInfo == nil {
		return
	}
	pluginsState := NewPluginsState(proxy, clientProto, clientAddr)
	query, _ = pluginsState.ApplyQueryPlugins(&proxy.pluginsGlobals, query)
	var response []byte
	var err error
	if pluginsState.action != PluginsActionForward {
		if pluginsState.synthResponse != nil {
			response, err = pluginsState.synthResponse.PackBuffer(response)
			if err != nil {
				return
			}
		}
	}
	if len(response) == 0 {
		encryptedQuery, clientNonce, err := proxy.Encrypt(serverInfo, query, serverProto)
		if err != nil {
			return
		}
		serverInfo.noticeBegin(proxy)
		if serverProto == "udp" {
			response, err = proxy.exchangeWithUDPServer(serverInfo, encryptedQuery, clientNonce)
		} else {
			response, err = proxy.exchangeWithTCPServer(serverInfo, encryptedQuery, clientNonce)
		}
		if err != nil {
			serverInfo.noticeFailure(proxy)
			return
		}
		response, _ = pluginsState.ApplyResponsePlugins(&proxy.pluginsGlobals, response)
	}
	if clientProto == "udp" {
		if len(response) > MaxDNSUDPPacketSize {
			response, err = TruncatedResponse(response)
			if err != nil {
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
			serverInfo.noticeFailure(proxy)
			return
		}
		clientPc.Write(response)
	}
	serverInfo.noticeSuccess(proxy)
}
