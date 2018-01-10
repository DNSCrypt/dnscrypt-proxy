package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"time"

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
}

func main() {
	log.SetFlags(0)
	proxy := Proxy{}
	if err := ConfigLoad(&proxy, "dnscrypt-proxy.toml"); err != nil {
		panic(err)
	}
	proxy.StartProxy()
}

func (proxy *Proxy) StartProxy() {
	proxy.questionSizeEstimator = NewQuestionSizeEstimator()
	if _, err := rand.Read(proxy.proxySecretKey[:]); err != nil {
		log.Fatal(err)
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)
	for _, registeredServer := range proxy.registeredServers {
		proxy.serversInfo.registerServer(proxy, registeredServer.name, registeredServer.stamp)
	}
	for _, listenAddrStr := range proxy.listenAddresses {
		listenUDPAddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
		if err != nil {
			log.Fatal(err)
		}
		listenTCPAddr, err := net.ResolveTCPAddr("tcp", listenAddrStr)
		if err != nil {
			log.Fatal(err)
		}
		if err := proxy.udpListener(listenUDPAddr); err != nil {
			log.Fatal(err)
		}
		if err := proxy.tcpListener(listenTCPAddr); err != nil {
			log.Fatal(err)
		}
	}
	for {
		time.Sleep(CertRefreshDelay)
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
		fmt.Printf("Now listening to %v [UDP]\n", listenAddr)
		for {
			buffer := make([]byte, MaxDNSPacketSize-1)
			length, clientAddr, err := clientPc.ReadFrom(buffer)
			if err != nil {
				return
			}
			packet := buffer[:length]
			go func() {
				proxy.processIncomingQuery(proxy.serversInfo.getOne(), proxy.mainProto, packet, &clientAddr, clientPc)
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
		fmt.Printf("Now listening to %v [TCP]\n", listenAddr)
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
				proxy.processIncomingQuery(proxy.serversInfo.getOne(), "tcp", packet, nil, clientPc)
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

func (proxy *Proxy) processIncomingQuery(serverInfo *ServerInfo, serverProto string, query []byte, clientAddr *net.Addr, clientPc net.Conn) {
	if len(query) < MinDNSPacketSize {
		return
	}
	pluginsState := NewPluginsState()
	query, _ = pluginsState.ApplyQueryPlugins(query)
	encryptedQuery, clientNonce, err := proxy.Encrypt(serverInfo, query, serverProto)
	if err != nil {
		return
	}
	var response []byte
	if serverProto == "udp" {
		response, err = proxy.exchangeWithUDPServer(serverInfo, encryptedQuery, clientNonce)
	} else {
		response, err = proxy.exchangeWithTCPServer(serverInfo, encryptedQuery, clientNonce)
	}
	if err != nil {
		return
	}
	if clientAddr != nil {
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
			proxy.questionSizeEstimator.adjust(len(response))
		}
	} else {
		response, err = PrefixWithSize(response)
		if err != nil {
			return
		}
		clientPc.Write(response)
	}
}
