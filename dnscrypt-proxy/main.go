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
	mainProto             string
}

func main() {
	log.SetFlags(0)
	stamp, _ := NewServerStampFromLegacy("212.47.228.136:443", "E801:B84E:A606:BFB0:BAC0:CE43:445B:B15E:BA64:B02F:A3C4:AA31:AE10:636A:0790:324D", "2.dnscrypt-cert.fr.dnscrypt.org")
	NewProxy("127.0.0.1:5399", "dnscrypt.org-fr", stamp, "udp")
}

func NewProxy(listenAddrStr string, serverName string, stamp ServerStamp, mainProto string) {
	proxy := Proxy{questionSizeEstimator: NewQuestionSizeEstimator(), timeout: TimeoutMax, mainProto: mainProto}
	if _, err := rand.Read(proxy.proxySecretKey[:]); err != nil {
		log.Fatal(err)
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)
	proxy.serversInfo.registerServer(&proxy, serverName, stamp)
	listenUDPAddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
	if err != nil {
		log.Fatal(err)
	}
	listenTCPAddr, err := net.ResolveTCPAddr("tcp", listenAddrStr)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		proxy.udpListener(listenUDPAddr)
	}()
	go func() {
		proxy.tcpListener(listenTCPAddr)
	}()
	for {
		time.Sleep(CertRefreshDelay)
		proxy.serversInfo.refresh(&proxy)
	}
}

func (proxy *Proxy) udpListener(listenAddr *net.UDPAddr) error {
	clientPc, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return err
	}
	defer clientPc.Close()
	fmt.Printf("Now listening to %v [UDP]\n", listenAddr)
	for {
		buffer := make([]byte, MaxDNSPacketSize-1)
		length, clientAddr, err := clientPc.ReadFrom(buffer)
		if err != nil {
			return err
		}
		packet := buffer[:length]
		go func() {
			proxy.processIncomingQuery(proxy.serversInfo.getOne(), proxy.mainProto, packet, &clientAddr, clientPc)
		}()
	}
}

func (proxy *Proxy) tcpListener(listenAddr *net.TCPAddr) error {
	acceptPc, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return err
	}
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
		}
	} else {
		response, err = PrefixWithSize(response)
		if err != nil {
			return
		}
		clientPc.Write(response)
	}
}
