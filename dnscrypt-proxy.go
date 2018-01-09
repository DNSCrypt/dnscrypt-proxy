package main

import (
	"crypto/rand"
	"encoding/binary"
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
}

func main() {
	log.SetFlags(0)
	NewProxy("127.0.0.1:5399", "dnscrypt.org-fr", "212.47.228.136:443", "E801:B84E:A606:BFB0:BAC0:CE43:445B:B15E:BA64:B02F:A3C4:AA31:AE10:636A:0790:324D", "2.dnscrypt-cert.fr.dnscrypt.org")
}

func NewProxy(listenAddrStr string, serverName string, serverAddrStr string, serverPkStr string, providerName string) {
	proxy := Proxy{questionSizeEstimator: NewQuestionSizeEstimator(), timeout: TimeoutMax}
	if _, err := rand.Read(proxy.proxySecretKey[:]); err != nil {
		log.Fatal(err)
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)
	proxy.serversInfo.registerServer(&proxy, serverName, serverAddrStr, serverPkStr, providerName)
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
		time.Sleep(30 * time.Minute)
		// Refresh certificates
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
			proxy.processIncomingQuery(proxy.serversInfo.getOne(), packet, &clientAddr, clientPc)
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
			buffer := make([]byte, 2+MaxDNSPacketSize-1)
			length, err := clientPc.Read(buffer)
			if err != nil {
				return
			}
			innerLength := binary.BigEndian.Uint16(buffer[0:2])
			if int(innerLength) > length-2 {
				return
			}
			packet := buffer[2:length]
			proxy.processIncomingQuery(proxy.serversInfo.getOne(), packet, nil, clientPc)
		}()
	}
}

func (proxy *Proxy) processIncomingQuery(serverInfo *ServerInfo, packet []byte, clientAddr *net.Addr, clientPc net.Conn) {
	if len(packet) < MinDNSPacketSize {
		return
	}
	encrypted, clientNonce, err := proxy.Encrypt(serverInfo, packet, "udp")
	if err != nil {
		return
	}
	pc, err := net.DialUDP("udp", nil, serverInfo.UDPAddr)
	if err != nil {
		return
	}
	pc.SetDeadline(time.Now().Add(serverInfo.Timeout))
	pc.Write(encrypted)

	encrypted = make([]byte, MaxDNSPacketSize)
	length, err := pc.Read(encrypted)
	pc.Close()
	if err != nil {
		return
	}
	encrypted = encrypted[:length]
	packet, err = proxy.Decrypt(serverInfo, encrypted, clientNonce)
	if err != nil {
		return
	}
	if clientAddr != nil {
		clientPc.(net.PacketConn).WriteTo(packet, *clientAddr)
	} else {
		packet = append(append(packet, 0), 0)
		copy(packet[2:], packet[:len(packet)-2])
		binary.BigEndian.PutUint16(packet[0:2], uint16(len(packet)-2))
		clientPc.Write(packet)
	}
	if HasTCFlag(packet) {
		proxy.questionSizeEstimator.blindAdjust()
	}
}
