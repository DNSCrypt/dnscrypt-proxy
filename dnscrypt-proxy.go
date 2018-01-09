package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

type Proxy struct {
	proxyPublicKey  [32]byte
	proxySecretKey  [32]byte
	minQuestionSize int
	serversInfo     []ServerInfo
}

func main() {
	log.SetFlags(0)
	_ = NewProxy("127.0.0.1:5399", "212.47.228.136:443", "E801:B84E:A606:BFB0:BAC0:CE43:445B:B15E:BA64:B02F:A3C4:AA31:AE10:636A:0790:324D", "2.dnscrypt-cert.fr.dnscrypt.org")
}

func NewProxy(listenAddrStr string, serverAddrStr string, serverPkStr string, providerName string) Proxy {
	proxy := Proxy{minQuestionSize: InitialMinQuestionSize}
	if _, err := rand.Read(proxy.proxySecretKey[:]); err != nil {
		log.Fatal(err)
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)
	proxy.fetchServerInfo(serverAddrStr, serverPkStr, providerName)
	proxy.udpListener(listenAddrStr)
	return proxy
}

func (proxy *Proxy) adjustMinQuestionSize() {
	if MaxDNSPacketSize-proxy.minQuestionSize < proxy.minQuestionSize {
		proxy.minQuestionSize = MaxDNSPacketSize
	} else {
		proxy.minQuestionSize *= 2
	}
}

func (proxy *Proxy) udpListener(listenAddrStr string) error {
	clientPc, err := net.ListenPacket("udp", listenAddrStr)
	if err != nil {
		return err
	}
	defer clientPc.Close()
	fmt.Printf("Now listening to %v [UDP]\n", listenAddrStr)
	for {
		buffer := make([]byte, MaxDNSPacketSize)
		length, clientAddr, err := clientPc.ReadFrom(buffer)
		if err != nil {
			return err
		}
		packet := buffer[:length]
		go func() {
			proxy.processIncomingUDPQuery(&proxy.serversInfo[0], packet, clientAddr, clientPc)
		}()
	}
}

func (proxy *Proxy) processIncomingUDPQuery(serverInfo *ServerInfo, packet []byte, clientAddr net.Addr, clientPc net.PacketConn) {
	if len(packet) < MinDNSPacketSize {
		return
	}
	encrypted, clientNonce := proxy.Crypt(serverInfo, packet)
	pc, err := net.DialUDP("udp", nil, serverInfo.UDPAddr)
	if err != nil {
		return
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(serverInfo.Timeout))
	pc.Write(encrypted)

	encrypted = make([]byte, MaxDNSPacketSize)
	length, err := pc.Read(encrypted)
	if err != nil {
		return
	}
	encrypted = encrypted[:length]
	packet, err = proxy.Decrypt(serverInfo, encrypted, clientNonce)
	if err != nil {
		return
	}
	clientPc.WriteTo(packet, clientAddr)
	if HasTCFlag(packet) {
		proxy.adjustMinQuestionSize()
	}
}

func (proxy *Proxy) fetchServerInfo(serverAddrStr string, serverPkStr string, providerName string) {
	serverPublicKey, err := hex.DecodeString(strings.Replace(serverPkStr, ":", "", -1))
	if err != nil || len(serverPublicKey) != ed25519.PublicKeySize {
		log.Fatal("Invalid public key")
	}
	certInfo, err := FetchCurrentCert(proxy, serverPublicKey, serverAddrStr, providerName)
	if err != nil {
		log.Fatal(err)
	}
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		log.Fatal(err)
	}
	remoteTCPAddr, err := net.ResolveTCPAddr("tcp", serverAddrStr)
	if err != nil {
		log.Fatal(err)
	}
	serverInfo := ServerInfo{
		MagicQuery:         certInfo.MagicQuery,
		ServerPk:           certInfo.ServerPk,
		SharedKey:          certInfo.SharedKey,
		CryptoConstruction: certInfo.CryptoConstruction,
		Timeout:            TimeoutMin,
		UDPAddr:            remoteUDPAddr,
		TCPAddr:            remoteTCPAddr,
	}
	proxy.serversInfo = append(proxy.serversInfo, serverInfo)
}
