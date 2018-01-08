package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/jedisct1/xsecretbox"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

type Proxy struct {
	proxyPublicKey  [32]byte
	proxySecretKey  [32]byte
	minQuestionSize uint
	serversInfo     []ServerInfo
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

func NewProxy(listenAddrStr string, serverAddrStr string, serverPkStr string, providerName string) Proxy {
	proxy := Proxy{minQuestionSize: InitialMinQuestionSize}
	if _, err := rand.Read(proxy.proxySecretKey[:]); err != nil {
		log.Fatal(err)
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)
	proxy.fetchServerInfo(serverAddrStr, serverPkStr, providerName)
	clientPc, err := net.ListenPacket("udp", listenAddrStr)
	if err != nil {
		log.Fatal(err)
	}
	defer clientPc.Close()
	fmt.Printf("Now listening to %v [UDP]\n", listenAddrStr)
	for {
		buffer := make([]byte, MaxDNSPacketSize)
		length, clientAddr, err := clientPc.ReadFrom(buffer)
		if err != nil {
			break
		}
		packet := buffer[:length]
		go func() {
			proxy.processIncomingQuery(&proxy.serversInfo[0], packet, clientAddr, clientPc)
		}()
	}
	return proxy
}

type ServerInfo struct {
	MagicQuery         [8]byte
	ServerPk           [32]byte
	SharedKey          [32]byte
	CryptoConstruction CryptoConstruction
	Timeout            time.Duration
	UDPAddr            *net.UDPAddr
	TCPAddr            *net.TCPAddr
}

func (proxy *Proxy) processIncomingQuery(serverInfo *ServerInfo, packet []byte, clientAddr net.Addr, clientPc net.PacketConn) {
	packet = Pad(packet, proxy.minQuestionSize)
	nonce := make([]byte, xsecretbox.NonceSize)
	rand.Read(nonce[0 : xsecretbox.NonceSize/2])
	encrypted := serverInfo.MagicQuery[:]
	encrypted = append(encrypted, proxy.proxyPublicKey[:]...)
	encrypted = append(encrypted, nonce[:xsecretbox.NonceSize/2]...)
	encrypted = xsecretbox.Seal(encrypted, nonce, packet, serverInfo.SharedKey[:])
	pc, err := net.DialUDP("udp", nil, serverInfo.UDPAddr)
	defer pc.Close()
	if err != nil {
		return
	}
	pc.SetDeadline(time.Now().Add(serverInfo.Timeout))
	pc.Write(encrypted)
	buffer := make([]byte, MaxDNSPacketSize)
	length, err := pc.Read(buffer)
	if err != nil {
		return
	}
	buffer = buffer[:length]
	serverMagicLen := len(ServerMagic)
	responseHeaderLen := serverMagicLen + xsecretbox.NonceSize
	if len(buffer) < responseHeaderLen+xsecretbox.TagSize ||
		!bytes.Equal(buffer[:serverMagicLen], ServerMagic[:]) {
		return
	}
	serverNonce := buffer[serverMagicLen:responseHeaderLen]
	if !bytes.Equal(nonce[:xsecretbox.NonceSize/2], serverNonce[:xsecretbox.NonceSize/2]) {
		return
	}
	decrypted, err := xsecretbox.Open(nil, serverNonce, buffer[responseHeaderLen:], serverInfo.SharedKey[:])
	if err != nil {
		return
	}
	decrypted, err = Unpad(decrypted)
	if err != nil || uint(len(decrypted)) < MinDNSPacketSize {
		return
	}
	if HasTCFlag(decrypted) {
		if MaxDNSPacketSize-proxy.minQuestionSize < proxy.minQuestionSize {
			proxy.minQuestionSize = MaxDNSPacketSize
		} else {
			proxy.minQuestionSize *= 2
		}
	}
	clientPc.WriteTo(decrypted, clientAddr)
}

func main() {
	log.SetFlags(0)
	_ = NewProxy("127.0.0.1:5399", "212.47.228.136:443", "E801:B84E:A606:BFB0:BAC0:CE43:445B:B15E:BA64:B02F:A3C4:AA31:AE10:636A:0790:324D", "2.dnscrypt-cert.fr.dnscrypt.org")
}
