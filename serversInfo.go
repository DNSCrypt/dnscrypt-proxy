package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"
)

type ServerStamp struct {
	serverAddrStr string
	serverPkStr   string
	providerName  string
}

type RegisteredServer struct {
	name  string
	stamp ServerStamp
}

func NewServerStampFromLegacy(serverAddrStr string, serverPkStr string, providerName string) (ServerStamp, error) {
	return ServerStamp{
		serverAddrStr: serverAddrStr,
		serverPkStr:   serverPkStr,
		providerName:  providerName,
	}, nil
}

type ServerInfo struct {
	MagicQuery         [8]byte
	ServerPk           [32]byte
	SharedKey          [32]byte
	CryptoConstruction CryptoConstruction
	Name               string
	Timeout            time.Duration
	UDPAddr            *net.UDPAddr
	TCPAddr            *net.TCPAddr
}

type ServersInfo struct {
	sync.RWMutex
	inner             []ServerInfo
	registeredServers []RegisteredServer
}

func (serversInfo *ServersInfo) registerServer(proxy *Proxy, name string, stamp ServerStamp) error {
	serversInfo.Lock()
	defer serversInfo.Unlock()
	newServer, err := serversInfo.fetchServerInfo(proxy, name, stamp)
	if err != nil {
		return err
	}
	for i, oldServer := range serversInfo.inner {
		if oldServer.Name == newServer.Name {
			serversInfo.inner[i] = newServer
			return nil
		}
	}
	serversInfo.inner = append(serversInfo.inner, newServer)
	serversInfo.registeredServers = append(serversInfo.registeredServers, RegisteredServer{name: name, stamp: stamp})
	return nil
}

func (serversInfo *ServersInfo) refresh(proxy *Proxy) {
	fmt.Println("Refreshing certificates")
	serversInfo.RLock()
	registeredServers := serversInfo.registeredServers
	serversInfo.RUnlock()
	for _, registeredServer := range registeredServers {
		serversInfo.registerServer(proxy, registeredServer.name, registeredServer.stamp)
	}
}

func (serversInfo *ServersInfo) getOne() *ServerInfo {
	serversInfo.RLock()
	serverInfo := &serversInfo.inner[rand.Intn(len(serversInfo.inner))]
	serversInfo.RUnlock()
	return serverInfo
}

func (serversInfo *ServersInfo) fetchServerInfo(proxy *Proxy, name string, stamp ServerStamp) (ServerInfo, error) {
	serverPk, err := hex.DecodeString(strings.Replace(stamp.serverPkStr, ":", "", -1))
	if err != nil || len(serverPk) != ed25519.PublicKeySize {
		log.Fatal("Invalid public key")
	}
	certInfo, err := FetchCurrentCert(proxy, serverPk, stamp.serverAddrStr, stamp.providerName)
	if err != nil {
		return ServerInfo{}, err
	}
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", stamp.serverAddrStr)
	if err != nil {
		return ServerInfo{}, err
	}
	remoteTCPAddr, err := net.ResolveTCPAddr("tcp", stamp.serverAddrStr)
	if err != nil {
		return ServerInfo{}, err
	}
	serverInfo := ServerInfo{
		MagicQuery:         certInfo.MagicQuery,
		ServerPk:           certInfo.ServerPk,
		SharedKey:          certInfo.SharedKey,
		CryptoConstruction: certInfo.CryptoConstruction,
		Name:               name,
		Timeout:            TimeoutMin,
		UDPAddr:            remoteUDPAddr,
		TCPAddr:            remoteTCPAddr,
	}
	return serverInfo, nil
}
