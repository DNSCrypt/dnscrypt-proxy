package main

import (
	"encoding/hex"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"
)

type ServerStamp struct {
	name          string
	serverAddrStr string
	serverPkStr   string
	providerName  string
}

func NewServerStampFromLegacy(name string, serverAddrStr string, serverPkStr string, providerName string) (ServerStamp, error) {
	return ServerStamp{
		name:          name,
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
	inner        []ServerInfo
	serverStamps []ServerStamp
}

func (serversInfo *ServersInfo) registerServer(proxy *Proxy, name string, serverAddrStr string, serverPkStr string, providerName string) error {
	newServer, err := serversInfo.fetchServerInfo(proxy, name, serverAddrStr, serverPkStr, providerName)
	if err != nil {
		return err
	}
	serversInfo.Lock()
	for i, oldServer := range serversInfo.inner {
		if oldServer.Name == newServer.Name {
			serversInfo.inner[i] = newServer
			serversInfo.Unlock()
			return nil
		}
	}
	serversInfo.inner = append(serversInfo.inner, newServer)
	serversInfo.Unlock()
	return nil
}

func (serversInfo *ServersInfo) getOne() *ServerInfo {
	serversInfo.RLock()
	serverInfo := &serversInfo.inner[rand.Intn(len(serversInfo.inner))]
	serversInfo.RUnlock()
	return serverInfo
}

func (serversInfo *ServersInfo) fetchServerInfo(proxy *Proxy, name string, serverAddrStr string, serverPkStr string, providerName string) (ServerInfo, error) {
	serverPublicKey, err := hex.DecodeString(strings.Replace(serverPkStr, ":", "", -1))
	if err != nil || len(serverPublicKey) != ed25519.PublicKeySize {
		log.Fatal("Invalid public key")
	}
	certInfo, err := FetchCurrentCert(proxy, serverPublicKey, serverAddrStr, providerName)
	if err != nil {
		return ServerInfo{}, err
	}
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		return ServerInfo{}, err
	}
	remoteTCPAddr, err := net.ResolveTCPAddr("tcp", serverAddrStr)
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
