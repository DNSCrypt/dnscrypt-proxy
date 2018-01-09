package main

import (
	"encoding/hex"
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ed25519"
)

type ServersInfo struct {
	sync.RWMutex
	inner []ServerInfo
}

func (serversInfo *ServersInfo) registerServer(proxy *Proxy, serverAddrStr string, serverPkStr string, providerName string) error {
	newServer, err := serversInfo.fetchServerInfo(proxy, serverAddrStr, serverPkStr, providerName)
	if err != nil {
		return err
	}
	serversInfo.Lock()
	serversInfo.inner = append(serversInfo.inner, newServer)
	serversInfo.Unlock()
	return nil
}

func (serversInfo *ServersInfo) getOne() *ServerInfo {
	serversInfo.RLock()
	serverInfo := &serversInfo.inner[0]
	serversInfo.RUnlock()
	return serverInfo
}

func (serversInfo *ServersInfo) fetchServerInfo(proxy *Proxy, serverAddrStr string, serverPkStr string, providerName string) (ServerInfo, error) {
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
		Timeout:            TimeoutMin,
		UDPAddr:            remoteUDPAddr,
		TCPAddr:            remoteTCPAddr,
	}
	return serverInfo, nil
}
