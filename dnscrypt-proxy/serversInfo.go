package main

import (
	"encoding/hex"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/VividCortex/ewma"
	"github.com/jedisct1/dlog"
	"golang.org/x/crypto/ed25519"
)

const (
	RTTEwmaDecay = 10.0
	DefaultPort  = 443
)

type ServerInformalProperties uint64

const (
	ServerInformalPropertyDNSSEC = ServerInformalProperties(1) << 0
	ServerInformalPropertyNoLog  = ServerInformalProperties(1) << 1
)

type RegisteredServer struct {
	name  string
	stamp ServerStamp
}

type ServerInfo struct {
	sync.RWMutex
	MagicQuery         [8]byte
	ServerPk           [32]byte
	SharedKey          [32]byte
	CryptoConstruction CryptoConstruction
	Name               string
	Timeout            time.Duration
	UDPAddr            *net.UDPAddr
	TCPAddr            *net.TCPAddr
	lastActionTS       time.Time
	rtt                ewma.MovingAverage
	initialRtt         int
}

type ServersInfo struct {
	sync.RWMutex
	inner             []ServerInfo
	registeredServers []RegisteredServer
}

func (serversInfo *ServersInfo) registerServer(proxy *Proxy, name string, stamp ServerStamp) error {
	newRegisteredServer := RegisteredServer{name: name, stamp: stamp}
	serversInfo.Lock()
	defer serversInfo.Unlock()
	for i, oldRegisteredServer := range serversInfo.registeredServers {
		if oldRegisteredServer.name == name {
			serversInfo.registeredServers[i] = newRegisteredServer
			return nil
		}
	}
	serversInfo.registeredServers = append(serversInfo.registeredServers, newRegisteredServer)
	return nil
}

func (serversInfo *ServersInfo) refreshServer(proxy *Proxy, name string, stamp ServerStamp) error {
	serversInfo.Lock()
	defer serversInfo.Unlock()
	newServer, err := serversInfo.fetchServerInfo(proxy, name, stamp)
	if err != nil {
		return err
	}
	newServer.rtt = ewma.NewMovingAverage(RTTEwmaDecay)
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

func (serversInfo *ServersInfo) refresh(proxy *Proxy) (int, error) {
	dlog.Infof("Refreshing certificates")
	serversInfo.RLock()
	registeredServers := serversInfo.registeredServers
	serversInfo.RUnlock()
	liveServers := 0
	var err error
	for _, registeredServer := range registeredServers {
		if err = serversInfo.refreshServer(proxy, registeredServer.name, registeredServer.stamp); err == nil {
			liveServers++
		}
	}
	serversInfo.Lock()
	inner := serversInfo.inner
	innerLen := len(inner)
	for i := 0; i < innerLen; i++ {
		for j := i + 1; j < innerLen; j++ {
			if inner[j].initialRtt < inner[i].initialRtt {
				inner[j], inner[i] = inner[i], inner[j]
			}
		}
	}
	serversInfo.inner = inner
	if innerLen > 1 {
		dlog.Noticef("Server with the lowest initial latency: %s (rtt: %dms)", inner[0].Name, inner[0].initialRtt)
		proxy.certIgnoreTimestamp = false
	}
	serversInfo.Unlock()
	return liveServers, err
}

func (serversInfo *ServersInfo) liveServers() int {
	serversInfo.RLock()
	liveServers := len(serversInfo.inner)
	serversInfo.RUnlock()
	return liveServers
}

func (serversInfo *ServersInfo) getOne() *ServerInfo {
	serversInfo.Lock()
	defer serversInfo.Unlock()
	serversCount := len(serversInfo.inner)
	if serversCount <= 0 {
		return nil
	}
	candidate := rand.Intn(serversCount)
	if candidate == 0 {
		return &serversInfo.inner[candidate]
	}
	if serversInfo.inner[candidate].rtt.Value() < serversInfo.inner[0].rtt.Value() {
		serversInfo.inner[candidate], serversInfo.inner[0] = serversInfo.inner[0], serversInfo.inner[candidate]
	}
	candidate = rand.Intn(Max(Min(serversCount, 2), len(serversInfo.inner)))
	serverInfo := &serversInfo.inner[candidate]
	return serverInfo
}

func (serversInfo *ServersInfo) fetchServerInfo(proxy *Proxy, name string, stamp ServerStamp) (ServerInfo, error) {
	serverPk, err := hex.DecodeString(strings.Replace(stamp.serverPkStr, ":", "", -1))
	if err != nil || len(serverPk) != ed25519.PublicKeySize {
		dlog.Fatalf("Unsupported public key: [%v]", serverPk)
	}
	certInfo, rtt, err := FetchCurrentCert(proxy, &name, proxy.mainProto, serverPk, stamp.serverAddrStr, stamp.providerName)
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
		Timeout:            proxy.timeout,
		UDPAddr:            remoteUDPAddr,
		TCPAddr:            remoteTCPAddr,
		initialRtt:         rtt,
	}
	return serverInfo, nil
}

func (serverInfo *ServerInfo) noticeFailure(proxy *Proxy) {
	serverInfo.Lock()
	serverInfo.rtt.Set(float64(proxy.timeout.Nanoseconds()))
	serverInfo.Unlock()
}

func (serverInfo *ServerInfo) noticeBegin(proxy *Proxy) {
	serverInfo.Lock()
	serverInfo.lastActionTS = time.Now()
	serverInfo.Unlock()
}

func (serverInfo *ServerInfo) noticeSuccess(proxy *Proxy) {
	now := time.Now()
	serverInfo.Lock()
	elapsed := now.Sub(serverInfo.lastActionTS) / 1024
	if elapsed > 0 {
		serverInfo.rtt.Add(float64(elapsed))
	}
	serverInfo.Unlock()
}
