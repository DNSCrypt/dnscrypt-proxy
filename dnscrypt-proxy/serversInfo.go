package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/url"
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
	ServerInformalPropertyDNSSEC   = ServerInformalProperties(1) << 0
	ServerInformalPropertyNoLog    = ServerInformalProperties(1) << 1
	ServerInformalPropertyNoFilter = ServerInformalProperties(1) << 2
)

type RegisteredServer struct {
	name  string
	stamp ServerStamp
}

type ServerInfo struct {
	sync.RWMutex
	Proto              StampProtoType
	MagicQuery         [8]byte
	ServerPk           [32]byte
	SharedKey          [32]byte
	CryptoConstruction CryptoConstruction
	Name               string
	Timeout            time.Duration
	URL                *url.URL
	HostName           string
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
	if stamp.proto == StampProtoTypeDNSCrypt {
		return serversInfo.fetchDNSCryptServerInfo(proxy, name, stamp)
	} else if stamp.proto == StampProtoTypeDoH {
		return serversInfo.fetchDoHServerInfo(proxy, name, stamp)
	}
	return ServerInfo{}, errors.New("Unsupported protocol")
}

func (serversInfo *ServersInfo) fetchDNSCryptServerInfo(proxy *Proxy, name string, stamp ServerStamp) (ServerInfo, error) {
	if len(stamp.serverPk) != ed25519.PublicKeySize {
		serverPk, err := hex.DecodeString(strings.Replace(string(stamp.serverPk), ":", "", -1))
		if err != nil || len(serverPk) != ed25519.PublicKeySize {
			dlog.Fatalf("Unsupported public key for [%s]: [%s]", name, stamp.serverPk)
		}
		dlog.Warnf("Public key [%s] shouldn't be hex-encoded any more", string(stamp.serverPk))
		stamp.serverPk = serverPk
	}
	certInfo, rtt, err := FetchCurrentDNSCryptCert(proxy, &name, proxy.mainProto, stamp.serverPk, stamp.serverAddrStr, stamp.providerName)
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
		Proto:              StampProtoTypeDNSCrypt,
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

func (serversInfo *ServersInfo) fetchDoHServerInfo(proxy *Proxy, name string, stamp ServerStamp) (ServerInfo, error) {
	if len(stamp.serverAddrStr) > 0 {
		addrStr := stamp.serverAddrStr
		ipOnly := addrStr[:strings.LastIndex(addrStr, ":")]
		proxy.xTransport.cachedIPs.Lock()
		proxy.xTransport.cachedIPs.cache[stamp.providerName] = ipOnly
		proxy.xTransport.cachedIPs.Unlock()
	}
	url := &url.URL{
		Scheme: "https",
		Host:   stamp.providerName,
		Path:   stamp.path,
	}
	body := []byte{
		0xca, 0xfe, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
	}
	_, _, err := proxy.xTransport.Post(url, "application/dns-udpwireformat", "application/dns-udpwireformat", body, proxy.timeout)
	if err != nil {
		return ServerInfo{}, err
	}
	resp, rtt, err := proxy.xTransport.Post(url, "application/dns-udpwireformat", "application/dns-udpwireformat", body, proxy.timeout)
	if err != nil {
		return ServerInfo{}, err
	}
	tls := resp.TLS
	if tls == nil || !tls.HandshakeComplete {
		return ServerInfo{}, errors.New("TLS handshake failed")
	}
	if len(stamp.hash) > 0 && len(stamp.hash) != 32 {
		dlog.Criticalf("Unsupported certificate hash for [%s]: [%x]", name, stamp.hash)
	}
	found := false
	var wantedHash [32]byte
	copy(wantedHash[:], stamp.hash)
	for _, cert := range tls.PeerCertificates {
		h := sha256.Sum256(cert.RawTBSCertificate)
		dlog.Debugf("Advertised cert: [%s] [%x]", cert.Subject, h)
		if len(stamp.hash) == 32 && h == wantedHash {
			found = true
			break
		}
	}
	if len(stamp.hash) == 32 && !found {
		return ServerInfo{}, fmt.Errorf("Certificate hash [%x] not found for [%s]", wantedHash, name)
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ServerInfo{}, err
	}
	if len(respBody) < MinDNSPacketSize || len(respBody) > MaxDNSPacketSize ||
		respBody[0] != 0xca || respBody[1] != 0xfe || respBody[4] != 0x00 || respBody[5] != 0x01 {
		return ServerInfo{}, errors.New("Webserver returned an unexpected response")
	}
	dlog.Noticef("[%s] OK (DoH) - rtt: %dms", name, rtt.Nanoseconds()/1000000)

	serverInfo := ServerInfo{
		Proto:      StampProtoTypeDoH,
		Name:       name,
		Timeout:    proxy.timeout,
		URL:        url,
		HostName:   stamp.providerName,
		initialRtt: int(rtt.Nanoseconds() / 1000000),
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
