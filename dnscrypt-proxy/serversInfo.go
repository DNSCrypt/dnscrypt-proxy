package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/VividCortex/ewma"
	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	"golang.org/x/crypto/ed25519"
)

const (
	RTTEwmaDecay = 10.0
)

type RegisteredServer struct {
	name        string
	stamp       stamps.ServerStamp
	description string
}

type ServerInfo struct {
	sync.RWMutex
	Proto              stamps.StampProtoType
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
	useGet             bool
}

type LBStrategy int

const (
	LBStrategyNone = LBStrategy(iota)
	LBStrategyP2
	LBStrategyPH
	LBStrategyFirst
	LBStrategyRandom
)

const DefaultLBStrategy = LBStrategyP2

type ServersInfo struct {
	sync.RWMutex
	inner             []*ServerInfo
	registeredServers []RegisteredServer
	lbStrategy        LBStrategy
	lbEstimator       bool
}

func NewServersInfo() ServersInfo {
	return ServersInfo{lbStrategy: DefaultLBStrategy, lbEstimator: true, registeredServers: make([]RegisteredServer, 0)}
}

func (serversInfo *ServersInfo) registerServer(proxy *Proxy, name string, stamp stamps.ServerStamp) error {
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

func (serversInfo *ServersInfo) refreshServer(proxy *Proxy, name string, stamp stamps.ServerStamp) error {
	serversInfo.RLock()
	previousIndex := -1
	for i, oldServer := range serversInfo.inner {
		if oldServer.Name == name {
			previousIndex = i
			break
		}
	}
	serversInfo.RUnlock()
	newServer, err := serversInfo.fetchServerInfo(proxy, name, stamp, previousIndex < 0)
	if err != nil {
		return err
	}
	if name != newServer.Name {
		dlog.Fatalf("[%s] != [%s]", name, newServer.Name)
	}
	newServer.rtt = ewma.NewMovingAverage(RTTEwmaDecay)
	serversInfo.Lock()
	defer serversInfo.Unlock()
	previousIndex = -1
	for i, oldServer := range serversInfo.inner {
		if oldServer.Name == name {
			previousIndex = i
			break
		}
	}
	if previousIndex >= 0 {
		serversInfo.inner[previousIndex] = &newServer
		return nil
	}
	serversInfo.inner = append(serversInfo.inner, &newServer)
	serversInfo.registeredServers = append(serversInfo.registeredServers, RegisteredServer{name: name, stamp: stamp})
	return nil
}

func (serversInfo *ServersInfo) refresh(proxy *Proxy) (int, error) {
	dlog.Debug("Refreshing certificates")
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

	dlog.Notice("Sorted latencies:")
	for i := 0; i < innerLen; i++ {
		dlog.Noticef("- %5dms %s", inner[i].initialRtt, inner[i].Name)
	}

	if innerLen > 0 {
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

func (serversInfo *ServersInfo) estimatorUpdate(candidate int) {
	candidateRtt, currentBestRtt := serversInfo.inner[candidate].rtt.Value(), serversInfo.inner[0].rtt.Value()
	if currentBestRtt < 0 {
		currentBestRtt = candidateRtt
		serversInfo.inner[0].rtt.Set(currentBestRtt)
	}
	partialSort := false
	if candidateRtt < currentBestRtt {
		serversInfo.inner[candidate], serversInfo.inner[0] = serversInfo.inner[0], serversInfo.inner[candidate]
		partialSort = true
		dlog.Debugf("New preferred candidate: %v (rtt: %v vs previous: %v)", serversInfo.inner[0].Name, candidateRtt, currentBestRtt)
	} else if candidateRtt > 0 && candidateRtt >= currentBestRtt*4.0 {
		if time.Since(serversInfo.inner[candidate].lastActionTS) > time.Duration(1*time.Minute) {
			serversInfo.inner[candidate].rtt.Add(MinF(MaxF(candidateRtt/2.0, currentBestRtt*2.0), candidateRtt))
			dlog.Debugf("Giving a new chance to candidate [%s], setting its RTT from %v to %v (best: %v)", serversInfo.inner[candidate].Name, candidateRtt, serversInfo.inner[candidate].rtt.Value(), currentBestRtt)
			partialSort = true
		}
	}
	if partialSort {
		serversCount := len(serversInfo.inner)
		for i := 1; i < serversCount; i++ {
			if serversInfo.inner[i-1].rtt.Value() > serversInfo.inner[i].rtt.Value() {
				serversInfo.inner[i-1], serversInfo.inner[i] = serversInfo.inner[i], serversInfo.inner[i-1]
			}
		}
	}
}

func (serversInfo *ServersInfo) getOne() *ServerInfo {
	serversInfo.Lock()
	defer serversInfo.Unlock()
	serversCount := len(serversInfo.inner)
	if serversCount <= 0 {
		return nil
	}
	if serversInfo.lbEstimator {
		candidate := rand.Intn(serversCount)
		if candidate == 0 {
			return serversInfo.inner[candidate]
		}
		serversInfo.estimatorUpdate(candidate)
	}
	var candidate int
	switch serversInfo.lbStrategy {
	case LBStrategyFirst:
		candidate = 0
	case LBStrategyPH:
		candidate = rand.Intn(Min(Min(serversCount, 2), serversCount/2))
	case LBStrategyRandom:
		candidate = rand.Intn(serversCount)
	default:
		candidate = rand.Intn(Min(serversCount, 2))
	}
	serverInfo := serversInfo.inner[candidate]
	dlog.Debugf("Using candidate %v: [%v]", candidate, (*serverInfo).Name)

	return serverInfo
}

func (serversInfo *ServersInfo) fetchServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	if stamp.Proto == stamps.StampProtoTypeDNSCrypt {
		return serversInfo.fetchDNSCryptServerInfo(proxy, name, stamp, isNew)
	} else if stamp.Proto == stamps.StampProtoTypeDoH {
		return serversInfo.fetchDoHServerInfo(proxy, name, stamp, isNew)
	}
	return ServerInfo{}, errors.New("Unsupported protocol")
}

func (serversInfo *ServersInfo) fetchDNSCryptServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	if len(stamp.ServerPk) != ed25519.PublicKeySize {
		serverPk, err := hex.DecodeString(strings.Replace(string(stamp.ServerPk), ":", "", -1))
		if err != nil || len(serverPk) != ed25519.PublicKeySize {
			dlog.Fatalf("Unsupported public key for [%s]: [%s]", name, stamp.ServerPk)
		}
		dlog.Warnf("Public key [%s] shouldn't be hex-encoded any more", string(stamp.ServerPk))
		stamp.ServerPk = serverPk
	}
	certInfo, rtt, err := FetchCurrentDNSCryptCert(proxy, &name, proxy.mainProto, stamp.ServerPk, stamp.ServerAddrStr, stamp.ProviderName, isNew)
	if err != nil {
		return ServerInfo{}, err
	}
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", stamp.ServerAddrStr)
	if err != nil {
		return ServerInfo{}, err
	}
	remoteTCPAddr, err := net.ResolveTCPAddr("tcp", stamp.ServerAddrStr)
	if err != nil {
		return ServerInfo{}, err
	}
	return ServerInfo{
		Proto:              stamps.StampProtoTypeDNSCrypt,
		MagicQuery:         certInfo.MagicQuery,
		ServerPk:           certInfo.ServerPk,
		SharedKey:          certInfo.SharedKey,
		CryptoConstruction: certInfo.CryptoConstruction,
		Name:               name,
		Timeout:            proxy.timeout,
		UDPAddr:            remoteUDPAddr,
		TCPAddr:            remoteTCPAddr,
		initialRtt:         rtt,
	}, nil
}

func (serversInfo *ServersInfo) fetchDoHServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	if len(stamp.ServerAddrStr) > 0 {
		addrStr := stamp.ServerAddrStr
		ipOnly := addrStr[:strings.LastIndex(addrStr, ":")]
		proxy.xTransport.cachedIPs.Lock()
		proxy.xTransport.cachedIPs.cache[stamp.ProviderName] = ipOnly
		proxy.xTransport.cachedIPs.Unlock()
	}
	url := &url.URL{
		Scheme: "https",
		Host:   stamp.ProviderName,
		Path:   stamp.Path,
	}
	body := []byte{
		0xca, 0xfe, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
	}
	useGet := false
	if _, _, err := proxy.xTransport.DoHQuery(useGet, url, body, proxy.timeout); err != nil {
		useGet = true
		if _, _, err := proxy.xTransport.DoHQuery(useGet, url, body, proxy.timeout); err != nil {
			return ServerInfo{}, err
		}
		dlog.Debugf("Server [%s] doesn't appear to support POST; falling back to GET requests", name)
	}
	resp, rtt, err := proxy.xTransport.DoHQuery(useGet, url, body, proxy.timeout)
	if err != nil {
		return ServerInfo{}, err
	}
	tls := resp.TLS
	if tls == nil || !tls.HandshakeComplete {
		return ServerInfo{}, errors.New("TLS handshake failed")
	}
	protocol := tls.NegotiatedProtocol
	if len(protocol) == 0 {
		protocol = "h1"
		dlog.Warnf("[%s] does not support HTTP/2", name)
	}
	dlog.Infof("[%s] TLS version: %x - Protocol: %v - Cipher suite: %v", name, tls.Version, protocol, tls.CipherSuite)
	showCerts := len(os.Getenv("SHOW_CERTS")) > 0
	found := false
	var wantedHash [32]byte
	for _, cert := range tls.PeerCertificates {
		h := sha256.Sum256(cert.RawTBSCertificate)
		if showCerts {
			dlog.Infof("Advertised cert: [%s] [%x]", cert.Subject, h)
		} else {
			dlog.Debugf("Advertised cert: [%s] [%x]", cert.Subject, h)
		}
		for _, hash := range stamp.Hashes {
			if len(hash) == len(wantedHash) {
				copy(wantedHash[:], hash)
				if h == wantedHash {
					found = true
					break
				}
			}
		}
		if found {
			break
		}
	}
	if !found && len(stamp.Hashes) > 0 {
		return ServerInfo{}, fmt.Errorf("Certificate hash [%x] not found for [%s]", wantedHash, name)
	}
	respBody, err := ioutil.ReadAll(io.LimitReader(resp.Body, MaxHTTPBodyLength))
	if err != nil {
		return ServerInfo{}, err
	}
	if len(respBody) < MinDNSPacketSize || len(respBody) > MaxDNSPacketSize ||
		respBody[0] != 0xca || respBody[1] != 0xfe || respBody[4] != 0x00 || respBody[5] != 0x01 {
		return ServerInfo{}, errors.New("Webserver returned an unexpected response")
	}
	if isNew {
		dlog.Noticef("[%s] OK (DoH) - rtt: %dms", name, rtt.Nanoseconds()/1000000)
	} else {
		dlog.Infof("[%s] OK (DoH) - rtt: %dms", name, rtt.Nanoseconds()/1000000)
	}
	return ServerInfo{
		Proto:      stamps.StampProtoTypeDoH,
		Name:       name,
		Timeout:    proxy.timeout,
		URL:        url,
		HostName:   stamp.ProviderName,
		initialRtt: int(rtt.Nanoseconds() / 1000000),
		useGet:     useGet,
	}, nil
}

func (serverInfo *ServerInfo) noticeFailure(proxy *Proxy) {
	serverInfo.Lock()
	serverInfo.rtt.Add(float64(proxy.timeout.Nanoseconds() / 1000000))
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
	elapsed := now.Sub(serverInfo.lastActionTS)
	elapsedMs := elapsed.Nanoseconds() / 1000000
	if elapsedMs > 0 && elapsed < proxy.timeout {
		serverInfo.rtt.Add(float64(elapsedMs))
	}
	serverInfo.Unlock()
}
