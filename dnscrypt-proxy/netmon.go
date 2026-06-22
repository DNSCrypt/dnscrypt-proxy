package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedisct1/dlog"
)

const (
	defaultNetworkMonitorInterval = 5 * time.Second
	offlineNetworkFingerprint     = "offline"
)

type networkInterfaceSnapshot struct {
	Name         string
	Index        int
	HardwareAddr net.HardwareAddr
	Addrs        []*net.IPNet
}

type networkMonitor struct {
	epochValue  atomic.Uint64
	mu          sync.Mutex
	last        string
	fingerprint func() string
	onChange    func()
}

func newNetworkMonitor() *networkMonitor {
	return &networkMonitor{fingerprint: currentNetworkFingerprint}
}

func (monitor *networkMonitor) epoch() uint64 {
	if monitor == nil {
		return 0
	}
	return monitor.epochValue.Load()
}

func (monitor *networkMonitor) init() {
	if monitor == nil {
		return
	}
	fingerprint := monitor.currentFingerprint()
	monitor.mu.Lock()
	monitor.last = fingerprint
	monitor.mu.Unlock()
}

func (monitor *networkMonitor) start(ctx context.Context, interval time.Duration) {
	if monitor == nil {
		return
	}
	if interval <= 0 {
		interval = defaultNetworkMonitorInterval
	}
	monitor.init()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			monitor.check()
		}
	}
}

func (monitor *networkMonitor) check() {
	fingerprint := monitor.currentFingerprint()
	monitor.mu.Lock()
	if monitor.last == "" {
		monitor.last = fingerprint
		monitor.mu.Unlock()
		return
	}
	if monitor.last == fingerprint {
		monitor.mu.Unlock()
		return
	}
	monitor.last = fingerprint
	monitor.epochValue.Add(1)
	onChange := monitor.onChange
	monitor.mu.Unlock()

	dlog.Notice("Network change detected; rotating DNSCrypt client state")
	if onChange != nil {
		onChange()
	}
}

func (monitor *networkMonitor) currentFingerprint() string {
	if monitor.fingerprint == nil {
		return offlineNetworkFingerprint
	}
	return monitor.fingerprint()
}

func currentNetworkFingerprint() string {
	localIPs := discoverNetworkMonitorLocalIPs()
	if len(localIPs) == 0 {
		return offlineNetworkFingerprint
	}
	interfaces := snapshotNetworkInterfaces()
	return buildNetworkFingerprint(localIPs, interfaces)
}

func discoverNetworkMonitorLocalIPs() []net.IP {
	probeAddrs := []string{"192.0.2.1:9", "[2001:db8::1]:9"}
	localIPs := make([]net.IP, 0, len(probeAddrs))
	seen := make(map[string]struct{}, len(probeAddrs))
	for _, probeAddr := range probeAddrs {
		conn, err := net.DialTimeout("udp", probeAddr, time.Second)
		if err != nil {
			continue
		}
		localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
		conn.Close()
		if !ok || localAddr.IP == nil || localAddr.IP.IsUnspecified() {
			continue
		}
		ip := append(net.IP(nil), localAddr.IP...)
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		localIPs = append(localIPs, ip)
	}
	return localIPs
}

func snapshotNetworkInterfaces() []networkInterfaceSnapshot {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	snapshots := make([]networkInterfaceSnapshot, 0, len(interfaces))
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		snapshot := networkInterfaceSnapshot{
			Name:         iface.Name,
			Index:        iface.Index,
			HardwareAddr: append(net.HardwareAddr(nil), iface.HardwareAddr...),
		}
		for _, addr := range addrs {
			ip, ipNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			ipNet.IP = ip
			snapshot.Addrs = append(snapshot.Addrs, ipNet)
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}

func buildNetworkFingerprint(localIPs []net.IP, interfaces []networkInterfaceSnapshot) string {
	if len(localIPs) == 0 {
		return offlineNetworkFingerprint
	}
	parts := make([]string, 0, len(localIPs))
	for _, ip := range localIPs {
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		ip = append(net.IP(nil), ip...)
		iface, ok := findNetworkInterfaceForIP(ip, interfaces)
		part := "ip=" + ip.String()
		if ok {
			part += "|name=" + iface.Name + "|index=" + strconv.Itoa(iface.Index)
			if len(iface.HardwareAddr) > 0 {
				part += "|mac=" + iface.HardwareAddr.String()
			}
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return offlineNetworkFingerprint
	}
	sort.Strings(parts)
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (proxy *Proxy) networkEpoch() uint64 {
	if proxy == nil || proxy.netMonitor == nil {
		return 0
	}
	return proxy.netMonitor.epoch()
}

func findNetworkInterfaceForIP(ip net.IP, interfaces []networkInterfaceSnapshot) (networkInterfaceSnapshot, bool) {
	matches := make([]networkInterfaceSnapshot, 0, 1)
	for _, iface := range interfaces {
		for _, addr := range iface.Addrs {
			if addr != nil && addr.Contains(ip) {
				matches = append(matches, iface)
				break
			}
		}
	}
	if len(matches) == 0 {
		return networkInterfaceSnapshot{}, false
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Name != matches[j].Name {
			return matches[i].Name < matches[j].Name
		}
		return matches[i].Index < matches[j].Index
	})
	return matches[0], true
}
