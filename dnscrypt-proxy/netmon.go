package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jedisct1/dlog"
)

const (
	defaultNetworkMonitorInterval = 5 * time.Second
	maxNetworkMonitorBackoff      = 30 * time.Second
	offlineNetworkFingerprint     = "offline"
)

type networkInterfaceSnapshot struct {
	Name         string
	Index        int
	MTU          int
	Flags        net.Flags
	HardwareAddr net.HardwareAddr
	Addrs        []*net.IPNet
}

type networkMonitorProbeState struct {
	address string
	retryAt time.Time
	backoff time.Duration
}

type networkMonitor struct {
	epochValue     atomic.Uint64
	sampling       atomic.Bool
	initialized    bool
	lastInterfaces string
	lastRoutes     string
	probes         [2]networkMonitorProbeState
	now            func() time.Time
	interfaces     func() ([]networkInterfaceSnapshot, error)
	probe          func(string) (net.IP, error)
	onChange       func()
}

func newNetworkMonitor() *networkMonitor {
	return &networkMonitor{
		probes: [2]networkMonitorProbeState{
			{address: "192.0.2.1:9"},
			{address: "[2001:db8::1]:9"},
		},
		now:        time.Now,
		interfaces: snapshotNetworkInterfaces,
		probe:      probeNetworkMonitorLocalIP,
	}
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
	if !monitor.sampling.CompareAndSwap(false, true) {
		return
	}
	defer monitor.sampling.Store(false)
	if monitor.initialized {
		return
	}
	monitor.initialized = true
	monitor.sample(false)
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
	if monitor == nil {
		return
	}
	if !monitor.sampling.CompareAndSwap(false, true) {
		return
	}
	defer monitor.sampling.Store(false)
	if !monitor.initialized {
		monitor.initialized = true
		monitor.sample(false)
		return
	}
	monitor.sample(true)
}

func (monitor *networkMonitor) sample(notify bool) {
	interfaces, err := monitor.interfaces()
	interfacesChanged := false
	if err == nil {
		interfaceFingerprint := buildNetworkInterfaceFingerprint(interfaces)
		interfacesChanged = monitor.lastInterfaces != "" && monitor.lastInterfaces != interfaceFingerprint
		monitor.lastInterfaces = interfaceFingerprint
		if interfacesChanged {
			for i := range monitor.probes {
				monitor.probes[i].retryAt = time.Time{}
				monitor.probes[i].backoff = 0
			}
			if notify {
				monitor.notifyNetworkChange()
			}
		}
	}

	localIPs := monitor.discoverLocalIPs(monitor.now())
	routeFingerprint := buildNetworkFingerprint(localIPs)
	routesChanged := monitor.lastRoutes != "" && monitor.lastRoutes != routeFingerprint
	monitor.lastRoutes = routeFingerprint
	if notify && routesChanged && !interfacesChanged {
		monitor.notifyNetworkChange()
	}
}

func (monitor *networkMonitor) notifyNetworkChange() {
	monitor.epochValue.Add(1)
	dlog.Notice("Network change detected; rotating DNSCrypt client state")
	if monitor.onChange != nil {
		monitor.onChange()
	}
}

func (monitor *networkMonitor) discoverLocalIPs(now time.Time) []net.IP {
	localIPs := make([]net.IP, 0, len(monitor.probes))
	seen := make(map[string]struct{}, len(monitor.probes))
	for i := range monitor.probes {
		state := &monitor.probes[i]
		if !state.retryAt.IsZero() && now.Before(state.retryAt) {
			continue
		}
		ip, err := monitor.probe(state.address)
		if err != nil {
			if state.backoff == 0 {
				state.backoff = defaultNetworkMonitorInterval
			} else {
				state.backoff = min(state.backoff*2, maxNetworkMonitorBackoff)
			}
			state.retryAt = now.Add(state.backoff)
			continue
		}
		state.retryAt = time.Time{}
		state.backoff = 0
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		ip = append(net.IP(nil), ip...)
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		localIPs = append(localIPs, ip)
	}
	return localIPs
}

func probeNetworkMonitorLocalIP(address string) (net.IP, error) {
	conn, err := net.DialTimeout("udp", address, time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr.IP == nil || localAddr.IP.IsUnspecified() {
		return nil, net.InvalidAddrError("missing local IP")
	}
	return append(net.IP(nil), localAddr.IP...), nil
}

func snapshotNetworkInterfaces() ([]networkInterfaceSnapshot, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	snapshots := make([]networkInterfaceSnapshot, 0, len(interfaces))
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		snapshot := networkInterfaceSnapshot{
			Name:         iface.Name,
			Index:        iface.Index,
			MTU:          iface.MTU,
			Flags:        iface.Flags,
			HardwareAddr: append(net.HardwareAddr(nil), iface.HardwareAddr...),
		}
		for _, addr := range addrs {
			if ipNet := snapshotNetworkAddress(addr); ipNet != nil {
				snapshot.Addrs = append(snapshot.Addrs, ipNet)
			}
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func snapshotNetworkAddress(addr net.Addr) *net.IPNet {
	switch addr := addr.(type) {
	case nil:
		return nil
	case *net.IPNet:
		if addr == nil {
			return nil
		}
		return &net.IPNet{
			IP:   append(net.IP(nil), addr.IP...),
			Mask: append(net.IPMask(nil), addr.Mask...),
		}
	case *net.IPAddr:
		if addr == nil {
			return nil
		}
		ip := append(net.IP(nil), addr.IP...)
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	default:
		ip, ipNet, err := net.ParseCIDR(addr.String())
		if err != nil {
			return nil
		}
		ipNet.IP = ip
		return ipNet
	}
}

func buildNetworkInterfaceFingerprint(interfaces []networkInterfaceSnapshot) string {
	parts := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses := make([]string, 0, len(iface.Addrs))
		seenAddresses := make(map[string]struct{}, len(iface.Addrs))
		for _, addr := range iface.Addrs {
			if addr == nil || addr.IP == nil || !addr.IP.IsGlobalUnicast() {
				continue
			}
			ip := addr.IP
			if ip.To4() == nil {
				if prefix := ip.Mask(addr.Mask); prefix != nil {
					ip = prefix
				}
			}
			prefixLength, bits := addr.Mask.Size()
			mask := "/" + strconv.Itoa(prefixLength)
			if bits == 0 {
				mask = "/mask=" + hex.EncodeToString(addr.Mask)
			}
			address := ip.String() + mask
			if _, seen := seenAddresses[address]; seen {
				continue
			}
			seenAddresses[address] = struct{}{}
			addresses = append(addresses, address)
		}
		sort.Strings(addresses)
		part := "name=" + iface.Name +
			"|index=" + strconv.Itoa(iface.Index) +
			"|addrs=" + strings.Join(addresses, ",")
		parts = append(parts, part)
	}
	return hashNetworkFingerprint(parts)
}

func buildNetworkFingerprint(localIPs []net.IP) string {
	if len(localIPs) == 0 {
		return offlineNetworkFingerprint
	}
	parts := make([]string, 0, len(localIPs))
	for _, ip := range localIPs {
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		ip = append(net.IP(nil), ip...)
		parts = append(parts, "ip="+ip.String())
	}
	if len(parts) == 0 {
		return offlineNetworkFingerprint
	}
	return hashNetworkFingerprint(parts)
}

func hashNetworkFingerprint(parts []string) string {
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
