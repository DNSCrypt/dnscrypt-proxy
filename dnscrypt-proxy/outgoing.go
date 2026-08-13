package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedisct1/dlog"
)

type outgoingAddrs struct {
	v4 net.IP
	v6 net.IP
}

type outgoingSource struct {
	iface      string
	resolved   atomic.Pointer[outgoingAddrs]
	refreshing atomic.Bool
	refreshMu  sync.Mutex
	onRefresh  func()
}

func newOutgoingSource(spec string) (*outgoingSource, error) {
	if len(spec) == 0 {
		return nil, nil
	}
	source := &outgoingSource{}
	if ip := ParseIP(spec); ip != nil {
		addrs := &outgoingAddrs{}
		if ip4 := ip.To4(); ip4 != nil {
			addrs.v4 = ip4
		} else {
			addrs.v6 = ip
		}
		source.resolved.Store(addrs)
		return source, nil
	}
	source.iface = spec
	if err := source.refresh(); err != nil {
		return nil, err
	}
	return source, nil
}

func pickOutgoingAddrs(addrs []net.Addr) *outgoingAddrs {
	picked := &outgoingAddrs{}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil || !ipNet.IP.IsGlobalUnicast() {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			if picked.v4 == nil {
				picked.v4 = ip4
			}
		} else if picked.v6 == nil {
			picked.v6 = ipNet.IP
		}
	}
	return picked
}

func (source *outgoingSource) refresh() error {
	if source == nil || len(source.iface) == 0 {
		return nil
	}
	iface, err := net.InterfaceByName(source.iface)
	if err != nil {
		return fmt.Errorf("Unknown outgoing interface [%s]: %v", source.iface, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("Unable to read the addresses of outgoing interface [%s]: %v", source.iface, err)
	}
	picked := pickOutgoingAddrs(addrs)
	if picked.v4 == nil && picked.v6 == nil {
		return fmt.Errorf("Outgoing interface [%s] has no usable address", source.iface)
	}
	source.resolved.Store(picked)
	return nil
}

func (source *outgoingSource) localIP(dst net.IP) net.IP {
	if source == nil {
		return nil
	}
	resolved := source.resolved.Load()
	if resolved == nil {
		return nil
	}
	if dst == nil {
		if resolved.v4 != nil {
			return resolved.v4
		}
		return resolved.v6
	}
	if dst.To4() == nil {
		return resolved.v6
	}
	return resolved.v4
}

var errNoOutgoingAddr = errors.New("No outgoing source address for the destination address family")

func (source *outgoingSource) localIPFor(dst net.IP) (net.IP, error) {
	if source == nil {
		return nil, nil
	}
	if dst != nil && (dst.IsLoopback() || dst.IsUnspecified()) {
		// Loopback and unspecified destinations never leave the host, so
		// binding an interface source address to them accomplishes nothing
		// and would only break the proxy's own self-directed queries.
		return nil, nil
	}
	ip := source.localIP(dst)
	if ip == nil {
		return nil, errNoOutgoingAddr
	}
	return ip, nil
}

func (source *outgoingSource) udpLocalFor(dst net.IP) (*net.UDPAddr, error) {
	ip, err := source.localIPFor(dst)
	if ip == nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip}, nil
}

func (source *outgoingSource) applyToErr(dialer *net.Dialer, network string, dst net.IP) error {
	ip, err := source.localIPFor(dst)
	if err != nil {
		return err
	}
	if ip == nil {
		return nil
	}
	// LocalAddr's concrete type must match network, or DialContext rejects it.
	if strings.HasPrefix(network, "udp") {
		dialer.LocalAddr = &net.UDPAddr{IP: ip}
	} else {
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
	return nil
}

func isBindError(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	var syscallErr *os.SyscallError
	return errors.As(opErr.Err, &syscallErr) && syscallErr.Syscall == "bind"
}

func (source *outgoingSource) dialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	if err := source.applyToErr(dialer, network, hostIP(address)); err != nil {
		return nil, err
	}
	conn, err := dialer.DialContext(context.Background(), network, address)
	source.noteDialError(err)
	return conn, err
}

// refreshLocked serializes against a concurrent refresh so resolved.Store and
// onRefresh from two refresh sources can't interleave.
func (source *outgoingSource) refreshLocked() error {
	source.refreshMu.Lock()
	defer source.refreshMu.Unlock()
	if err := source.refresh(); err != nil {
		return err
	}
	if source.onRefresh != nil {
		source.onRefresh()
	}
	return nil
}

func (source *outgoingSource) noteDialError(err error) {
	if source == nil || len(source.iface) == 0 || err == nil || !isBindError(err) {
		return
	}
	if !source.refreshing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer source.refreshing.Store(false)
		if err := source.refreshLocked(); err != nil {
			dlog.Debugf("Unable to refresh outgoing interface [%s]: %v", source.iface, err)
		}
	}()
}

func hostIP(address string) net.IP {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil
	}
	return ParseIP(host)
}
