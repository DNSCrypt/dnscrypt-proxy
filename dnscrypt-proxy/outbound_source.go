package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"codeberg.org/miekg/dns"
)

type outboundSourcePolicy struct {
	ipv4 netip.Addr
	ipv6 netip.Addr
}

// outboundTarget selects source binding for a destination; an invalid source leaves it unbound.
type outboundTarget struct {
	destination netip.Addr
	source      netip.Addr
}

func parseOutboundSources(ipv4Str, ipv6Str string) (outboundSourcePolicy, error) {
	var policy outboundSourcePolicy
	for _, field := range []struct {
		family int
		value  string
		addr   *netip.Addr
	}{
		{4, ipv4Str, &policy.ipv4},
		{6, ipv6Str, &policy.ipv6},
	} {
		if field.value == "" {
			continue
		}
		addr, err := netip.ParseAddr(field.value)
		if err != nil {
			return outboundSourcePolicy{}, fmt.Errorf("invalid outbound_source_ipv%d value %q: expected an IP address literal", field.family, field.value)
		}
		if field.family == 4 {
			addr = addr.Unmap()
		}
		if addr.IsUnspecified() || addr.IsMulticast() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return outboundSourcePolicy{}, fmt.Errorf("invalid outbound_source_ipv%d value %q: address cannot be unspecified, multicast, or limited broadcast", field.family, field.value)
		}
		if addr.Is4In6() || addr.Is4() != (field.family == 4) {
			return outboundSourcePolicy{}, fmt.Errorf("invalid outbound_source_ipv%d value %q: expected an IPv%d address", field.family, field.value, field.family)
		}
		*field.addr = addr
	}
	return policy, nil
}

func (policy *outboundSourcePolicy) enabled() bool {
	return policy != nil && (policy.ipv4.IsValid() || policy.ipv6.IsValid())
}

func (target outboundTarget) family() string {
	if target.destination.Is4() {
		return "4"
	}
	return "6"
}

// sourceFor applies an enabled policy, leaving loopback and unspecified destinations unbound.
func (policy *outboundSourcePolicy) sourceFor(destination netip.Addr) (outboundTarget, error) {
	if !destination.IsValid() {
		return outboundTarget{}, fmt.Errorf("invalid outbound destination address")
	}
	target := outboundTarget{destination: destination.Unmap()}
	if target.destination.IsLoopback() || target.destination.IsUnspecified() {
		return target, nil
	}
	target.source = policy.ipv6
	if target.destination.Is4() {
		target.source = policy.ipv4
	}
	if !target.source.IsValid() {
		return outboundTarget{}, fmt.Errorf("outbound_source_ipv%s is not configured for destination %s", target.family(), target.destination)
	}
	return target, nil
}

func (target outboundTarget) udpAddr() *net.UDPAddr {
	if !target.source.IsValid() {
		return nil
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(target.source, 0))
}

// wrapDialError adds the source setting to errors from covered connections.
func (target *outboundTarget) wrapDialError(proto string, err error) error {
	if target == nil || err == nil || !target.source.IsValid() {
		return err
	}
	return fmt.Errorf("outbound_source_ipv%s=%s: %s connection to %s failed: %w", target.family(), target.source, proto+target.family(), target.destination, err)
}

// configureDialer applies source binding and normalizes the destination's address family.
func (policy *outboundSourcePolicy) configureDialer(dialer *net.Dialer, proto, address string) (string, string, *outboundTarget, error) {
	if !policy.enabled() {
		return proto, address, nil, nil
	}
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil {
		return "", "", nil, err
	}
	target, err := policy.sourceFor(endpoint.Addr())
	if err != nil {
		return "", "", nil, err
	}
	dialer.LocalAddr = nil
	if target.source.IsValid() {
		if proto == "udp" {
			dialer.LocalAddr = target.udpAddr()
		} else {
			dialer.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(target.source, 0))
		}
	}
	remote := netip.AddrPortFrom(target.destination, endpoint.Port())
	return proto + target.family(), remote.String(), &target, nil
}

func (policy *outboundSourcePolicy) dialTCPContext(ctx context.Context, destination netip.AddrPort, timeout, keepAlive time.Duration) (net.Conn, error) {
	if !destination.IsValid() {
		return nil, fmt.Errorf("invalid TCP destination")
	}
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	dialer := net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
	network, remote, target, err := policy.configureDialer(&dialer, "tcp", destination.String())
	if err != nil {
		return nil, err
	}
	conn, err := dialer.DialContext(ctx, network, remote)
	return conn, target.wrapDialError("tcp", err)
}

func (policy *outboundSourcePolicy) dialTCP(destination netip.AddrPort, timeout, keepAlive time.Duration) (net.Conn, error) {
	return policy.dialTCPContext(context.Background(), destination, timeout, keepAlive)
}

// dialUDP binds a connected UDP socket without waiting for the peer.
func (policy *outboundSourcePolicy) dialUDP(destination *net.UDPAddr) (*net.UDPConn, error) {
	if destination == nil {
		return nil, fmt.Errorf("nil UDP destination")
	}
	if !policy.enabled() {
		return net.DialUDP("udp", nil, destination)
	}
	target, err := policy.sourceFor(destination.AddrPort().Addr())
	if err != nil {
		return nil, err
	}
	remote := netip.AddrPortFrom(target.destination, destination.AddrPort().Port())
	conn, err := net.DialUDP("udp"+target.family(), target.udpAddr(), net.UDPAddrFromAddrPort(remote))
	return conn, target.wrapDialError("udp", err)
}

// listenUDP binds an unconnected socket and keeps its destination in the same address family.
func (policy *outboundSourcePolicy) listenUDP(destination netip.Addr) (*net.UDPConn, string, netip.Addr, error) {
	if !policy.enabled() {
		conn, err := net.ListenUDP("udp", nil)
		return conn, "udp", destination, err
	}
	target, err := policy.sourceFor(destination)
	if err != nil {
		return nil, "", netip.Addr{}, err
	}
	network := "udp" + target.family()
	conn, err := net.ListenUDP(network, target.udpAddr())
	return conn, network, target.destination, target.wrapDialError("udp", err)
}

// newDNSTransport isolates dialer changes from the shared DNS defaults.
func newDNSTransport() *dns.Transport {
	transport := dns.NewTransport()
	dialer := *transport.Dialer
	transport.Dialer = &dialer
	return transport
}
