package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"codeberg.org/miekg/dns"
)

type outboundSourceFamily uint8

const (
	outboundSourceIPv4 outboundSourceFamily = iota + 1
	outboundSourceIPv6
)

var ipv4LimitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

type outboundSourcePolicy struct {
	ipv4 netip.Addr
	ipv6 netip.Addr
}

// outboundTarget selects source binding for a destination; an invalid source leaves it unbound.
type outboundTarget struct {
	destination netip.Addr
	source      netip.Addr
	family      outboundSourceFamily
}

func parseOutboundSourcePolicy(ipv4Str, ipv6Str string) (outboundSourcePolicy, error) {
	var policy outboundSourcePolicy
	var err error
	if policy.ipv4, err = parseOutboundSource("outbound_source_ipv4", ipv4Str, outboundSourceIPv4); err != nil {
		return outboundSourcePolicy{}, err
	}
	if policy.ipv6, err = parseOutboundSource("outbound_source_ipv6", ipv6Str, outboundSourceIPv6); err != nil {
		return outboundSourcePolicy{}, err
	}
	return policy, nil
}

func parseOutboundSource(setting, value string, family outboundSourceFamily) (netip.Addr, error) {
	if value == "" {
		return netip.Addr{}, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid %s value %q: expected an IP address literal", setting, value)
	}
	if family == outboundSourceIPv4 {
		addr = addr.Unmap()
	}
	if addr.IsUnspecified() || addr.IsMulticast() || addr == ipv4LimitedBroadcast {
		return netip.Addr{}, fmt.Errorf(
			"invalid %s value %q: address cannot be unspecified, multicast, or limited broadcast",
			setting,
			value,
		)
	}
	if family == outboundSourceIPv4 && !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("invalid %s value %q: expected an IPv4 address", setting, value)
	}
	if family == outboundSourceIPv6 && (!addr.Is6() || addr.Is4In6()) {
		return netip.Addr{}, fmt.Errorf("invalid %s value %q: expected an IPv6 address", setting, value)
	}
	return addr, nil
}

func (policy *outboundSourcePolicy) enabled() bool {
	return policy != nil && (policy.ipv4.IsValid() || policy.ipv6.IsValid())
}

func (family outboundSourceFamily) setting() string {
	if family == outboundSourceIPv4 {
		return "outbound_source_ipv4"
	}
	return "outbound_source_ipv6"
}

func (target outboundTarget) bound() bool {
	return target.source.IsValid()
}

// networkFor restricts a network to the address family of the destination.
func (target outboundTarget) networkFor(proto string) string {
	if target.family == outboundSourceIPv4 {
		return proto + "4"
	}
	return proto + "6"
}

// dialError explains which setting selected the source address that failed.
func (target outboundTarget) dialError(proto string, remote fmt.Stringer, err error) error {
	return fmt.Errorf(
		"%s=%s: %s connection to %s failed: %w",
		target.family.setting(),
		target.source,
		target.networkFor(proto),
		remote,
		err,
	)
}

// sourceFor applies an enabled policy, leaving loopback and unspecified destinations unbound.
func (policy *outboundSourcePolicy) sourceFor(destination netip.Addr) (outboundTarget, error) {
	if !destination.IsValid() {
		return outboundTarget{}, fmt.Errorf("invalid outbound destination address")
	}
	target := outboundTarget{destination: destination.Unmap(), family: outboundSourceIPv6}
	if target.destination.Is4() {
		target.family = outboundSourceIPv4
	}
	if target.destination.IsLoopback() || target.destination.IsUnspecified() {
		return target, nil
	}
	source := policy.ipv6
	if target.family == outboundSourceIPv4 {
		source = policy.ipv4
	}
	if !source.IsValid() {
		return outboundTarget{}, fmt.Errorf(
			"%s is not configured for destination %s",
			target.family.setting(),
			target.destination,
		)
	}
	target.source = source
	return target, nil
}

func (policy *outboundSourcePolicy) dialTCPContext(
	ctx context.Context,
	destination netip.AddrPort,
	timeout, keepAlive time.Duration,
) (net.Conn, error) {
	if !destination.IsValid() {
		return nil, fmt.Errorf("invalid TCP destination")
	}
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	dialer := net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
	if !policy.enabled() {
		return dialer.DialContext(ctx, "tcp", destination.String())
	}
	target, err := policy.sourceFor(destination.Addr())
	if err != nil {
		return nil, err
	}
	remote := netip.AddrPortFrom(target.destination, destination.Port())
	network := target.networkFor("tcp")
	if target.bound() {
		dialer.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(target.source, 0))
	}
	conn, err := dialer.DialContext(ctx, network, remote.String())
	if err != nil && target.bound() {
		return nil, target.dialError("tcp", remote, err)
	}
	return conn, err
}

func (policy *outboundSourcePolicy) dialTCP(
	destination netip.AddrPort,
	timeout, keepAlive time.Duration,
) (net.Conn, error) {
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
	addrPort := destination.AddrPort()
	target, err := policy.sourceFor(addrPort.Addr())
	if err != nil {
		return nil, err
	}
	remote := netip.AddrPortFrom(target.destination, addrPort.Port())
	network := target.networkFor("udp")
	var local *net.UDPAddr
	if target.bound() {
		local = net.UDPAddrFromAddrPort(netip.AddrPortFrom(target.source, 0))
	}
	conn, err := net.DialUDP(network, local, net.UDPAddrFromAddrPort(remote))
	if err != nil && target.bound() {
		return nil, target.dialError("udp", remote, err)
	}
	return conn, err
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
	network := target.networkFor("udp")
	var local *net.UDPAddr
	if target.bound() {
		local = net.UDPAddrFromAddrPort(netip.AddrPortFrom(target.source, 0))
	}
	conn, err := net.ListenUDP(network, local)
	if err != nil && target.bound() {
		return nil, "", netip.Addr{}, fmt.Errorf(
			"%s=%s: unable to bind %s socket for destination %s: %w",
			target.family.setting(),
			target.source,
			network,
			target.destination,
			err,
		)
	}
	return conn, network, target.destination, err
}

// newDNSTransport isolates dialer changes from the shared DNS defaults.
func newDNSTransport() *dns.Transport {
	transport := dns.NewTransport()
	dialer := *transport.Dialer
	transport.Dialer = &dialer
	return transport
}

// configureDNSTransport applies source binding and returns the matching exchange destination and error context.
func (policy *outboundSourcePolicy) configureDNSTransport(
	transport *dns.Transport,
	proto, resolver string,
	covered bool,
) (string, string, *outboundTarget, error) {
	if transport == nil || transport.Dialer == nil {
		return "", "", nil, fmt.Errorf("DNS transport has no dialer")
	}
	if !covered || !policy.enabled() {
		return proto, resolver, nil, nil
	}
	endpoint, err := netip.ParseAddrPort(resolver)
	if err != nil {
		return "", "", nil, fmt.Errorf("DNS resolver %q is not an IP address literal: %w", resolver, err)
	}
	target, err := policy.sourceFor(endpoint.Addr())
	if err != nil {
		return "", "", nil, err
	}
	dialer := *transport.Dialer
	dialer.LocalAddr = nil
	if target.bound() {
		local := netip.AddrPortFrom(target.source, 0)
		if proto == "udp" {
			dialer.LocalAddr = net.UDPAddrFromAddrPort(local)
		} else {
			dialer.LocalAddr = net.TCPAddrFromAddrPort(local)
		}
	}
	transport.Dialer = &dialer
	remote := netip.AddrPortFrom(target.destination, endpoint.Port())
	return target.networkFor(proto), remote.String(), &target, nil
}

// wrapDialError adds the source address to an exchange error.
func (target *outboundTarget) wrapDialError(proto string, err error) error {
	if target == nil || err == nil || !target.bound() {
		return err
	}
	return target.dialError(proto, target.destination, err)
}
