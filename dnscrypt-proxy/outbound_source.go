package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
)

type outboundSourceFamily uint8

const (
	outboundSourceIPv4 outboundSourceFamily = iota + 1
	outboundSourceIPv6
)

type outboundSourcePolicy struct {
	ipv4 netip.Addr
	ipv6 netip.Addr
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
	if addr.IsUnspecified() || addr.IsMulticast() || addr == netip.IPv4Unspecified() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, fmt.Errorf("invalid %s value %q: address cannot be unspecified, multicast, or limited broadcast", setting, value)
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

func (family outboundSourceFamily) network(proto string) (string, error) {
	switch proto {
	case "tcp", "udp":
	default:
		return "", fmt.Errorf("unsupported outbound network %q", proto)
	}
	switch family {
	case outboundSourceIPv4:
		return proto + "4", nil
	case outboundSourceIPv6:
		return proto + "6", nil
	default:
		return "", fmt.Errorf("unknown outbound address family")
	}
}

func (family outboundSourceFamily) setting() string {
	if family == outboundSourceIPv4 {
		return "outbound_source_ipv4"
	}
	return "outbound_source_ipv6"
}

func (policy *outboundSourcePolicy) sourceFor(destination netip.Addr) (normalized, source netip.Addr, family outboundSourceFamily, bind bool, err error) {
	if !destination.IsValid() {
		return netip.Addr{}, netip.Addr{}, 0, false, fmt.Errorf("invalid outbound destination address")
	}
	normalized = destination.Unmap()
	if normalized.Is4() {
		family = outboundSourceIPv4
	} else if normalized.Is6() {
		family = outboundSourceIPv6
	} else {
		return netip.Addr{}, netip.Addr{}, 0, false, fmt.Errorf("unknown outbound destination family for %s", destination)
	}
	if normalized.IsLoopback() || normalized.IsUnspecified() {
		return normalized, netip.Addr{}, family, false, nil
	}
	if !policy.enabled() {
		return normalized, netip.Addr{}, family, false, nil
	}
	if family == outboundSourceIPv4 {
		source = policy.ipv4
	} else {
		source = policy.ipv6
	}
	if !source.IsValid() {
		return netip.Addr{}, netip.Addr{}, 0, false, fmt.Errorf("%s is not configured for destination %s", family.setting(), normalized)
	}
	return normalized, source, family, true, nil
}

func netIPToAddr(ip net.IP, zone string) (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q", ip)
	}
	if zone != "" {
		addr = addr.WithZone(zone)
	}
	return addr, nil
}

func tcpAddrPort(addr *net.TCPAddr) (netip.AddrPort, error) {
	if addr == nil {
		return netip.AddrPort{}, fmt.Errorf("nil TCP destination")
	}
	if addr.Port < 0 || addr.Port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("invalid TCP destination port %d", addr.Port)
	}
	ip, err := netIPToAddr(addr.IP, addr.Zone)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, uint16(addr.Port)), nil
}

func udpAddrPort(addr *net.UDPAddr) (netip.AddrPort, error) {
	if addr == nil {
		return netip.AddrPort{}, fmt.Errorf("nil UDP destination")
	}
	if addr.Port < 0 || addr.Port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("invalid UDP destination port %d", addr.Port)
	}
	ip, err := netIPToAddr(addr.IP, addr.Zone)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, uint16(addr.Port)), nil
}

func (policy *outboundSourcePolicy) tcpDialer(destination netip.Addr, timeout, keepAlive time.Duration) (*net.Dialer, string, netip.Addr, error) {
	if !policy.enabled() {
		return &net.Dialer{Timeout: timeout, KeepAlive: keepAlive}, "tcp", destination, nil
	}
	normalized, source, family, bind, err := policy.sourceFor(destination)
	if err != nil {
		return nil, "", netip.Addr{}, err
	}
	network := "tcp"
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
	if policy.enabled() {
		if network, err = family.network("tcp"); err != nil {
			return nil, "", netip.Addr{}, err
		}
		if bind {
			dialer.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(source, 0))
		}
	}
	return dialer, network, normalized, nil
}

func (policy *outboundSourcePolicy) dialTCPContext(ctx context.Context, destination *net.TCPAddr, timeout, keepAlive time.Duration) (net.Conn, error) {
	if !policy.enabled() {
		dialer := net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
		return dialer.DialContext(ctx, "tcp", destination.String())
	}
	addrPort, err := tcpAddrPort(destination)
	if err != nil {
		return nil, err
	}
	dialer, network, normalized, err := policy.tcpDialer(addrPort.Addr(), timeout, keepAlive)
	if err != nil {
		return nil, err
	}
	normalizedDestination := net.TCPAddrFromAddrPort(netip.AddrPortFrom(normalized, addrPort.Port()))
	conn, err := dialer.DialContext(ctx, network, normalizedDestination.String())
	if err != nil && policy.enabled() && dialer.LocalAddr != nil {
		return nil, fmt.Errorf("%s=%s: unable to bind %s connection to %s: %w", familySetting(normalized), dialer.LocalAddr, network, normalizedDestination, err)
	}
	return conn, err
}

func (policy *outboundSourcePolicy) dialTCP(destination *net.TCPAddr, timeout, keepAlive time.Duration) (net.Conn, error) {
	return policy.dialTCPContext(context.Background(), destination, timeout, keepAlive)
}

func (policy *outboundSourcePolicy) dialUDP(ctx context.Context, destination *net.UDPAddr, timeout time.Duration) (*net.UDPConn, error) {
	addrPort, err := udpAddrPort(destination)
	if err != nil {
		return nil, err
	}
	if !policy.enabled() {
		dialer := net.Dialer{Timeout: timeout}
		return dialer.DialUDP(ctx, "udp", netip.AddrPort{}, addrPort)
	}
	normalized, source, family, bind, err := policy.sourceFor(addrPort.Addr())
	if err != nil {
		return nil, err
	}
	network := "udp"
	local := netip.AddrPort{}
	if policy.enabled() {
		if network, err = family.network("udp"); err != nil {
			return nil, err
		}
		if bind {
			local = netip.AddrPortFrom(source, 0)
		}
	}
	remote := netip.AddrPortFrom(normalized, addrPort.Port())
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialUDP(ctx, network, local, remote)
	if err != nil && bind {
		return nil, fmt.Errorf("%s=%s: unable to bind %s connection to %s: %w", family.setting(), source, network, remote, err)
	}
	return conn, err
}

func (policy *outboundSourcePolicy) listenUDP(destination netip.Addr) (*net.UDPConn, string, netip.Addr, error) {
	if !policy.enabled() {
		conn, err := net.ListenUDP("udp", nil)
		return conn, "udp", destination, err
	}
	normalized, source, family, bind, err := policy.sourceFor(destination)
	if err != nil {
		return nil, "", netip.Addr{}, err
	}
	network := "udp"
	local := netip.AddrPort{}
	if policy.enabled() {
		if network, err = family.network("udp"); err != nil {
			return nil, "", netip.Addr{}, err
		}
		if bind {
			local = netip.AddrPortFrom(source, 0)
		}
	}
	conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(local))
	if err != nil && bind {
		return nil, "", netip.Addr{}, fmt.Errorf("%s=%s: unable to bind %s socket for destination %s: %w", family.setting(), source, network, normalized, err)
	}
	return conn, network, normalized, err
}

func familySetting(addr netip.Addr) string {
	if addr.Is4() {
		return outboundSourceIPv4.setting()
	}
	return outboundSourceIPv6.setting()
}

func newDNSTransport() *dns.Transport {
	transport := dns.NewTransport()
	transport.Dialer = newDNSDialer(5*time.Second, 3*time.Second, nil, nil)
	return transport
}

func newDNSDialer(timeout, keepAlive time.Duration, resolver *net.Resolver, local net.Addr) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: keepAlive, Resolver: resolver, LocalAddr: local}
}

func (policy *outboundSourcePolicy) configureDNSTransport(transport *dns.Transport, proto, resolver string, covered bool) (string, string, error) {
	if transport == nil || transport.Dialer == nil {
		return "", "", fmt.Errorf("DNS transport has no dialer")
	}
	if !covered || !policy.enabled() {
		return proto, resolver, nil
	}
	host, port, err := net.SplitHostPort(resolver)
	if err != nil {
		return "", "", err
	}
	destination, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return "", "", fmt.Errorf("DNS resolver %q is not an IP address literal: %w", resolver, err)
	}
	normalized, source, family, bind, err := policy.sourceFor(destination)
	if err != nil {
		return "", "", err
	}
	network, err := family.network(proto)
	if err != nil {
		return "", "", err
	}
	var local net.Addr
	if bind {
		if proto == "udp" {
			local = net.UDPAddrFromAddrPort(netip.AddrPortFrom(source, 0))
		} else {
			local = net.TCPAddrFromAddrPort(netip.AddrPortFrom(source, 0))
		}
	}
	transport.Dialer = newDNSDialer(transport.Dialer.Timeout, transport.Dialer.KeepAlive, transport.Dialer.Resolver, local)
	return network, net.JoinHostPort(normalized.String(), port), nil
}

func (policy *outboundSourcePolicy) wrapDNSError(err error, proto, resolver string, covered bool) error {
	if err == nil || !covered || !policy.enabled() {
		return err
	}
	host, _, splitErr := net.SplitHostPort(resolver)
	if splitErr != nil {
		return err
	}
	destination, parseErr := netip.ParseAddr(strings.Trim(host, "[]"))
	if parseErr != nil {
		return err
	}
	normalized, source, family, bind, sourceErr := policy.sourceFor(destination)
	if sourceErr != nil || !bind {
		return err
	}
	network, networkErr := family.network(proto)
	if networkErr != nil {
		return err
	}
	return fmt.Errorf("%s=%s: %s connection to %s failed: %w", family.setting(), source, network, normalized, err)
}
