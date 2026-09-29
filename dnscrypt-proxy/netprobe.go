package main

import (
	"errors"
	"net"
	"strings"
)

// resolveNetprobeAddresses parses a netprobe address specification.
// Multiple addresses (for example an IPv4 and an IPv6 address) can be
// separated by commas; connectivity is detected as soon as any of them works.
func resolveNetprobeAddresses(address string) ([]*net.UDPAddr, error) {
	var addrs []*net.UDPAddr
	for _, part := range strings.Split(address, ",") {
		part = strings.TrimSpace(part)
		if len(part) == 0 {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", part)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		return nil, errors.New("No valid netprobe address in [" + address + "]")
	}
	return addrs, nil
}
