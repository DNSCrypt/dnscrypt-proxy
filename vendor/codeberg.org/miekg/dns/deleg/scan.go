package deleg

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

func Parse(i Info, b, o string) error {
	switch x := i.(type) {
	case *SERVERIPV6:
		return x.parse(b)
	case *SERVERIPV4:
		return x.parse(b)
	case *SERVERNAME:
		return x.parse(b, o)
	case *INCLUDEDELEGI:
		return x.parse(b, o)
	}
	return fmt.Errorf("no deleg parse defined")
}

func (s *SERVERIPV4) parse(b string) error {
	if len(b) == 0 {
		return errors.New("delegserveripv4: empty ips")
	}
	if strings.Contains(b, ":") {
		return errors.New("delegserveripv4: expected ipv4, got ipv6")
	}

	ips := make([]netip.Addr, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var e string
		e, b, _ = strings.Cut(b, ",")
		ip, err := netip.ParseAddr(e)
		if err != nil || !ip.Is4() {
			return errors.New("delegserveripv4: bad ip")
		}
		ips = append(ips, ip)
	}
	s.IPs = ips
	return nil
}

func (s *SERVERIPV6) parse(b string) error {
	if len(b) == 0 {
		return errors.New("delegserveripv6: empty ips")
	}

	ips := make([]netip.Addr, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var e string
		e, b, _ = strings.Cut(b, ",")
		ip, err := netip.ParseAddr(e)
		if err != nil {
			return errors.New("delegserveripv6: bad ip")
		}
		if !ip.Is6() || ip.Is4In6() {
			return errors.New("delegserveripv6: expected ipv6, got ipv4-mapped-ipv6")
		}
		ips = append(ips, ip)
	}
	s.IPs = ips
	return nil
}

func (s *SERVERNAME) parse(b, o string) error {
	if len(b) == 0 {
		return errors.New("delegservername: empty hostnames")
	}

	hostnames := make([]string, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var e string
		e, b, _ = strings.Cut(b, ",")
		e = dnsutilAbsolute(e, o)
		if e == "" {
			return errors.New("delegservername: bad hostname")
		}
		hostnames = append(hostnames, e)
	}
	s.Hostnames = hostnames
	return nil
}

func (s *INCLUDEDELEGI) parse(b, o string) error {
	if len(b) == 0 {
		return errors.New("delegincludedelegi: empty domains")
	}

	domains := make([]string, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var e string
		e, b, _ = strings.Cut(b, ",")
		e = dnsutilAbsolute(e, o)
		if e == "" {
			return errors.New("delegincludedelegi: bad domain")
		}
		domains = append(domains, e)
	}
	s.Domains = domains
	return nil
}
