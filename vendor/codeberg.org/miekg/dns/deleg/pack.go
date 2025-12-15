package deleg

import (
	"fmt"

	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

// should all be generated...

// _pack converts an info to wire-format.
func _pack(i Info, msg []byte, off int) (int, error) {
	switch x := i.(type) {
	case *SERVERIPV4:
		return x.pack(msg, off)
	case *SERVERIPV6:
		return x.pack(msg, off)
	case *SERVERNAME:
		return x.pack(msg, off)
	case *INCLUDEDELEGI:
		return x.pack(msg, off)
	}
	return 0, fmt.Errorf("dns: no deleg pack defined")
}

// unpack converts wire-format to an info.
func _unpack(i Info, data *cryptobyte.String) error {
	switch x := i.(type) {
	case *SERVERIPV4:
		return x.unpack(data)
	case *SERVERIPV6:
		return x.unpack(data)
	case *SERVERNAME:
		return x.unpack(data)
	case *INCLUDEDELEGI:
		return x.unpack(data)
	}
	return fmt.Errorf("dns: no deleg unpack defined")
}

func (s *SERVERIPV4) pack(msg []byte, off int) (int, error) {
	off, err := packTLV(s, msg, off)
	if err != nil {
		return off, err
	}
	for _, ip := range s.IPs {
		off, err = pack.A(ip, msg, off)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func (s *SERVERIPV4) unpack(sc *cryptobyte.String) error {
	for !sc.Empty() {
		ip, err := unpack.A(sc)
		if err != nil {
			return err
		}
		s.IPs = append(s.IPs, ip)
	}
	return nil
}

func (s *SERVERIPV6) pack(msg []byte, off int) (int, error) {
	off, err := packTLV(s, msg, off)
	if err != nil {
		return off, err
	}
	for _, ip := range s.IPs {
		off, err = pack.AAAA(ip, msg, off)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func (s *SERVERIPV6) unpack(sc *cryptobyte.String) error {
	for !sc.Empty() {
		ip, err := unpack.AAAA(sc)
		if err != nil {
			return err
		}
		s.IPs = append(s.IPs, ip)
	}
	return nil
}

func (s *SERVERNAME) pack(msg []byte, off int) (int, error) {
	off, err := packTLV(s, msg, off)
	if err != nil {
		return off, err
	}
	for _, hostname := range s.Hostnames {
		off, err = pack.Name(hostname, msg, off, nil, false)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func (s *SERVERNAME) unpack(sc *cryptobyte.String) error {
	if !sc.Empty() {
		hostname, err := unpack.Name(sc, nil)
		if err != nil {
			return err
		}
		s.Hostnames = append(s.Hostnames, hostname)
	}
	return nil
}

func (s *INCLUDEDELEGI) pack(msg []byte, off int) (int, error) {
	off, err := packTLV(s, msg, off)
	if err != nil {
		return off, err
	}
	for _, domain := range s.Domains {
		off, err = pack.Name(domain, msg, off, nil, false)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}

func (s *INCLUDEDELEGI) unpack(sc *cryptobyte.String) error {
	if !sc.Empty() {
		domain, err := unpack.Name(sc, nil)
		if err != nil {
			return err
		}
		s.Domains = append(s.Domains, domain)
	}
	return nil
}

func packTLV(p Info, msg []byte, off int) (off1 int, err error) {
	key := InfoToKey(p)
	length := uint16(p.Len()) - tlv // now here we do the rdata length, not the 4 octets we encoding here
	off, err = pack.Uint16(key, msg, off)
	if err != nil {
		return len(msg), fmt.Errorf("dns: overflow packing DELEG")
	}
	off, err = pack.Uint16(length, msg, off)
	if err != nil {
		return len(msg), fmt.Errorf("dns: overflow packing DELEG")
	}
	return off, err
}
