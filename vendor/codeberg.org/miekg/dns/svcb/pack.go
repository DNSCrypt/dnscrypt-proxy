package svcb

import (
	"errors"
	"fmt"

	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

// _pack converts a pair to wire-format.
func _pack(p Pair, msg []byte, off int) (int, error) {
	switch x := p.(type) {
	case *MANDATORY:
		return x.pack(msg, off)
	case *ALPN:
		return x.pack(msg, off)
	case *NODEFAULTALPN:
		return x.pack(msg, off)
	case *PORT:
		return x.pack(msg, off)
	case *IPV4HINT:
		return x.pack(msg, off)
	case *ECHCONFIG:
		return x.pack(msg, off)
	case *IPV6HINT:
		return x.pack(msg, off)
	case *DOHPATH:
		return x.pack(msg, off)
	case *OHTTP:
		return x.pack(msg, off)
	case *LOCAL:
		return x.pack(msg, off)
	}
	return 0, fmt.Errorf("dns: no svcb pack defined")
}

// _unpack converts wire-format to a pair. Only exported to make it available to the dns unpacker.
func _unpack(p Pair, data *cryptobyte.String) error {
	switch x := p.(type) {
	case *MANDATORY:
		return x.unpack(data)
	case *ALPN:
		return x.unpack(data)
	case *NODEFAULTALPN:
		return x.unpack(data)
	case *PORT:
		return x.unpack(data)
	case *IPV4HINT:
		return x.unpack(data)
	case *ECHCONFIG:
		return x.unpack(data)
	case *IPV6HINT:
		return x.unpack(data)
	case *DOHPATH:
		return x.unpack(data)
	case *OHTTP:
		return x.unpack(data)
	case *LOCAL:
		return x.unpack(data)
	}
	return fmt.Errorf("dns: no svcb unpack defined")
}

func (s *MANDATORY) pack(msg []byte, off int) (off1 int, err error) {
	off, err = packTLV(s, msg, off)
	if err != nil {
		return len(msg), err
	}
	for _, k := range s.Key {
		off, err = pack.Uint16(k, msg, off)
	}
	return off, nil
}

func (s *MANDATORY) unpack(sc *cryptobyte.String) error {
	for !sc.Empty() {
		var key uint16
		if !sc.ReadUint16(&key) {
			return errors.New("dns: svcbmandatory: value length is not a multiple of 2")
		}
		s.Key = append(s.Key, key)
	}
	return nil
}

func (s *ALPN) pack(msg []byte, off int) (off1 int, err error) {
	off, err = packTLV(s, msg, off)
	for _, e := range s.Alpn {
		if e == "" {
			return len(msg), errors.New("dns: svcbalpn: empty alpn-id")
		}
		if len(e) > 255 {
			return len(msg), errors.New("dns: svcbalpn: alpn-id too long")
		}

		if off, err = pack.Uint8(byte(len(e)), msg, off); err != nil {
			return len(msg), err
		}
		if off, err = pack.StringAny(e, msg, off); err != nil {
			return len(msg), err
		}
	}
	return off, nil
}

func (s *ALPN) unpack(sc *cryptobyte.String) error {
	for !sc.Empty() {
		var data cryptobyte.String
		if !sc.ReadUint8LengthPrefixed(&data) {
			return fmt.Errorf("dns: overflow unpacking data")
		}
		s.Alpn = append(s.Alpn, string(data))
	}
	return nil
}

func (s *NODEFAULTALPN) pack(msg []byte, off int) (int, error) {
	off, err := packTLV(s, msg, off)
	return off, err
}

func (*NODEFAULTALPN) unpack(sc *cryptobyte.String) error {
	if !sc.Empty() {
		return errors.New("dns: svcbnodefaultalpn: no-default-alpn must have no value")
	}
	return nil
}

func (s *PORT) pack(msg []byte, off int) (off1 int, err error) {
	off, err = packTLV(s, msg, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint16(s.Port, msg, off)
	return off, err
}

func (s *PORT) unpack(sc *cryptobyte.String) error {
	if !sc.ReadUint16(&s.Port) {
		return errors.New("dns: svcbport: port length is not exactly 2 octets")
	}
	return nil
}

func (s *IPV4HINT) pack(msg []byte, off int) (int, error) {
	off, err := packTLV(s, msg, off)
	if err != nil {
		return off, err
	}
	for _, ip := range s.Hint {
		off, err = pack.A(ip, msg, off)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func (s *IPV4HINT) unpack(sc *cryptobyte.String) error {
	for !sc.Empty() {
		ip, err := unpack.A(sc)
		if err != nil {
			return errors.New("dns: svcbipv4hint: ipv4 address byte array length is not a multiple of 4")
		}
		s.Hint = append(s.Hint, ip)
	}
	return nil
}

func (s *ECHCONFIG) pack(msg []byte, off int) (int, error) {
	off, err := packTLV(s, msg, off)
	if err != nil {
		return off, err
	}
	if len(s.ECH) > len(msg) {
		return off, errors.New("dns: svcbechconfig: overflow packing")
	}
	n := copy(msg[off:], s.ECH)
	return off + n, nil
}

func (s *ECHCONFIG) unpack(sc *cryptobyte.String) error {
	s.ECH = make([]byte, len([]byte(*sc)))
	if !sc.CopyBytes(s.ECH) {
		return errors.New("dns: svcbechconfig overflow unpacking")
	}
	return nil
}

func (s *IPV6HINT) pack(msg []byte, off int) (int, error) {
	off, err := packTLV(s, msg, off)
	if err != nil {
		return off, err
	}
	for _, ip := range s.Hint {
		off, err = pack.AAAA(ip, msg, off)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func (s *IPV6HINT) unpack(sc *cryptobyte.String) error {
	for !sc.Empty() {
		ip, err := unpack.AAAA(sc)
		if err != nil {
			return errors.New("dns: svcbipv6hint: expected ipv6, got ipv4")
		}
		s.Hint = append(s.Hint, ip)
	}
	return nil
}

func (s *DOHPATH) pack(msg []byte, off int) (int, error) {
	off, err := packTLV(s, msg, off)
	if err != nil {
		return off, err
	}
	return pack.StringAny(s.Template, msg, off)
}

func (s *DOHPATH) unpack(sc *cryptobyte.String) (err error) {
	s.Template, err = unpack.StringAny(sc, len(*sc))
	return err
}

func (s *OHTTP) pack(msg []byte, off int) (int, error) {
	off, err := packTLV(s, msg, off)
	return off, err
}

func (*OHTTP) unpack(sc *cryptobyte.String) error {
	if !sc.Empty() {
		return errors.New("dns: svcbotthp: svcbotthp must have no value")
	}
	return nil
}

func (s *LOCAL) pack(msg []byte, off int) (int, error) {
	off, err := pack.Uint16(s.KeyCode, msg, off)
	if err != nil {
		return len(msg), fmt.Errorf("dns: svcblocal: overflow packing keycode")
	}
	off, err = pack.Uint16(uint16(len(s.Data)), msg, off)
	if err != nil {
		return len(msg), fmt.Errorf("dns: svcblocal: overflow packing length")
	}
	n := copy(msg[off:], s.Data)
	return off + n, nil
}

func (s *LOCAL) unpack(sc *cryptobyte.String) error {
	// keys also, custom TLV
	s.Data = make([]byte, len(*sc))
	if !sc.CopyBytes(s.Data) {
		return errors.New("dns: svcblocal overflow unpacking")
	}
	return nil
}

func packTLV(p Pair, msg []byte, off int) (off1 int, err error) {
	key := PairToKey(p)
	length := uint16(p.Len()) - tlv // now here we do the rdata length, not the 4 octets we encoding here
	off, err = pack.Uint16(key, msg, off)
	if err != nil {
		return len(msg), fmt.Errorf("dns: overflow packing SVCB")
	}
	off, err = pack.Uint16(length, msg, off)
	if err != nil {
		return len(msg), fmt.Errorf("dns: overflow packing SVCB")
	}
	return off, err
}
