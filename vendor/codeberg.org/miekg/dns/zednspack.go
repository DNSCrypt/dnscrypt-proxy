package dns

// should be generated, it is not...

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"

	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

func (o *LLQ) pack(msg []byte, off int) (off1 int, err error) {
	off, err = pack.Uint16(o.Version, msg, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint16(o.Opcode, msg, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint16(o.Error, msg, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint64(o.ID, msg, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint32(o.LeaseLife, msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (o *LLQ) unpack(s *cryptobyte.String) error {
	if !s.ReadUint16(&o.Version) {
		return unpack.ErrOverflow
	}
	if !s.ReadUint16(&o.Opcode) {
		return unpack.ErrOverflow
	}
	if !s.ReadUint16(&o.Error) {
		return unpack.ErrOverflow
	}
	if !s.ReadUint64(&o.ID) {
		return unpack.ErrOverflow
	}
	if !s.ReadUint32(&o.LeaseLife) {
		return unpack.ErrOverflow
	}
	return nil
}

func (o *NSID) unpack(s *cryptobyte.String) error {
	o.Nsid = hex.EncodeToString(*s)
	return nil
}

func (o *NSID) pack(msg []byte, off int) (int, error) {
	return hex.Decode(msg[off:], []byte(o.Nsid))
}

func (o *COOKIE) pack(msg []byte, off int) (int, error) {
	return hex.Decode(msg[off:], []byte(o.Cookie))
}

func (o *COOKIE) unpack(s *cryptobyte.String) error {
	o.Cookie = hex.EncodeToString(*s)
	return nil
}

func (o *PADDING) unpack(s *cryptobyte.String) error {
	return nil
}

func (o *PADDING) pack(msg []byte, off int) (int, error) {
	return 0, nil
}

func (o *DAU) pack(msg []byte, off int) (off1 int, err error) {
	for i := range o.AlgCode {
		if off, err = pack.Uint8(o.AlgCode[i], msg, off); err != nil {
			return off, err
		}
	}
	return off, nil
}

func (o *DAU) unpack(s *cryptobyte.String) error {
	for !s.Empty() {
		var a uint8
		s.ReadUint8(&a)
		o.AlgCode = append(o.AlgCode, a)
	}
	return nil
}

func (o *DHU) pack(msg []byte, off int) (off1 int, err error) {
	for i := range o.AlgCode {
		if off, err = pack.Uint8(o.AlgCode[i], msg, off); err != nil {
			return off, err
		}
	}
	return off, nil
}

func (o *DHU) unpack(s *cryptobyte.String) error {
	for !s.Empty() {
		var a uint8
		s.ReadUint8(&a)
		o.AlgCode = append(o.AlgCode, a)
	}
	return nil
}

func (o *N3U) pack(msg []byte, off int) (off1 int, err error) {
	for i := range o.AlgCode {
		if off, err = pack.Uint8(o.AlgCode[i], msg, off); err != nil {
			return off, err
		}
	}
	return off, nil
}

func (o *N3U) unpack(s *cryptobyte.String) error {
	for !s.Empty() {
		var a uint8
		s.ReadUint8(&a)
		o.AlgCode = append(o.AlgCode, a)
	}
	return nil
}

func (o *EDE) unpack(s *cryptobyte.String) (err error) {
	if !s.ReadUint16(&o.InfoCode) {
		return unpack.ErrOverflow
	}
	if o.ExtraText, err = unpack.StringAny(s, len(*s)); err != nil {
		return unpack.Errorf("overflow EDE option")
	}
	return nil
}

func (o *EDE) pack(msg []byte, off int) (int, error) {
	off, err := pack.Uint16(o.InfoCode, msg, off)
	if err != nil {
		return off, err
	}
	o.ExtraText = string(msg[off:])
	return off, nil
}

func (e *REPORTING) unpack(s *cryptobyte.String) (err error) {
	e.AgentDomain, err = unpack.Name(s, nil) // TODO: unpackNAme with nil buffer, no compression pointers..
	if err != nil {
		return unpack.Errorf("overflow REPORTING agent domain")
	}
	return nil
}

func (e *REPORTING) pack(msg []byte, off int) (int, error) {
	return pack.Name(e.AgentDomain, msg, off, nil, false)
}

func (o *EXPIRE) pack(msg []byte, off int) (int, error) {
	if o.Expire == 0 {
		return off, nil
	}
	return pack.Uint32(o.Expire, msg, off)
}

func (o *EXPIRE) unpack(s *cryptobyte.String) error {
	if s.Empty() { // zero-length EXPIRE query, see RFC 7314 Section 2
		o.Expire = 0
		return nil
	}
	if !s.ReadUint32(&o.Expire) {
		return unpack.ErrOverflow
	}
	return nil
}

func (o *TCPKEEPALIVE) pack(msg []byte, off int) (int, error) {
	if o.Timeout > 0 {
		return pack.Uint16(o.Timeout, msg, off)
	}
	return off, nil
}

func (o *TCPKEEPALIVE) unpack(s *cryptobyte.String) error {
	if s.Empty() {
		return nil
	}
	if !s.ReadUint16(&o.Timeout) {
		return unpack.ErrOverflow
	}
	return nil
}

func (o *SUBNET) pack(msg []byte, off int) (int, error) {
	binary.BigEndian.PutUint16(msg[off:], o.Family)
	off += 2
	msg[off] = o.SourceNetmask
	off++
	msg[off] = o.SourceScope
	off++
	switch o.Family {
	case 1:
		msg[off] = 32
	case 2:
		msg[off] = 128
	default:
		return off, pack.Errorf("bad address family")
	}
	return off, nil
}

func (o *SUBNET) unpack(s *cryptobyte.String) (err error) {
	if !s.ReadUint16(&o.Family) {
		return unpack.ErrOverflow
	}
	if !s.ReadUint8(&o.SourceNetmask) {
		return unpack.ErrOverflow
	}
	if !s.ReadUint8(&o.SourceScope) {
		return unpack.ErrOverflow
	}
	ok := false
	n := o.SourceNetmask / 8
	switch o.Family {
	case 0:
		// TODO(miek): make something that does not do a full parse.
		o.Address = netip.MustParseAddr("0.0.0.0")
	case 1:
		in := make([]byte, net.IPv4len, net.IPv4len)
		if !s.CopyBytes(in[:n]) {
			return unpack.Errorf("overflow SUBNET a")
		}
		if o.Address, ok = netip.AddrFromSlice(in); !ok {
			return unpack.Errorf("overflow SUBNET a")
		}
	case 2:
		in := make([]byte, net.IPv6len, net.IPv6len)
		if !s.CopyBytes(in[:n]) {
			return unpack.Errorf("overflow SUBNET aaaa")
		}
		if o.Address, ok = netip.AddrFromSlice(in); !ok {
			return unpack.Errorf("overflow SUBNET aaaa")
		}
	default:
		return unpack.Errorf("bad address family")
	}
	return nil
}

func (o *ESU) pack(msg []byte, off int) (int, error) {
	return pack.StringAny(o.URI, msg, off)
}

func (o *ESU) unpack(s *cryptobyte.String) (err error) {
	o.URI, err = unpack.StringAny(s, len(*s))
	return err
}

func (o *ZONEVERSION) pack(msg []byte, off int) (int, error) {
	off, err := pack.Uint8(o.Labels, msg, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint8(o.Type, msg, off)
	if err != nil {
		return off, err
	}
	return pack.StringAny(string(o.Version), msg, off)
}

func (o *ZONEVERSION) unpack(s *cryptobyte.String) (err error) {
	if !s.ReadUint8(&o.Labels) {
		return unpack.ErrOverflow
	}
	if !s.ReadUint8(&o.Type) {
		return unpack.ErrOverflow
	}
	v, err := unpack.StringAny(s, len(*s))
	o.Version = []byte(v)
	return err
}
