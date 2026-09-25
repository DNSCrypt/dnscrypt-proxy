package dns

import "codeberg.org/miekg/dns/internal/dnslex"

func (*OPT) parse(_ *dnslex.Lexer, _ string) *ParseError {
	return &ParseError{err: "OPT records do not have a presentation format"}
}

// version returns the EDNS version used. Only version zero is currently defined. See [Msg.Version].
func (rr *OPT) version() uint8 { return uint8(rr.Hdr.TTL & 0x00FF0000 >> 16) }

// setVersion sets the version of EDNS. This is usually zero. See [Msg.Version].
func (rr *OPT) setVersion(v uint8) { rr.Hdr.TTL = rr.Hdr.TTL&0xFF00FFFF | uint32(v)<<16 }

// udpSize returns the UDP buffer size. See [Msg.UDPSize].
func (rr *OPT) udpSize() uint16 { return rr.Hdr.Class }

// setUDPSize sets the UDP buffer size. See [Msg.UDPSize].
func (rr *OPT) setUDPSize(size uint16) { rr.Hdr.Class = size }

// security returns the value of the DO (DNSSEC OK) bit. See [Msg.Security].
func (rr *OPT) security() bool { return rr.Hdr.TTL&_DO == _DO }

// setSecurity sets the security (DNSSEC OK) bit. See [Msg.Security].
func (rr *OPT) setSecurity(do bool) {
	if do {
		rr.Hdr.TTL |= _DO
	} else {
		rr.Hdr.TTL &^= _DO
	}
}

// compactAnswers returns the value of the CO (Compact Answers OK) bit. See [Msg.CompactAnswers].
func (rr *OPT) compactAnswers() bool { return rr.Hdr.TTL&_CO == _CO }

// setCompactAnswers sets the CO (Compact Answers OK) bit. See [Msg.CompactAnswers].
func (rr *OPT) setCompactAnswers(co bool) {
	if co {
		rr.Hdr.TTL |= _CO
	} else {
		rr.Hdr.TTL &^= _CO
	}
}

// delegation returns the value of the delegation (DE OK) bit. See [Msg.Delegation].
func (rr *OPT) delegation() bool { return rr.Hdr.TTL&_DE == _DE }

// setDelegation sets the delegation (DE OK) bit. See [Msg.Delegation].
func (rr *OPT) setDelegation(de bool) {
	if de {
		rr.Hdr.TTL |= _DE
	} else {
		rr.Hdr.TTL &^= _DE
	}
}

// rcode returns the EDNS extended Rcode field (the upper 8 bits of the TTL). See [Msg.Rcode].
func (rr *OPT) rcode() uint16 {
	return uint16(rr.Hdr.TTL&0xFF000000>>24) << 4
}

// setRcode sets the EDNS extended Rcode field.
// If the Rcode is not an extended Rcode, will reset the extended Rcode field to 0. See [Msg.Rcode].
func (rr *OPT) setRcode(v uint16) {
	rr.Hdr.TTL = rr.Hdr.TTL&0x00FFFFFF | uint32(v>>4)<<24
}

// z returns the Z part of the OPT RR as a uint16 with only the 13 least significant bits used.
func (rr *OPT) z() uint16 {
	return uint16(rr.Hdr.TTL & 0x1FFF)
}

// setZ sets the Z part of the OPT RR, note only the 13 significant bits of z are used.
func (rr *OPT) setZ(z uint16) {
	rr.Hdr.TTL = rr.Hdr.TTL&^0x1FFF | uint32(z&0x1FFF)
}
