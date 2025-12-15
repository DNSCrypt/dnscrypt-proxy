package dns

import (
	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

// helper functions called from the generated zmsg.go - among others
// all need to move to internal/pack or internal/unpack

// unpackHeader unpacks an RR header advancing msg.
func unpackHeader(msg *cryptobyte.String, msgBuf []byte) (h Header, typ, rdlength uint16, err error) {
	h.Name, err = unpack.Name(msg, msgBuf)
	if err != nil {
		return h, 0, 0, err
	}
	t := uint16(0)
	if !msg.ReadUint16(&t) ||
		!msg.ReadUint16(&h.Class) ||
		!msg.ReadUint32(&h.TTL) ||
		!msg.ReadUint16(&rdlength) {
		return h, t, rdlength, unpack.ErrTruncatedMessage
	}
	return h, t, rdlength, nil
}

// packHeader packs an RR header, returning the off to the end of the header.
// See PackName for documentation about the compression.
func (h Header) packHeader(msg []byte, off int, rrtype uint16, compress map[string]uint16) (int, error) {
	if off == len(msg) {
		return off, nil
	}
	off, err := pack.Name(h.Name, msg, off, compress, true)
	if err != nil {
		return len(msg), err
	}
	off, err = pack.Uint16(rrtype, msg, off)
	if err != nil {
		return len(msg), err
	}
	off, err = pack.Uint16(h.Class, msg, off)
	if err != nil {
		return len(msg), err
	}
	off, err = pack.Uint32(h.TTL, msg, off)
	if err != nil {
		return len(msg), err
	}
	off, err = pack.Uint16(0, msg, off) // The RDLENGTH field will be set later in packRR.
	if err != nil {
		return len(msg), err
	}
	return off, nil
}
