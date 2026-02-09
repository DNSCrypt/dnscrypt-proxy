package dns

import (
	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

// helper functions called from the generated zmsg.go - among others
// all need to move to internal/pack or internal/unpack

// unpackHeader unpacks an RR header advancing msg.
func unpackHeader(h *Header, msg *cryptobyte.String, msgBuf []byte) (typ, rdlength uint16, err error) {
	h.Name, err = unpack.Name(msg, msgBuf)
	if err != nil {
		return 0, 0, err
	}
	if !msg.ReadUint16(&typ) ||
		!msg.ReadUint16(&h.Class) ||
		!msg.ReadUint32(&h.TTL) ||
		!msg.ReadUint16(&rdlength) {
		return typ, rdlength, unpack.ErrTruncatedMessage
	}
	return typ, rdlength, nil
}

// packHeader packs an RR header, returning the off to the end of the header.
// See PackName for documentation about the compression.
func (h Header) packHeader(msg []byte, off int, rrtype uint16, compress map[string]uint16) (int, error) {
	off, err := pack.Name(h.Name, msg, off, compress, true)
	if err != nil {
		return len(msg), err
	}
	if len(msg)-off < 10 {
		return len(msg), &pack.Error{Err: "overflow RR header"}
	}
	_ = msg[off+10]

	off, _ = pack.Uint16(rrtype, msg, off)
	off, _ = pack.Uint16(h.Class, msg, off)
	off, _ = pack.Uint32(h.TTL, msg, off)
	off += 2 // rdlength is written latter
	return off, nil
}
