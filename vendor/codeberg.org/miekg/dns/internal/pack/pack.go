package pack

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"

	"codeberg.org/miekg/dns/internal/ddd"
)

const maxCompressionOffset = 2 << 13 // We have 14 bits for the compression pointer

// maybe this should all moved to cryptobyte as well...
// near future direction is clear all pack helpers should be here, not in msg_helpers.go

func Uint8(i uint8, msg []byte, off int) (off1 int, err error) {
	if off+1 > len(msg) {
		return len(msg), &Error{"overflow uint8"}
	}
	msg[off] = i
	return off + 1, nil
}

func Uint16(i uint16, msg []byte, off int) (off1 int, err error) {
	if off+2 > len(msg) {
		return len(msg), &Error{"overflow uint16"}
	}
	binary.BigEndian.PutUint16(msg[off:], i)
	return off + 2, nil
}

func Uint32(i uint32, msg []byte, off int) (off1 int, err error) {
	if off+4 > len(msg) {
		return len(msg), &Error{"overflow uint32"}
	}
	binary.BigEndian.PutUint32(msg[off:], i)
	return off + 4, nil
}

func Uint48(i uint64, msg []byte, off int) (off1 int, err error) {
	if off+6 > len(msg) {
		return len(msg), &Error{"overflow uint64 as uint48"}
	}
	msg[off] = byte(i >> 40)
	msg[off+1] = byte(i >> 32)
	msg[off+2] = byte(i >> 24)
	msg[off+3] = byte(i >> 16)
	msg[off+4] = byte(i >> 8)
	msg[off+5] = byte(i)
	off += 6
	return off, nil
}

func Uint64(i uint64, msg []byte, off int) (off1 int, err error) {
	if off+8 > len(msg) {
		return len(msg), &Error{"overflow uint64"}
	}
	binary.BigEndian.PutUint64(msg[off:], i)
	off += 8
	return off, nil
}

// StringAny packs a string as-is, no decoding or length bytes are written.
func StringAny(s string, msg []byte, off int) (int, error) {
	if off+len(s) > len(msg) {
		return len(msg), &Error{"overflow string anything"}
	}
	copy(msg[off:off+len(s)], s)
	off += len(s)
	return off, nil
}

func StringTxt(s []string, msg []byte, off int) (int, error) {
	off, err := Txt(s, msg, off)
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

func Txt(txt []string, msg []byte, off int) (int, error) {
	if len(txt) == 0 {
		if off >= len(msg) {
			return len(msg), ErrBuf
		}
		msg[off] = 0
		return off, nil
	}
	var err error
	for i := range txt {
		off, err = TxtString(txt[i], msg, off)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}

func String(s string, msg []byte, off int) (int, error) {
	off, err := TxtString(s, msg, off)
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

func TxtString(s string, msg []byte, off int) (int, error) {
	lenByteoff := off
	if off >= len(msg) || len(s) > 256*4+1 /* If all \DDD */ {
		return len(msg), &Error{"buffer size too small"}
	}
	off++
	for i := 0; i < len(s); i++ {
		if len(msg) <= off {
			return off, &Error{"buffer size too small"}
		}
		if s[i] == '\\' {
			i++
			if i == len(s) {
				break
			}
			// check for \DDD
			if ddd.Is(s[i:]) {
				msg[off] = ddd.ToByte(s[i:])
				i += 2
			} else {
				msg[off] = s[i]
			}
		} else {
			msg[off] = s[i]
		}
		off++
	}
	l := off - lenByteoff - 1
	if l > 255 {
		return len(msg), &Error{"string exceeded 255 bytes in txt"}
	}
	msg[lenByteoff] = byte(l)
	return off, nil
}

func A(a netip.Addr, msg []byte, off int) (int, error) {
	if off+net.IPv4len > len(msg) {
		return len(msg), &Error{"overflow a"}
	}
	if !a.Is4() && !a.Is4In6() {
		return len(msg), &Error{"invalid a"}
	}
	val := a.As4()
	copy(msg[off:], val[:])
	off += net.IPv4len
	return off, nil
}

func AAAA(aaaa netip.Addr, msg []byte, off int) (int, error) {
	if off+net.IPv6len > len(msg) {
		return len(msg), &Error{"overflow aaaa"}
	}
	val := aaaa.As16()
	copy(msg[off:], val[:])
	off += net.IPv6len
	return off, nil
}

func Name(s string, msg []byte, off int, compression map[string]uint16, compress bool) (off1 int, err error) {
	// XXX: A logical copy of this function exists in dnsutil.IsName and should be kept in sync with this function.

	ls := len(s)

	if ls == 1 && s[0] == '.' {
		msg[off] = 0
		return off + 1, nil

	}
	if ls > 1 && s[0] == '.' { // leading dots are not legal except for the root zone
		return len(msg), &Error{"leading dot in name: " + s}
	}
	// TODO(miek): add back?
	//	if !strings.HasSuffix(s, ".") {
	//		return len(msg), &Error{"name must be fully qualified: " + s}
	//	}

	// Each dot ends a segment of the name. We trade each dot byte for a length byte.
	// Except for escaped dots (\.), which are normal dots. There is also a trailing zero.

	// Emit sequence of counted strings, chopping at dots.
	var (
		begin     int
		compBegin int
	)

	lenmsg := len(msg)
	for i := range ls {
		if s[i] != '.' {
			continue
		}

		labelLen := i - begin
		if labelLen >= 1<<6 { // top two bits of length must be clear
			return lenmsg, &Error{"illegal label type in name: " + s}
		}
		if labelLen == 0 {
			return lenmsg, &Error{"consecutive dots in name: " + s}
		}

		// off can already (we're in a loop) be bigger than len(msg)
		// this happens when a name isn't fully qualified
		if off+1+labelLen > lenmsg {
			return lenmsg, &Error{"buffer size too small"}
		}

		// Don't try to compress '.'
		// We should only compress when compress is true, but we should also still pick
		// up names that can be used for *future* compression(s).
		if compression != nil && labelLen > 1 {
			if p, ok := compression[s[compBegin:]]; ok {
				// The first hit is the longest matching dname keep the pointer offset we get back and store
				// the offset of the current name, because that's where we need to insert the pointer later

				// If compress is true, we're allowed to compress this name.
				if compress {
					// We have two bytes (14 bits) to put the pointer in.
					binary.BigEndian.PutUint16(msg[off:], 0xC000|p)
					return off + 2, nil
				}
			} else if off < maxCompressionOffset {
				// Only offsets smaller than maxCompressionOffset can be used.
				compression[s[compBegin:]] = uint16(off)
			}
		}

		// The following is covered by the length check above.
		msg[off] = byte(labelLen)
		copy(msg[off+1:], s[begin:i])

		off += 1 + labelLen
		begin = i + 1
		compBegin = begin
	}

	msg[off] = 0 // length check needed??
	return off + 1, nil
}

func StringBase32(s string, msg []byte, off int) (int, error) {
	b32, err := Base32([]byte(s))
	if err != nil {
		return len(msg), err
	}
	if off+len(b32) > len(msg) {
		return len(msg), &Error{Err: "overflow base32"}
	}
	copy(msg[off:off+len(b32)], b32)
	off += len(b32)
	return off, nil
}

func StringBase64(s string, msg []byte, off int) (int, error) {
	b64, err := Base64([]byte(s))
	if err != nil {
		return len(msg), err
	}
	if off+len(b64) > len(msg) {
		return len(msg), &Error{Err: "overflow base64"}
	}
	copy(msg[off:off+len(b64)], b64)
	off += len(b64)
	return off, nil
}

func Base32(s []byte) (buf []byte, err error) {
	for i, b := range s {
		if b >= 'a' && b <= 'z' {
			s[i] = b - 32
		}
	}
	b32hex := base32.HexEncoding.WithPadding(base32.NoPadding)
	buflen := b32hex.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := b32hex.Decode(buf, s)
	buf = buf[:n]
	return
}

func Base64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func StringHex(s string, msg []byte, off int) (int, error) {
	h, err := hex.DecodeString(s)
	if err != nil {
		return len(msg), err
	}
	if off+len(h) > len(msg) {
		return len(msg), &Error{Err: "overflow hex"}
	}
	copy(msg[off:off+len(h)], h)
	off += len(h)
	return off, nil
}

func Names(names []string, msg []byte, off int, compress map[string]uint16) (int, error) {
	var err error
	for i := range names {
		off, err = Name(names[i], msg, off, compress, false)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}
