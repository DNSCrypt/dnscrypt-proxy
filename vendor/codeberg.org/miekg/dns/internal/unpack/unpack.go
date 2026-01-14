package unpack

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"

	"codeberg.org/miekg/dns/internal/ddd"
	"golang.org/x/crypto/cryptobyte"
)

const (
	maxNameWireOctets = 255 // See RFC 1035 section 2.3.4

	// This is the maximum length of a domain name in presentation format. The
	// maximum wire length of a domain name is 255 octets (see above), with the
	// maximum label length being 63. The wire format requires one extra byte over
	// the presentation format.
	maxNamePresentationLength = maxNameWireOctets - 1
)

func A(s *cryptobyte.String) (netip.Addr, error) {
	in := make([]byte, net.IPv4len)
	if !s.CopyBytes(in) {
		return netip.Addr{}, &Error{"overflow A"}
	}
	ip, ok := netip.AddrFromSlice(in)
	if !ok {
		return netip.Addr{}, &Error{"invalid A"}
	}
	return ip, nil
}

func AAAA(s *cryptobyte.String) (netip.Addr, error) {
	in := make([]byte, net.IPv6len)
	if !s.CopyBytes(in) {
		return netip.Addr{}, &Error{"overflow AAAA"}
	}
	ip, ok := netip.AddrFromSlice(in)
	if !ok {
		return netip.Addr{}, &Error{"invalid AAAA"}
	}
	return ip, nil
}

// See [pack.StringAny].
func StringAny(s *cryptobyte.String, len int) (string, error) {
	var b []byte
	if !s.ReadBytes(&b, len) {
		return "", &Error{"overflow string anything"}
	}
	return string(b), nil
}

func StringTxt(s *cryptobyte.String) ([]string, error) { return Txt(s) }

func Txt(s *cryptobyte.String) ([]string, error) {
	var strs []string
	for !s.Empty() {
		str, err := String(s)
		if err != nil {
			return strs, err
		}
		strs = append(strs, str)
	}
	return strs, nil
}

func String(s *cryptobyte.String) (string, error) {
	var txt cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&txt) {
		return "", &Error{"overflow string"}
	}
	var sb strings.Builder
	consumed := 0
	for i, b := range txt {
		switch {
		case b == '"' || b == '\\':
			if consumed == 0 {
				sb.Grow(len(txt) * 2)
			}
			sb.Write(txt[consumed:i])
			sb.WriteByte('\\')
			sb.WriteByte(b)
			consumed = i + 1
		case b < ' ' || b > '~': // unprintable
			if consumed == 0 {
				sb.Grow(len(txt) * 2)
			}
			sb.Write(txt[consumed:i])
			sb.WriteString(ddd.Escape(b))
			consumed = i + 1
		}
	}
	if consumed == 0 { // no escaping needed
		return string(txt), nil
	}
	sb.Write(txt[consumed:])
	return sb.String(), nil
}

// Name unpacks a domain name.
// In addition to the simple sequences of counted strings above, domain names are allowed to refer to strings elsewhere in the
// packet, to avoid repeating common suffixes when returning many entries in a single domain. The pointers are marked
// by a length byte with the top two bits set. Ignoring those two bits, that byte and the next give a 14 bit offset from into msg
// where we should pick up the trail.
// Note that if we jump elsewhere in the packet, we record the last offset we read from when we found the first pointer,
// which is where the next record or record field will start. We enforce that pointers always point backwards into the message.

// Name unpacks a name in a cryptobyte.String.
func Name(s *cryptobyte.String, msgBuf []byte) (string, error) {
	name := make([]byte, 0, maxNamePresentationLength)
	var ptrs bool

	// If we never see a pointer, we need to ensure that we advance s to our final position.
	cs := *s

	var c byte
	for {
		if !cs.ReadUint8(&c) {
			return "", &Error{"overflow"}
		}
		switch c & 0xC0 {
		case 0x00: // literal string
			if c == 0 { // If we see a zero-length label (root label), this is the end of the name.
				if !ptrs {
					*s = cs
				}
				if len(name) == 0 {
					return ".", nil
				}
				return string(name), nil
			}

			if len(name)+int(c)+1 > maxNamePresentationLength {
				return "", &Error{"name exceeded max wire-format octets: " + string(*s)}
			}
			var label []byte
			cs.ReadBytes(&label, int(c))
			name = append(name, label...)
			name = append(name, '.')

		case 0xC0: // pointer
			if msgBuf == nil {
				return "", &Error{"pointer in uncompressable name"}
			}
			var c1 byte
			if !cs.ReadUint8(&c1) {
				return "", &Error{"overflow"}
			}
			// If this is the first pointer we've seen, we need to advance s to our current position.
			if !ptrs {
				*s = cs
			}
			// The pointer should always point backwards to an earlier part of the message. Technically it could work pointing
			// forwards, but we choose not to support that as RFC 1035 specifically refers to a "prior
			// occurrence".
			off := uint16(c&^0xC0)<<8 | uint16(c1)
			if int(off) >= Offset(cs, msgBuf)-2 {
				return "", &Error{"pointer not to prior occurrence of name"}
			}
			// Jump to the offset in msgBuf. We carry msgBuf around with us solely for this line.
			cs = msgBuf[off:]
			ptrs = true

		default: // 0x80 and 0x40 are reserved
			return "", &Error{"reserved domain name label type"}
		}
	}
}

// Offset reports the offset of data into buf.
func Offset(data, buf []byte) int { return len(buf) - len(data) }

func StringBase32(s *cryptobyte.String, len int) (string, error) {
	var b []byte
	if !s.ReadBytes(&b, len) {
		return "", ErrOverflow
	}
	return Base32(b), nil
}

func StringBase64(s *cryptobyte.String, len int) (string, error) {
	var b []byte
	if !s.ReadBytes(&b, len) {
		return "", ErrOverflow
	}
	return Base64(b), nil
}

func Base32(b []byte) string {
	return base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
func Base64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func StringHex(s *cryptobyte.String, len int) (string, error) {
	var b []byte
	if !s.ReadBytes(&b, len) {
		return "", ErrOverflow
	}
	return hex.EncodeToString(b), nil
}

func Names(s *cryptobyte.String, msgBuf []byte) ([]string, error) {
	var names []string
	for !s.Empty() {
		name, err := Name(s, msgBuf)
		if err != nil {
			return names, err
		}
		names = append(names, name)
	}
	return names, nil
}
