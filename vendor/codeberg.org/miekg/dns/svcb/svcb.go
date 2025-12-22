// Package svcb deals with all the intricacies of the SVCB/HTTPS RR. All the sub-types ([Pair]) used in
// the RR are defined here.
package svcb

import (
	"encoding/base64"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/internal/ddd"
	"codeberg.org/miekg/dns/internal/reverse"
)

// Keys as defined in RFC 9460.
const (
	KeyMandatory uint16 = iota
	KeyAlpn
	KeyNoDefaultALPN
	KeyPort
	KeyIPv4Hint
	KeyEchConfig
	KeyIPv6Hint
	KeyDohPath // See RFC 9461 Section 5.
	KeyOhttp   // See RFC 9540 Section 8.

	KeyReserved uint16 = 65535
)

// Pair defines a key=value pair for the SVCB RR type. An SVCB RR can have multiple pairs appended to it.
// The numerical key code is derived from the type, see [PairToKey].
type Pair interface {
	String() string // String returns the string representation of the value.
	Len() int       // Len returns the length of value in the wire format.
	Clone() Pair    // Clone returns a deep copy of the Pair.
}

// KeyToString return the string representation for k.  For KeyReserved the empty string is returned. For
// unknown keys "key"+value is returned, see section 2.1 of RFC 9460.
func KeyToString(k uint16) string {
	if k == KeyReserved {
		return ""
	}
	if s, ok := keyToString[k]; ok {
		return s
	}
	return "key" + strconv.Itoa(int(k))
}

var keyToString = map[uint16]string{
	KeyMandatory:     "mandatory",
	KeyAlpn:          "alpn",
	KeyNoDefaultALPN: "no-default-alpn",
	KeyPort:          "port",
	KeyIPv4Hint:      "ipv4hint",
	KeyEchConfig:     "ech",
	KeyIPv6Hint:      "ipv6hint",
	KeyDohPath:       "dohpath",
	KeyOhttp:         "ohttp",
}

// StringtoKey is the reverse of KeyToString and takes keyXXXX into account.
func StringToKey(s string) uint16 {
	if k, ok := stringToKey[s]; ok {
		return k
	}
	if strings.HasPrefix(s, "key") {
		k, _ := strconv.Atoi(s[3:])
		return uint16(k)
	}
	return KeyReserved
}

var stringToKey = reverse.Int16(keyToString)

// KeyToPair convert the key value to a Pair.
func KeyToPair(k uint16) func() Pair {
	switch k {
	case KeyMandatory:
		return func() Pair { return new(MANDATORY) }
	case KeyAlpn:
		return func() Pair { return new(ALPN) }
	case KeyNoDefaultALPN:
		return func() Pair { return new(NODEFAULTALPN) }
	case KeyPort:
		return func() Pair { return new(PORT) }
	case KeyIPv4Hint:
		return func() Pair { return new(IPV4HINT) }
	case KeyEchConfig:
		return func() Pair { return new(ECHCONFIG) }
	case KeyIPv6Hint:
		return func() Pair { return new(IPV6HINT) }
	case KeyDohPath:
		return func() Pair { return new(DOHPATH) }
	case KeyOhttp:
		return func() Pair { return new(OHTTP) }
	case KeyReserved:
		return func() Pair { return nil }
	default:
		return func() Pair { return &LOCAL{KeyCode: k} }
	}
}

// PairToKey is the reverse of KeyToPair.
func PairToKey(p Pair) uint16 {
	switch p := p.(type) {
	case *MANDATORY:
		return KeyMandatory
	case *ALPN:
		return KeyAlpn
	case *NODEFAULTALPN:
		return KeyNoDefaultALPN
	case *PORT:
		return KeyPort
	case *IPV4HINT:
		return KeyIPv4Hint
	case *ECHCONFIG:
		return KeyEchConfig
	case *IPV6HINT:
		return KeyIPv6Hint
	case *DOHPATH:
		return KeyDohPath
	case *OHTTP:
		return KeyOhttp
	case *LOCAL:
		return p.KeyCode
	}
	return KeyReserved
}

// MANDATORY pair adds to required keys that must be interpreted for the RR
// to be functional. If ignored, the whole RRSet must be ignored.
// "port" and "no-default-alpn" are mandatory by default if present,
// so they shouldn't be included here.
//
// It is incumbent upon the user of this library to reject the RRSet if or avoid constructing such an RRSet that:
//
//   - "mandatory" is included as one of the keys of mandatory
//   - no key is listed multiple times in mandatory
//   - all keys listed in mandatory are present
//   - escape sequences are not used in mandatory
//   - mandatory, when present, lists at least one key
//
// Basic use pattern for creating a mandatory option in a SVCB RR, called s:
//
//	s.Value = append(s.Value, &svcb.MANDATORY{})
//	t := &svcb.ALPN{Alpn: []string{"xmpp-client"}}
//	s.Value = append(s.Value, t)
type MANDATORY struct {
	Key []uint16
}

func (s *MANDATORY) String() string {
	str := make([]string, len(s.Key))
	for i, e := range s.Key {
		str[i] = KeyToString(e)
	}
	return strings.Join(str, ",")
}

func (s *MANDATORY) Len() int { return tlv + 2*len(s.Key) }

// ALPN pair is used to list supported connection protocols.
// The user of this library must ensure that at least one protocol is listed when alpn is present.
// Protocol IDs can be found at:
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
// Basic use pattern for creating an ALPN option, in a SVCB RR called s:
//
//	e := svcb.ALPN{Alpn: []string{"h2", "http/1.1"}}
//	s.Value = append(s.Value, e)
type ALPN struct {
	Alpn []string
}

func (s *ALPN) String() string {
	// An ALPN value is a comma-separated list of values, each of which can be
	// an arbitrary binary value. In order to allow parsing, the comma and
	// backslash characters are themselves escaped.
	//
	// However, this escaping is done in addition to the normal escaping which
	// happens in zone files, meaning that these values must be
	// double-escaped. This looks terrible, so if you see a never-ending
	// sequence of backslash in a zone file this may be why.
	//
	// https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-08#appendix-A.1
	var str strings.Builder
	for i, alpn := range s.Alpn {
		// 4*len(alpn) is the worst case where we escape every character in the alpn as \123, plus 1 byte for the ',' separating the alpn from others
		str.Grow(4*len(alpn) + 1)
		if i > 0 {
			str.WriteByte(',')
		}
		for j := 0; j < len(alpn); j++ {
			e := alpn[j]
			if ' ' > e || e > '~' {
				str.WriteString(ddd.Escape(e))
				continue
			}
			switch e {
			// We escape a few characters which may confuse humans or parsers.
			case '"', ';', ' ':
				str.WriteByte('\\')
				str.WriteByte(e)
			// The comma and backslash characters themselves must be
			// doubly-escaped. We use `\\` for the first backslash and
			// the escaped numeric value for the other value. We especially
			// don't want a comma in the output.
			case ',':
				str.WriteString(`\\\044`)
			case '\\':
				str.WriteString(`\\\092`)
			default:
				str.WriteByte(e)
			}
		}
	}
	return str.String()
}

func (s *ALPN) Len() int {
	var l int
	for _, e := range s.Alpn {
		l += 1 + len(e)
	}
	return l + tlv
}

// NODEFAULTALPN pair signifies no support for default connection protocols.
// Should be used in conjunction with alpn.
// Basic use pattern for creating a no-default-alpn option:
//
//	t := &svcb.ALPN{Alpn: []string{"xmpp-client"}}
//	s.Value = append(s.Value, t)
//	e := &svcb.NODEFAULTALPN{}
//	s.Value = append(s.Value, e)
type NODEFAULTALPN struct{}

func (*NODEFAULTALPN) String() string { return "" }
func (*NODEFAULTALPN) Len() int       { return tlv + 0 }

// PORT pair defines the port for connection.
// Basic use pattern for creating a port option:
//
//	s.Value = append(s.Value, &svcb.PORT{Port: 80})
type PORT struct {
	Port uint16
}

func (*PORT) Len() int         { return tlv + 2 }
func (s *PORT) String() string { return strconv.FormatUint(uint64(s.Port), 10) }

// IPV4HINT pair suggests an IPv4 address which may be used to open connections
// if A and AAAA record responses for SVCB's Target domain haven't been received.
// In that case, optionally, A and AAAA requests can be made, after which the connection
// to the hinted IP address may be terminated and a new connection may be opened.
// Basic use pattern for creating an ipv4hint option:
//
//	 h := &dns.HTTPS{Hdr: dns.Header{Name: ".", Class: dns.ClassINET}}
//	 e := &svcb.IPV4HINT{Hint: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
//
//	Or
//
//	 e.Hint = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
//	 h.Value = append(h.Value, e)
type IPV4HINT struct {
	Hint []netip.Addr
}

func (s *IPV4HINT) Len() int { return tlv + 4*len(s.Hint) }

func (s *IPV4HINT) String() string {
	str := make([]string, len(s.Hint))
	for i, e := range s.Hint {
		if !e.IsValid() || !e.Is4() {
			return "<nil>"
		}
		str[i] = e.String()
	}
	return strings.Join(str, ",")
}

// ECHCONFIG pair contains the ECHConfig structure defined in draft-ietf-tls-esni [RFC xxxx].
// Basic use pattern for creating an ech option:
//
//	h := &dns.HTTPS{Hdr: dns.Header{Name: ".", Class: dns.ClassINET}}
//	e := &svcb.ECHCONFIG{ECH: []byte{0xfe, 0x08, ...}}
//	h.Value = append(h.Value, e)
type ECHCONFIG struct {
	ECH []byte // Specifically ECHConfigList including the redundant length prefix.
}

func (s *ECHCONFIG) String() string { return base64.StdEncoding.EncodeToString(s.ECH) }
func (s *ECHCONFIG) Len() int       { return tlv + len(s.ECH) }

// IPV6HINT pair suggests an IPv6 address which may be used to open connections
// if A and AAAA record responses for SVCB's Target domain haven't been received.
// In that case, optionally, A and AAAA requests can be made, after which the
// connection to the hinted IP address may be terminated and a new connection may be opened.
// Basic use pattern for creating an ipv6hint option:
//
//	h := &dns.HTTPS{Hdr: dns.Header{Name: ".", Class: dns.ClassINET}}
//	e := &svcb.IPV6HINT{Hint: []netip.Addr{netip.MustParseAddr("2001:db8::1")}}
//	h.Value = append(h.Value, e)
type IPV6HINT struct {
	Hint []netip.Addr
}

func (s *IPV6HINT) Len() int { return tlv + 16*len(s.Hint) }

func (s *IPV6HINT) String() string {
	str := make([]string, len(s.Hint))
	for i, e := range s.Hint {
		if e.Is4() {
			return "<nil>"
		}
		str[i] = e.String()
	}
	return strings.Join(str, ",")
}

// DOHPATH pair is used to indicate the URI template that the
// clients may use to construct a DNS over HTTPS URI.
//
// See RFC 9461 (https://datatracker.ietf.org/doc/html/rfc9461)
// and RFC 9462 (https://datatracker.ietf.org/doc/html/rfc9462).
//
// A basic example of using the dohpath option together with the alpn
// option to indicate support for DNS over HTTPS on a certain path:
//
//	e := &svcb.ALPN{Alpn: []string{"h2", "h3"}}
//	p := &svcb.DOHPATH{Template: "/dns-query{?dns}"}
//	s.Value = append(s.Value, e, p)
//
// The parsing currently doesn't validate that Template is a valid RFC 6570 URI template.
type DOHPATH struct {
	Template string
}

func (s *DOHPATH) String() string { return pairToString([]byte(s.Template)) }
func (s *DOHPATH) Len() int       { return tlv + len(s.Template) }

// The "ohttp" SvcParamKey is used to indicate that a service described in a SVCB RR
// can be accessed as a target using an associated gateway.
// Both the presentation and wire-format values for the "ohttp" parameter MUST be empty.
//
// See RFC 9460 (https://datatracker.ietf.org/doc/html/rfc9460/)
// and RFC 9230 (https://datatracker.ietf.org/doc/html/rfc9230/)
//
// A basic example of using the dohpath option together with the alpn
// option to indicate support for DNS over HTTPS on a certain path:
//
//	e := &dns.ALPN{Alpn: []string{"h2", "h3"}}
//	p := &svcb.OHTTP{}
//	s.Value = append(s.Value, e, p)
type OHTTP struct{}

func (*OHTTP) String() string { return "" }
func (*OHTTP) Len() int       { return tlv + 0 }

// LOCAL pair is intended for experimental/private use. The key is recommended
// to be in the range [65280, 65534], see Section 14.3.2. of RFC 9460.
// Basic use pattern for creating a keyNNNNN option:
//
//	h := &dns.HTTPS{Hdr: dns.Header{Name: ".", Class: dns.ClassINET}}
//	e := &svcb.LOCAL{KeyCode: 65400, Data: []byte("abc")}
//	h.Value = append(h.Value, e)
type LOCAL struct {
	KeyCode uint16 // Just like as in RFC 5559.
	Data    []byte // All byte sequences are allowed.
}

func (s *LOCAL) String() string { return pairToString(s.Data) }
func (s *LOCAL) Len() int       { return tlv + len(s.Data) }

func (s *MANDATORY) Clone() Pair   { return &MANDATORY{slices.Clone(s.Key)} }
func (s *ALPN) Clone() Pair        { return &ALPN{slices.Clone(s.Alpn)} }
func (*NODEFAULTALPN) Clone() Pair { return &NODEFAULTALPN{} }
func (s *PORT) Clone() Pair        { return &PORT{s.Port} }
func (s *ECHCONFIG) Clone() Pair   { return &ECHCONFIG{slices.Clone(s.ECH)} }
func (*OHTTP) Clone() Pair         { return &OHTTP{} }
func (s *DOHPATH) Clone() Pair     { return &DOHPATH{Template: s.Template} }
func (s *LOCAL) Clone() Pair       { return &LOCAL{s.KeyCode, slices.Clone(s.Data)} }

func (s *IPV4HINT) Clone() Pair {
	return &IPV4HINT{Hint: slices.Clone(s.Hint)}
}

func (s *IPV6HINT) Clone() Pair {
	return &IPV6HINT{Hint: slices.Clone(s.Hint)}
}

const tlv = 4
