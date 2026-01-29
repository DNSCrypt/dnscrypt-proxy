// Package deleg deals with all the intricacies of the DELEG RR. All the sub-types ([Info]) used in the RR are defined here.
// As DELEG is derived from the SVCB RR so there are a lot of similarities. This implements draft version -03
// and higher.
package deleg

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/internal/reverse"
)

// Keys as defined in the DELEG draft.
const (
	KeyServerIPv4 uint16 = iota + 1
	KeyServerIPv6
	KeyServerName
	KeyIncludeDelegi

	KeyReserved uint16 = 65535
)

// Info defines a key=value pair for the DELEG/DELEGI RR type. A DELEG RR can have multiple infos appended to it.
// The numerical key code is derived from the type, see [InfoToKey].
type Info interface {
	String() string // String returns the string representation of the value.
	Len() int       // Len returns the length of value in the wire format.
	Clone() Info    // Clone returns a deep copy of the Info.
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
	KeyServerIPv4:    "server-ipv4",
	KeyServerIPv6:    "server-ipv6",
	KeyServerName:    "server-name",
	KeyIncludeDelegi: "include-delegi",
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

var stringToKey = reverse.Map(keyToString)

// KeyToInfo convert the key value to a Info.
func KeyToInfo(k uint16) func() Info {
	switch k {
	case KeyServerIPv4:
		return func() Info { return new(SERVERIPV4) }
	case KeyServerIPv6:
		return func() Info { return new(SERVERIPV6) }
	case KeyServerName:
		return func() Info { return new(SERVERNAME) }
	case KeyIncludeDelegi:
		return func() Info { return new(INCLUDEDELEGI) }
	default:
		return nil
	}
}

// InfoToKey is the reverse of KeyToInfo.
func InfoToKey(i Info) uint16 {
	switch i.(type) {
	case *SERVERIPV4:
		return KeyServerIPv4
	case *SERVERIPV6:
		return KeyServerIPv6
	case *SERVERNAME:
		return KeyServerName
	case *INCLUDEDELEGI:
		return KeyIncludeDelegi
	}
	return KeyReserved
}

// SERVERNAME info add nameserver hosts names to the DELEG RR.
type SERVERNAME struct {
	Hostnames []string `dns:"domain-name"`
}

func (s *SERVERNAME) String() string { return strings.Join(s.Hostnames, ",") }

func (s *SERVERNAME) Len() int {
	l := tlv
	for i := range s.Hostnames {
		l += len(s.Hostnames[i]) + 1
	}
	return l
}

// INCLUDEDELEGI info adds DELEGI domains to the DELEG RR.
type INCLUDEDELEGI struct {
	Domains []string `dns:"domain-name"`
}

func (s *INCLUDEDELEGI) String() string { return strings.Join(s.Domains, ",") }

func (s *INCLUDEDELEGI) Len() int {
	l := tlv
	for i := range s.Domains {
		l += len(s.Domains[i]) + 1
	}
	return l
}

// SERVERIPV4 info adds IPv4 addresses to the DELEG RR.
type SERVERIPV4 struct {
	IPs []netip.Addr
}

func (s *SERVERIPV4) Len() int { return tlv + 4*len(s.IPs) }

func (s *SERVERIPV4) String() string {
	str := make([]string, len(s.IPs))
	for i, e := range s.IPs {
		str[i] = e.String()
	}
	return strings.Join(str, ",")
}

// SERVERIPV6 info adds IPv6 addresses to the DELEG RR.
type SERVERIPV6 struct {
	IPs []netip.Addr
}

func (s *SERVERIPV6) Len() int { return tlv + 16*len(s.IPs) }

func (s *SERVERIPV6) String() string {
	str := make([]string, len(s.IPs))
	for i, e := range s.IPs {
		str[i] = e.String()
	}
	return strings.Join(str, ",")
}

const tlv = 4

func (s *SERVERIPV4) Clone() Info    { return &SERVERIPV4{slices.Clone(s.IPs)} }
func (s *SERVERIPV6) Clone() Info    { return &SERVERIPV6{slices.Clone(s.IPs)} }
func (s *SERVERNAME) Clone() Info    { return &SERVERNAME{slices.Clone(s.Hostnames)} }
func (s *INCLUDEDELEGI) Clone() Info { return &INCLUDEDELEGI{slices.Clone(s.Domains)} }
