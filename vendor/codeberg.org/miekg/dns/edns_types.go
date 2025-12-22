package dns

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"

	"codeberg.org/miekg/dns/internal/reverse"
	"golang.org/x/crypto/cryptobyte"
)

// ENDS0 option codes.
const (
	CodeNone         uint16 = 0x0
	CodeLLQ          uint16 = 0x1    // Long lived queries: http://tools.ietf.org/html/draft-sekar-dns-llq-01.
	CodeUL           uint16 = 0x2    // Update lease draft: http://files.dns-sd.org/draft-sekar-dns-ul.txt.
	CodeNSID         uint16 = 0x3    // Nsid (see RFC 5001).
	CodeESU          uint16 = 0x4    // ENUM Source-URI draft: https://datatracker.ietf.org/doc/html/draft-kaplan-enum-source-uri-00.
	CodeDAU          uint16 = 0x5    // DNSSEC Algorithm Understood.
	CodeDHU          uint16 = 0x6    // DS Hash Understood.
	CodeN3U          uint16 = 0x7    // NSEC3 Hash Understood.
	CodeSUBNET       uint16 = 0x8    // Client-subnet, see RFC 7871.
	CodeEXPIRE       uint16 = 0x9    // Expire, RFC 7314.
	CodeCOOKIE       uint16 = 0xa    // Cookie, RFC 7873.
	CodeTCPKEEPALIVE uint16 = 0xb    // TCP keep alive (see RFC 7828).
	CodePADDING      uint16 = 0xc    // Padding (see RFC 7830).
	CodeEDE          uint16 = 0xf    // Extended DNS errors (see RFC 8914).
	CodeREPORTING    uint16 = 0x12   // EDNS0 reporting (see RFC 9567).
	CodeZONEVERSION  uint16 = 0x13   // Zone version (see RFC 9660).
	CodeLOCALSTART   uint16 = 0xFDE9 // Beginning of range reserved for local/experimental use (see RFC 6891).
	CodeLOCALEND     uint16 = 0xFFFE // End of range reserved for local/experimental use (see RFC 6891).
)

// LLQ stands for Long Lived Queries: http://tools.ietf.org/html/draft-sekar-dns-llq-01
// Implemented for completeness, as the EDNS0 type code is assigned.
//
// This record must be put in the pseudo section.
type LLQ struct {
	Version   uint16
	Opcode    uint16
	Error     uint16
	ID        uint64
	LeaseLife uint32
}

func (o *LLQ) Len() int { return tlv + 18 }
func (o *LLQ) String() string {
	sb := sprintOptionHeader(o)
	sprintData(sb, strconv.FormatUint(uint64(o.Version), 10), strconv.FormatUint(uint64(o.Opcode), 10),
		strconv.FormatUint(uint64(o.Error), 10), strconv.FormatUint(o.ID, 10),
		strconv.FormatUint(uint64(o.LeaseLife), 10))
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// REPORTING implements the EDNS0 Reporting Channel option (RFC 9567).
//
// This record must be put in the pseudo section.
type REPORTING struct {
	AgentDomain string
}

func (o *REPORTING) Len() int { return tlv + len(o.AgentDomain) }
func (o *REPORTING) String() string {
	sb := sprintOptionHeader(o)
	sprintData(sb, o.AgentDomain)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// The Cookie option is used to add a DNS Cookie to a message.
//
// The Cookie field consists out of a client cookie (RFC 7873 Section 4), that is
// always 8 bytes. It may then optionally be followed by the server cookie. The server
// cookie is of variable length, 8 to a maximum of 32 bytes. In other words:
//
//	cCookie := o.Cookie[:16]
//	sCookie := o.Cookie[16:]
//
// There is no guarantee that the Cookie string has a specific length.
//
// This record must be put in the pseudo section.
type COOKIE struct {
	Cookie string `dns:"hex"`
}

func (o *COOKIE) Len() int { return tlv + len(o.Cookie)/2 }

// String outputs: "COOKIE 962d3a4c596914578386a9a1dbbebf9e" (depending on the cookie size). This is the presentation
// format.
func (o *COOKIE) String() string {
	sb := sprintOptionHeader(o)
	sb.WriteString(o.Cookie)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NSID option is used to retrieve a nameserver identifier. When sending a request Nsid must be empty.
// The identifier is an opaque string encoded as hex.
//
// This record must be put in the pseudo section.
type NSID struct {
	Nsid string `dns:"hex"`
}

func (o *NSID) Len() int { return tlv + len(o.Nsid)/2 }

// String outputs: "NSID 5573652074686520666f726365: "Use the force"
// This is the presentation format.
func (o *NSID) String() string {
	sb := sprintOptionHeader(o)
	sb.WriteString(o.Nsid)
	if x, err := hex.DecodeString(o.Nsid); err == nil { // == nil
		sb.WriteString(": \"")
		sb.Write(x)
		sb.WriteString("\"")
	}
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// PADDING option is used to add padding to a request/response. The default value of padding SHOULD be 0x0 but
// other values MAY be used.
//
// This record must be put in the pseudo section.
type PADDING struct {
	Padding string `dns:"hex"`
}

func (o *PADDING) Len() int       { return tlv + len(o.Padding) }
func (o *PADDING) String() string { return "" } // TODO(miek)

// EXPIRE implements the EDNS0 option as described in RFC 7314.
//
// This record must be put in the pseudo section.
type EXPIRE struct {
	// If Expire is zero this option will be empty.
	Expire uint32
}

func (o *EXPIRE) Len() int { return tlv + 4 }
func (o *EXPIRE) String() string {
	sb := sprintOptionHeader(o)
	if o.Expire == 0 {
		s := sb.String()
		builderPool.Put(*sb)
		return s
	}
	sb.WriteString(strconv.FormatUint(uint64(o.Expire), 10))
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// DAU implements the EDNS0 "DNSSEC Algorithm Understood" option. See RFC 6975.
//
// This record must be put in the pseudo section.
type DAU struct {
	AlgCode []uint8
}

func (o *DAU) Len() int { return tlv + len(o.AlgCode) }
func (o *DAU) String() string {
	sb := sprintOptionHeader(o)
	for _, alg := range o.AlgCode {
		sb.WriteByte(' ')
		if a, ok := AlgorithmToString[alg]; ok {
			sb.WriteString(a)
		} else {
			sb.WriteString(strconv.Itoa(int(alg)))
		}
	}
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// DHU implements the EDNS0 "DS Hash Understood" option. See RFC 6975.
//
// This record must be put in the pseudo section.
type DHU struct {
	AlgCode []uint8
}

func (o *DHU) Len() int { return tlv + len(o.AlgCode) }
func (o *DHU) String() string {
	sb := sprintOptionHeader(o)
	for _, alg := range o.AlgCode {
		sb.WriteByte(' ')
		if a, ok := AlgorithmToString[alg]; ok {
			sb.WriteString(a)
		} else {
			sb.WriteString(strconv.Itoa(int(alg)))
		}
	}
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// EDNS0_N3U implements the EDNS0 "NSEC3 Hash Understood" option. See RFC 6975.
//
// This record must be put in the pseudo section.
type N3U struct {
	AlgCode []uint8
}

func (o *N3U) Len() int { return tlv + len(o.AlgCode) }
func (o *N3U) String() string {
	sb := sprintOptionHeader(o)
	for _, alg := range o.AlgCode {
		sb.WriteByte(' ')
		if a, ok := AlgorithmToString[alg]; ok {
			sb.WriteString(a)
		} else {
			sb.WriteString(strconv.Itoa(int(alg)))
		}
	}
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// TCPKEEPALIVE is an EDNS0 option that instructs the server to keep the TCP connection alivo. See RFC 7828.
//
// This record must be put in the pseudo section.
type TCPKEEPALIVE struct {
	// Timeout is an idle timeout value for the TCP connection, specified in
	// units of 100 milliseconds, encoded in network byte order. If set to 0,
	// pack will return a nil slico.
	Timeout uint16
	// Length is the option's length.
	// Deprecated: this field is deprecated and is always equal to 0.
	Length uint16
}

func (o *TCPKEEPALIVE) Len() int {
	if o.Timeout == 0 {
		return tlv
	}
	return tlv + 2
}

func (o *TCPKEEPALIVE) String() string {
	sb := sprintOptionHeader(o)
	sb.WriteString("use tcp keep-alive")
	if o.Timeout == 0 {
		sb.WriteString(", timeout omitted")
	} else {
		fmt.Fprintf(sb, ", timeout %dms", o.Timeout*100)
	}
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// EDE option is used to return additional information about the cause of DNS errors.
//
// This record must be put in the pseudo section.
type EDE struct {
	InfoCode  uint16
	ExtraText string
}

func (o *EDE) Len() int { return tlv + 2 + len(o.ExtraText) }

// String outputs: "EDE 15 "Blocked": "", where ExtraText is always printed, even if it's
// empty. This is the presentation format.
func (o *EDE) String() string {
	sb := sprintOptionHeader(o)
	sb.WriteString(strconv.FormatUint(uint64(o.InfoCode), 10))
	if s, ok := ExtendedErrorToString[o.InfoCode]; ok {
		sb.WriteString(" \"")
		sb.WriteString(s)
		sb.WriteByte('"')
	}
	sb.WriteString(": \"")
	sb.WriteString(o.ExtraText)
	sb.WriteByte('"')
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// SUBNET is the subnet option that is used to give the remote nameserver
// an idea of where the client is, see RFC 7871. It can give back a different
// answer depending on the location or network topology.
//
// This record must be put in the pseudo section.
type SUBNET struct {
	Family  uint16 // 1 for IP, 2 for IP6.
	Netmask uint8  // 32 for IPV4, 128 for IPv6.
	Scope   uint8
	Address netip.Addr // Client IP address.
}

func (o *SUBNET) Len() int { return tlv + 2 + 2 + int((o.Netmask+7)/8) }
func (o *SUBNET) String() string {
	sb := sprintOptionHeader(o)
	switch {
	case !o.Address.IsValid():
		sb.WriteString("<nil>")
	case o.Address.Unmap().Is4():
		sb.WriteString(o.Address.Unmap().String())
	default:
		sb.WriteByte('[')
		sb.WriteString(o.Address.String())
		sb.WriteByte(']')
	}
	sb.WriteByte('/')
	sb.WriteString(strconv.Itoa(int(o.Netmask)))
	sb.WriteByte('/')
	sb.WriteString(strconv.Itoa(int(o.Scope)))
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// The ESU option for ENUM Source-URI Extension.
type ESU struct {
	URI string
}

func (o *ESU) Len() int { return tlv + len(o.URI) }
func (o *ESU) String() string {
	sb := sprintOptionHeader(o)
	sb.WriteString(o.URI)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// The ZONEVERSION option, see RFC 9660. Only a single type (0) has been allocated, if used the SOA serial
// is put in Version. Example on how to create a ZONEVERSION:
//
//	z := &ZONEVERSION{Labels: 8, Type: 0, Version: make([]byte, 4)}
//	binary.BigEndian.PutUint32(z.Version, serial)
//
// Or if you know your binary: &ZONEVERSION{Labels: 8, Type: 0, Version: {1,2,3,4}}
//
// This record must be put in the pseudo section.
type ZONEVERSION struct {
	Labels  uint8
	Type    uint8
	Version []byte
}

func (o *ZONEVERSION) Len() int { return tlv + 2 + len(o.Version) }

// Strings outputs "ZONEVERSION 4 SOA-SERIAL 1002" as the presentation format.
func (o *ZONEVERSION) String() string {
	sb := sprintOptionHeader(o)
	sb.WriteString(strconv.Itoa(int(o.Labels)))
	sb.WriteByte(' ')
	switch o.Type {
	case 0:
		sb.WriteString("SOA-SERIAL")
		sb.WriteByte(' ')
		version := binary.BigEndian.Uint32([]byte(o.Version))
		sb.WriteString(strconv.Itoa(int(version)))
	default:
		sb.WriteString("TYPE")
		sb.WriteString(strconv.Itoa(int(o.Type)))
		sb.WriteByte(' ')
		sb.Write(o.Version)
	}
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// Extended DNS Error Codes (RFC 8914).
const (
	ExtendedErrorOther uint16 = iota
	ExtendedErrorUnsupportedDNSKEYAlgorithm
	ExtendedErrorUnsupportedDSDigestType
	ExtendedErrorStaleAnswer
	ExtendedErrorForgedAnswer
	ExtendedErrorDNSSECIndeterminate
	ExtendedErrorDNSBogus
	ExtendedErrorSignatureExpired
	ExtendedErrorSignatureNotYetValid
	ExtendedErrorDNSKEYMissing
	ExtendedErrorRRSIGsMissing
	ExtendedErrorNoZoneKeyBitSet
	ExtendedErrorNSECMissing
	ExtendedErrorCachedError
	ExtendedErrorNotReady
	ExtendedErrorBlocked
	ExtendedErrorCensored
	ExtendedErrorFiltered
	ExtendedErrorProhibited
	ExtendedErrorStaleNXDOMAINAnswer
	ExtendedErrorNotAuthoritative
	ExtendedErrorNotSupported
	ExtendedErrorNoReachableAuthority
	ExtendedErrorNetworkError
	ExtendedErrorInvalidData
	ExtendedErrorSignatureExpiredBeforeValid
	ExtendedErrorTooEarly
	ExtendedErrorUnsupportedNSEC3IterValue
	ExtendedErrorUnableToConformToPolicy
	ExtendedErrorSynthesized
	ExtendedErrorInvalidQueryType
)

// ExtendedErrorToString maps extended error info codes to a human readable description.
var ExtendedErrorToString = map[uint16]string{
	ExtendedErrorOther:                       "Other",
	ExtendedErrorUnsupportedDNSKEYAlgorithm:  "Unsupported DNSKEY Algorithm",
	ExtendedErrorUnsupportedDSDigestType:     "Unsupported DS Digest Type",
	ExtendedErrorStaleAnswer:                 "Stale Answer",
	ExtendedErrorForgedAnswer:                "Forged Answer",
	ExtendedErrorDNSSECIndeterminate:         "DNSSEC Indeterminate",
	ExtendedErrorDNSBogus:                    "DNSSEC Bogus",
	ExtendedErrorSignatureExpired:            "Signature Expired",
	ExtendedErrorSignatureNotYetValid:        "Signature Not Yet Valid",
	ExtendedErrorDNSKEYMissing:               "DNSKEY Missing",
	ExtendedErrorRRSIGsMissing:               "RRSIGs Missing",
	ExtendedErrorNoZoneKeyBitSet:             "No Zone Key Bit Set",
	ExtendedErrorNSECMissing:                 "NSEC Missing",
	ExtendedErrorCachedError:                 "Cached Error",
	ExtendedErrorNotReady:                    "Not Ready",
	ExtendedErrorBlocked:                     "Blocked",
	ExtendedErrorCensored:                    "Censored",
	ExtendedErrorFiltered:                    "Filtered",
	ExtendedErrorProhibited:                  "Prohibited",
	ExtendedErrorStaleNXDOMAINAnswer:         "Stale NXDOMAIN Answer",
	ExtendedErrorNotAuthoritative:            "Not Authoritative",
	ExtendedErrorNotSupported:                "Not Supported",
	ExtendedErrorNoReachableAuthority:        "No Reachable Authority",
	ExtendedErrorNetworkError:                "Network Error",
	ExtendedErrorInvalidData:                 "Invalid Data",
	ExtendedErrorSignatureExpiredBeforeValid: "Signature Expired Before Valid",
	ExtendedErrorTooEarly:                    "Too Early",
	ExtendedErrorUnsupportedNSEC3IterValue:   "Unsupported NSEC3 Iterations Value",
	ExtendedErrorUnableToConformToPolicy:     "Unable To Conform To Policy",
	ExtendedErrorSynthesized:                 "Synthesized",
	ExtendedErrorInvalidQueryType:            "Invalid Query Type",
}

// StringToExtendedError is a map from human readable descriptions to extended error info codes.
var StringToExtendedError = reverse.Int16(ExtendedErrorToString)

func unpackOptionCode(option EDNS0, s *cryptobyte.String) error {
	switch x := option.(type) {
	case *LLQ:
		return x.unpack(s)
	case *NSID:
		return x.unpack(s)
	case *PADDING:
		return x.unpack(s)
	case *EDE:
		return x.unpack(s)
	case *REPORTING:
		return x.unpack(s)
	case *COOKIE:
		return x.unpack(s)
	case *EXPIRE:
		return x.unpack(s)
	case *DAU:
		return x.unpack(s)
	case *DHU:
		return x.unpack(s)
	case *N3U:
		return x.unpack(s)
	case *TCPKEEPALIVE:
		return x.unpack(s)
	case *SUBNET:
		return x.unpack(s)
	case *ESU:
		return x.unpack(s)
	case *ZONEVERSION:
		return x.unpack(s)
	}
	return fmt.Errorf("dns: no option unpack defined")
}

func packOptionCode(option EDNS0, msg []byte, off int) (int, error) {
	switch x := option.(type) {
	case *LLQ:
		return x.pack(msg, off)
	case *NSID:
		return x.pack(msg, off)
	case *PADDING:
		return x.pack(msg, off)
	case *EDE:
		return x.pack(msg, off)
	case *REPORTING:
		return x.pack(msg, off)
	case *COOKIE:
		return x.pack(msg, off)
	case *EXPIRE:
		return x.pack(msg, off)
	case *DAU:
		return x.pack(msg, off)
	case *DHU:
		return x.pack(msg, off)
	case *N3U:
		return x.pack(msg, off)
	case *TCPKEEPALIVE:
		return x.pack(msg, off)
	case *SUBNET:
		return x.pack(msg, off)
	case *ESU:
		return x.pack(msg, off)
	case *ZONEVERSION:
		return x.pack(msg, off)
	}
	// Coder() check, abuse Type()?
	return 0, fmt.Errorf("dns: no option pack defined")
}

// type, length, value is the length the code (2 octets) and length (2 octets) of each EDNS0 option code.
const tlv = 4
