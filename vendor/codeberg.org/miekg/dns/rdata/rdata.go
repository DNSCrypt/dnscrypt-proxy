// Package rdata contains the rdata elements of all the resource records, each type that implements
// [codeberg.org/miekg/dns.RR].
//
// Each rdata elements implements [codeberg.org/miek/dns.RDATA]. And thus the [fmt.Stringer] interface. To
// full print the text reprentation use the following:
//
//	 mx := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET, TTL: 3600},
//			       MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}
//	 fmt.Printf("%s %s\t%s", mx.Header(), dnsutil.TypeToString(dns.RRToType(mx)), mx.Data())
package rdata

import (
	"net/netip"

	"codeberg.org/miekg/dns/deleg"
	"codeberg.org/miekg/dns/svcb"
)

//go:generate go run len_generate.go

// NULL data. See RFC 1035.
type NULL struct {
	Null string `dns:"any"`
}

// CNAME data. See RFC 1034.
type CNAME struct {
	Target string `dns:"cdomain-name"`
}

// HINFO data. See RFC 1034.
type HINFO struct {
	Cpu string
	Os  string
}

// MB data. See RFC 1035.
type MB struct {
	Mb string `dns:"cdomain-name"`
}

// MG data. See RFC 1035.
type MG struct {
	Mg string `dns:"cdomain-name"`
}

// MINFO data. See RFC 1035.
type MINFO struct {
	Rmail string `dns:"cdomain-name"`
	Email string `dns:"cdomain-name"`
}

// MR data. See RFC 1035.
type MR struct {
	Mr string `dns:"cdomain-name"`
}

// MF data. See RFC 1035.
type MF struct {
	Mf string `dns:"cdomain-name"`
}

// MD data. See RFC 1035.
type MD struct {
	Md string `dns:"cdomain-name"`
}

// MX data. See RFC 1035.
type MX struct {
	Preference uint16
	Mx         string `dns:"cdomain-name"`
}

// AFSDB data. See RFC 1183.
type AFSDB struct {
	Subtype  uint16
	Hostname string `dns:"domain-name"`
}

// X25 data. See RFC 1183, Section 3.1.
type X25 struct {
	PSDNAddress string
}

// ISDN data. See RFC 1183, Section 3.2.
type ISDN struct {
	Address    string
	SubAddress string
}

// RT data. See RFC 1183, Section 3.3.
type RT struct {
	Preference uint16
	Host       string `dns:"domain-name"` // RFC 3597 prohibits compressing records not defined in RFC 1035.
}

// NS data. See RFC 1035.
type NS struct {
	Ns string `dns:"cdomain-name"`
}

// PTR data. See RFC 1035.
type PTR struct {
	Ptr string `dns:"cdomain-name"`
}

// RP data. See RFC 1138, Section 2.2.
type RP struct {
	Mbox string `dns:"domain-name"`
	Txt  string `dns:"domain-name"`
}

// SOA data. See RFC 1035.
type SOA struct {
	Ns      string `dns:"cdomain-name"`
	Mbox    string `dns:"cdomain-name"`
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minttl  uint32
}

// TXT data. See RFC 1035.
type TXT struct {
	Txt []string `dns:"txt"`
}

// IPN data. See https://www.iana.org/assignments/dns-parameters/IPN/ipn-completed-template.
type IPN struct {
	Node uint64
}

// SRV data. See RFC 2782.
type SRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string `dns:"domain-name"`
}

// NAPTR data. See RFC 2915.
type NAPTR struct {
	Order       uint16
	Preference  uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement string `dns:"domain-name"`
}

// CERT data. See RFC 4398.
type CERT struct {
	Type        uint16
	KeyTag      uint16
	Algorithm   uint8
	Certificate string `dns:"base64"`
}

// DNAME data. See RFC 2672.
type DNAME struct {
	Target string `dns:"domain-name"`
}

// A data. See RFC 1035.
type A struct {
	Addr netip.Addr `dns:"a"`
}

// AAAA data. See RFC 3596.
type AAAA struct {
	Addr netip.Addr `dns:"aaaa"`
}

// PX data. See RFC 2163.
type PX struct {
	Preference uint16
	Map822     string `dns:"domain-name"`
	Mapx400    string `dns:"domain-name"`
}

// GPOS data. See RFC 1712.
type GPOS struct {
	Longitude string
	Latitude  string
	Altitude  string
}

// LOC data. See RFC 1876.
type LOC struct {
	Version   uint8
	Size      uint8
	HorizPre  uint8
	VertPre   uint8
	Latitude  uint32
	Longitude uint32
	Altitude  uint32
}

// RRSIG data. See RFC 4034 and RFC 3755.
type RRSIG struct {
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OrigTTL     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string `dns:"domain-name"`
	Signature   string `dns:"base64"`
}

// NSEC data. See RFC 4034 and RFC 3755.
type NSEC struct {
	NextDomain string   `dns:"domain-name"`
	TypeBitMap []uint16 `dns:"nsec"`
}

func (rd NSEC) Len() int {
	l := len(rd.NextDomain) + 1
	l += typeBitMapLen(rd.TypeBitMap)
	return l
}

// DS data. See RFC 4034 and RFC 3658.
type DS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

// KX data. See RFC 2230.
type KX struct {
	Preference uint16
	Exchanger  string `dns:"domain-name"`
}

// TA data. See http://www.watson.org/~weiler/INI1999-19.pdf.
type TA struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string `dns:"hex"`
}

// TALINK data. See https://www.iana.org/assignments/dns-parameters/TALINK/talink-completed-template.
type TALINK struct {
	PreviousName string `dns:"domain-name"`
	NextName     string `dns:"domain-name"`
}

// SSHFP data. See RFC 4255.
type SSHFP struct {
	Algorithm   uint8
	Type        uint8
	FingerPrint string `dns:"hex"`
}

// DNSKEY data. See RFC 4034 and RFC 3755.
type DNSKEY struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string `dns:"base64"`
}

// RKEY data. See https://www.iana.org/assignments/dns-parameters/RKEY/rkey-completed-template.
type RKEY struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string `dns:"base64"`
}

// NSAPPTR data. See RFC 1348.
type NSAPPTR struct {
	Ptr string `dns:"domain-name"`
}

// NSEC3 data. See RFC 5155.
type NSEC3 struct {
	Hash       uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8
	Salt       string `dns:"size-hex:SaltLength"`
	HashLength uint8
	NextDomain string   `dns:"size-base32:HashLength"`
	TypeBitMap []uint16 `dns:"nsec"`
}

func (rd NSEC3) Len() int {
	l := 6 + len(rd.Salt)/2 + 1 + len(rd.NextDomain) + 1
	l += typeBitMapLen(rd.TypeBitMap)
	return l
}

// NSEC3PARAM data. See RFC 5155.
type NSEC3PARAM struct {
	Hash       uint8
	Flags      uint8
	Iterations uint16
	SaltLength uint8
	Salt       string `dns:"size-hex:SaltLength"`
}

// TKEY data. See RFC 2930.
type TKEY struct {
	Algorithm  string `dns:"domain-name"`
	Inception  uint32
	Expiration uint32
	Mode       uint16
	Error      uint16
	KeySize    uint16
	Key        string `dns:"size-hex:KeySize"`
	OtherLen   uint16
	OtherData  string `dns:"size-hex:OtherLen"`
}

// RFC3597 represents an unknown/generic data. See RFC 3597.
type RFC3597 struct {
	RRType uint16 `dns:"-"` // actual type
	Data   string `dns:"hex"`
}

// URI data. See RFC 7553.
type URI struct {
	Priority uint16
	Weight   uint16
	Target   string `dns:"any"` // Target is to be parsed as a sequence of character encoded octets according to RFC 3986.
}

// DHCID data. See RFC 4701.
type DHCID struct {
	Digest string `dns:"base64"`
}

// TLSA data. See RFC 6698.
type TLSA struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  string `dns:"hex"`
}

// SMIMEA data. See RFC 8162.
type SMIMEA struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  string `dns:"hex"`
}

// HIP data. See RFC 8005.
type HIP struct {
	HitLength          uint8
	PublicKeyAlgorithm uint8
	PublicKeyLength    uint16
	Hit                string   `dns:"size-hex:HitLength"`
	PublicKey          string   `dns:"size-base64:PublicKeyLength"`
	RendezvousServers  []string `dns:"domain-name"`
}

// NINFO data. See https://www.iana.org/assignments/dns-parameters/NINFO/ninfo-completed-template.
type NINFO struct {
	ZSData []string `dns:"txt"`
}

// NID data. See RFC 6742.
type NID struct {
	Preference uint16
	NodeID     uint64
}

// L32 data, See RFC 6742.
type L32 struct {
	Preference uint16
	Locator32  netip.Addr `dns:"a"`
}

// L64 data, See RFC 6742.
type L64 struct {
	Preference uint16
	Locator64  uint64
}

// LP data. See RFC 6742.
type LP struct {
	Preference uint16
	Fqdn       string `dns:"domain-name"`
}

type EUI48 struct {
	Address uint64 `dns:"uint48"`
}

// EUI64 data. See RFC 7043.
type EUI64 struct {
	Address uint64
}

// CAA data. See RFC 6844.
type CAA struct {
	Flag  uint8
	Tag   string
	Value string `dns:"any"` // Value is the character-string encoding of the value field as specified in RFC 1035, Section 5.1.
}

// UID data. Deprecated, IANA-Reserved.
type UID struct {
	Uid uint32
}

// GID data. Deprecated, IANA-Reserved.
type GID struct {
	Gid uint32
}

// UINFO data. Deprecated, IANA-Reserved.
type UINFO struct {
	Uinfo string
}

// EID data. See http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt.
type EID struct {
	Endpoint string `dns:"hex"`
}

// NIMLOC data. See http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt.
type NIMLOC struct {
	Locator string `dns:"hex"`
}

// OPENPGPKEY data. See RFC 7929.
type OPENPGPKEY struct {
	PublicKey string `dns:"base64"`
}

// CSYNC data. See RFC 7477.
type CSYNC struct {
	Serial     uint32
	Flags      uint16
	TypeBitMap []uint16 `dns:"nsec"`
}

func (rd CSYNC) Len() int {
	l := 4 + 2
	l += typeBitMapLen(rd.TypeBitMap)
	return l
}

// ZONEMD data, RFC 8976.
type ZONEMD struct {
	Serial uint32
	Scheme uint8
	Hash   uint8
	Digest string `dns:"hex"`
}

// SVCB data. See RFC 9460.
type SVCB struct {
	Priority uint16      // If zero, Value must be empty or discarded by the user of this library.
	Target   string      `dns:"domain-name"`
	Value    []svcb.Pair `dns:"pairs"`
}

// DELEG data. See draft https://datatracker.ietf.org/doc/draft-ietf-deleg/.
type DELEG struct {
	Value []deleg.Info `dns:"infos"`
}

// DYNC data. See RFC 9859.
type DSYNC struct {
	Type   uint16
	Scheme uint8
	Port   uint16
	Target string `dns:"domain-name"`
}

// TSIG data.
type TSIG struct {
	Algorithm  string `dns:"domain-name"` // Algorithm is encoded as a name, see HmacSHAXXX contstants.
	TimeSigned uint64 `dns:"uint48"`
	Fudge      uint16
	MACSize    uint16
	MAC        string `dns:"size-hex:MACSize"`
	OrigID     uint16 // OrigID is the original message ID, when creating a TSIG this should be set to the message ID.
	Error      uint16
	OtherLen   uint16
	OtherData  string `dns:"size-hex:OtherLen"`
}

// typeBitMapLen is a helper function which computes the "maximum" length of
// a the NSEC Type BitMap field.
func typeBitMapLen(bitmap []uint16) int {
	var l int
	var lastwindow, lastlength uint16
	for _, t := range bitmap {
		window := t / 256
		length := (t-window*256)/8 + 1
		if window > lastwindow && lastlength != 0 { // New window, jump to the new off
			l += int(lastlength) + 2
			lastlength = 0
		}
		if window < lastwindow || length < lastlength {
			// packNsec would return Error{err: "nsec bits out of order"} here, but
			// when computing the length, we want do be liberal.
			continue
		}
		lastwindow, lastlength = window, length
	}
	l += int(lastlength) + 2
	return l
}
