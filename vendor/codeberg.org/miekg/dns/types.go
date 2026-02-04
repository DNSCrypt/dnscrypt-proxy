package dns

import (
	"strconv"
	"time"

	"codeberg.org/miekg/dns/internal/dnslex"
	"codeberg.org/miekg/dns/rdata"
)

// Packet formats

// Wire constants and supported types.
const (

	// If you add one here, also add internal/dnsstrings/types.go

	TypeNone       uint16 = 0
	TypeA          uint16 = 1
	TypeNS         uint16 = 2
	TypeMD         uint16 = 3
	TypeMF         uint16 = 4
	TypeCNAME      uint16 = 5
	TypeSOA        uint16 = 6
	TypeMB         uint16 = 7
	TypeMG         uint16 = 8
	TypeMR         uint16 = 9
	TypeNULL       uint16 = 10
	TypePTR        uint16 = 12
	TypeHINFO      uint16 = 13
	TypeMINFO      uint16 = 14
	TypeMX         uint16 = 15
	TypeTXT        uint16 = 16
	TypeRP         uint16 = 17
	TypeAFSDB      uint16 = 18
	TypeX25        uint16 = 19
	TypeISDN       uint16 = 20
	TypeRT         uint16 = 21
	TypeNSAPPTR    uint16 = 23
	TypeSIG        uint16 = 24
	TypeKEY        uint16 = 25
	TypePX         uint16 = 26
	TypeGPOS       uint16 = 27
	TypeAAAA       uint16 = 28
	TypeLOC        uint16 = 29
	TypeNXT        uint16 = 30
	TypeEID        uint16 = 31
	TypeNIMLOC     uint16 = 32
	TypeSRV        uint16 = 33
	TypeATMA       uint16 = 34
	TypeNAPTR      uint16 = 35
	TypeKX         uint16 = 36
	TypeCERT       uint16 = 37
	TypeDNAME      uint16 = 39
	TypeOPT        uint16 = 41
	TypeAPL        uint16 = 42 // Not implemented.
	TypeDS         uint16 = 43
	TypeSSHFP      uint16 = 44
	TypeIPSECKEY   uint16 = 45 // Not implemented.
	TypeRRSIG      uint16 = 46
	TypeNSEC       uint16 = 47
	TypeDNSKEY     uint16 = 48
	TypeDHCID      uint16 = 49
	TypeNSEC3      uint16 = 50
	TypeNSEC3PARAM uint16 = 51
	TypeTLSA       uint16 = 52
	TypeSMIMEA     uint16 = 53
	TypeHIP        uint16 = 55
	TypeNINFO      uint16 = 56
	TypeRKEY       uint16 = 57
	TypeTALINK     uint16 = 58
	TypeCDS        uint16 = 59
	TypeCDNSKEY    uint16 = 60
	TypeOPENPGPKEY uint16 = 61
	TypeCSYNC      uint16 = 62
	TypeZONEMD     uint16 = 63
	TypeSVCB       uint16 = 64
	TypeHTTPS      uint16 = 65
	TypeDSYNC      uint16 = 66
	TypeSPF        uint16 = 99
	TypeUINFO      uint16 = 100
	TypeUID        uint16 = 101
	TypeGID        uint16 = 102
	TypeUNSPEC     uint16 = 103
	TypeNID        uint16 = 104
	TypeL32        uint16 = 105
	TypeL64        uint16 = 106
	TypeLP         uint16 = 107
	TypeEUI48      uint16 = 108
	TypeEUI64      uint16 = 109
	TypeNXNAME     uint16 = 128
	TypeURI        uint16 = 256
	TypeCAA        uint16 = 257
	TypeAVC        uint16 = 258
	TypeAMTRELAY   uint16 = 260 // Not implemented.
	TypeRESINFO    uint16 = 261
	TypeWALLET     uint16 = 262
	TypeCLA        uint16 = 263
	TypeIPN        uint16 = 264

	TypeTKEY uint16 = 249
	TypeTSIG uint16 = 250

	// Valid question types only.
	TypeIXFR  uint16 = 251
	TypeAXFR  uint16 = 252
	TypeMAILB uint16 = 253
	TypeMAILA uint16 = 254
	TypeANY   uint16 = 255

	TypeTA       uint16 = 32768
	TypeDLV      uint16 = 32769
	TypeDELEG    uint16 = 65432 // Provisional type.
	TypeDELEGI   uint16 = 65433 // Provisional type.
	TypeReserved uint16 = 65535

	// valid question classes only.
	ClassINET   = 1
	ClassCSNET  = 2
	ClassCHAOS  = 3
	ClassHESIOD = 4
	ClassNONE   = 254
	ClassANY    = 255

	// Message Response Codes, see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml.
	RcodeSuccess                = 0  // NoError   - No Error                          [DNS]
	RcodeFormatError            = 1  // FormErr   - Format Error                      [DNS]
	RcodeServerFailure          = 2  // ServFail  - Server Failure                    [DNS]
	RcodeNameError              = 3  // NXDomain  - Non-Existent Domain               [DNS]
	RcodeNotImplemented         = 4  // NotImp    - Not Implemented                   [DNS]
	RcodeRefused                = 5  // Refused   - Query Refused                     [DNS]
	RcodeYXDomain               = 6  // YXDomain  - Name Exists when it should not    [DNS Update]
	RcodeYXRrset                = 7  // YXRRSet   - RR Set Exists when it should not  [DNS Update]
	RcodeNXRrset                = 8  // NXRRSet   - RR Set that should exist does not [DNS Update]
	RcodeNotAuth                = 9  // NotAuth   - Server Not Authoritative for zone [DNS Update]
	RcodeNotZone                = 10 // NotZone   - Name not contained in zone        [DNS Update/TSIG]
	RcodeStatefulNotImplemented = 11 // DSOTYPENI - DSO-TYPE Not Implemented [DSO]    [DSO]
	RcodeBadSig                 = 16 // BADSIG    - TSIG Signature Failure            [TSIG]
	RcodeBadVers                = 16 // BADVERS   - Bad OPT Version                   [EDNS0]
	RcodeBadKey                 = 17 // BADKEY    - Key not recognized                [TSIG]
	RcodeBadTime                = 18 // BADTIME   - Signature out of time window      [TSIG]
	RcodeBadMode                = 19 // BADMODE   - Bad TKEY Mode                     [TKEY]
	RcodeBadName                = 20 // BADNAME   - Duplicate key name                [TKEY]
	RcodeBadAlg                 = 21 // BADALG    - Algorithm not supported           [TKEY]
	RcodeBadTrunc               = 22 // BADTRUNC  - Bad Truncation                    [TSIG]
	RcodeBadCookie              = 23 // BADCOOKIE - Bad/missing Server Cookie         [DNS Cookies]

	// Message Opcodes. There is no 3.
	OpcodeQuery    = 0
	OpcodeIQuery   = 1
	OpcodeStatus   = 2
	OpcodeNotify   = 4
	OpcodeUpdate   = 5
	OpcodeStateful = 6
)

// Names for things inside RRs should be RR-name (all capitals) and than snakecase the rest.

// Used in ZONEMD, RFC 8976.
const (
	ZONEMDSchemeSimple = 1

	ZONEMDHashSHA384 = 1
	ZONEMDHashSHA512 = 2
)

// header is the wire format for the DNS packet header.
type header struct {
	ID                                 uint16
	Bits                               uint16
	Qdcount, Ancount, Nscount, Arcount uint16
}

const (
	// Header.Bits
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
	_Z  = 1 << 6  // Z
	_AD = 1 << 5  // authenticated data
	_CD = 1 << 4  // checking disabled

	// EDNS0 OPT "Header.Bits", these are placed directory in a *Msg in this impl.
	_DO = 1 << 15 // DNSSEC OK
	_CO = 1 << 14 // Compact Answers OK
	_DE = 1 << 13 // DELEG OK
)

// Various constants used in the LOC RR. See RFC 1876.
const (
	LOCEquator       = 1 << 31 // RFC 1876, Section 2.
	LOCPrimemeridian = 1 << 31 // RFC 1876, Section 2.
	LOCHours         = 60 * 1000
	LOCDegrees       = 60 * LOCHours
	LOCAltitudebase  = 100000
)

// Different Certificate Types, see RFC 4398, Section 2.1.
const (
	CERTPkix = 1 + iota
	CERTSpki
	CERTPgp
	CERTIpix
	CERTIspki
	CERTIpgp
	CERTAcpkix
	CERTIAcpkix
	CERTUri = 253
	CERTOid = 254
)

// CertTypeToString converts the Cert Type to its string representation.
// See RFC 4398 and RFC 6944.
var CertTypeToString = map[uint16]string{
	CERTPkix:    "PKIX",
	CERTSpki:    "SPKI",
	CERTPgp:     "PGP",
	CERTIpix:    "IPIX",
	CERTIspki:   "ISPKI",
	CERTIpgp:    "IPGP",
	CERTAcpkix:  "ACPKIX",
	CERTIAcpkix: "IACPKIX",
	CERTUri:     "URI",
	CERTOid:     "OID",
}

// NULL RR. See RFC 1035.
type NULL struct {
	Hdr Header
	rdata.NULL
}

func (rr *NULL) String() string {
	// There is no presentation format; prefix string with a comment.
	return ";" + rr.Hdr.String() + rr.Null
}

func (*NULL) parse(_ *dnslex.Lexer, _ string) *ParseError {
	return &ParseError{err: "NULL records do not have a presentation format"}
}

// NXNAME is a meta record. See https://www.iana.org/go/draft-ietf-dnsop-compact-denial-of-existence-04
// Reference: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
type NXNAME struct {
	Hdr Header
	// Does not have any rdata
}

func (rr *NXNAME) Len() int       { return rr.Hdr.Len() }
func (rr *NXNAME) String() string { return rr.Hdr.String() }

func (*NXNAME) parse(_ *dnslex.Lexer, _ string) *ParseError {
	return &ParseError{err: "NXNAME records do not have a presentation format"}
}

// CNAME RR. See RFC 1034.
type CNAME struct {
	Hdr Header
	rdata.CNAME
}

func (rr *CNAME) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.Target)
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// HINFO RR. See RFC 1034.
type HINFO struct {
	Hdr Header
	rdata.HINFO
}

func (rr *HINFO) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.HINFO.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// MB RR. See RFC 1035.
type MB struct {
	Hdr Header
	rdata.MB
}

func (rr *MB) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.MB.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// MG RR. See RFC 1035.
type MG struct {
	Hdr Header
	rdata.MG
}

func (rr *MG) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.MG.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// MINFO RR. See RFC 1035.
type MINFO struct {
	Hdr Header
	rdata.MINFO
}

func (rr *MINFO) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.MINFO.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// MR RR. See RFC 1035.
type MR struct {
	Hdr Header
	rdata.MR
}

func (rr *MR) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.MR.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// MF RR. See RFC 1035.
type MF struct {
	Hdr Header
	rdata.MF
}

func (rr *MF) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.MF.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// MD RR. See RFC 1035.
type MD struct {
	Hdr Header
	rdata.MD
}

func (rr *MD) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.MD.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// MX RR. See RFC 1035.
type MX struct {
	Hdr Header
	rdata.MX
}

func (rr *MX) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.MX.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// AFSDB RR. See RFC 1183.
type AFSDB struct {
	Hdr Header
	rdata.AFSDB
}

func (rr *AFSDB) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.AFSDB.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// X25 RR. See RFC 1183, Section 3.1.
type X25 struct {
	Hdr Header
	rdata.X25
}

func (rr *X25) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.X25.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// ISDN RR. See RFC 1183, Section 3.2.
type ISDN struct {
	Hdr Header
	rdata.ISDN
}

func (rr *ISDN) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.ISDN.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// RT RR. See RFC 1183, Section 3.3.
type RT struct {
	Hdr Header
	rdata.RT
}

func (rr *RT) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.RT.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NS RR. See RFC 1035.
type NS struct {
	Hdr Header
	rdata.NS
}

func (rr *NS) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.NS.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// PTR RR. See RFC 1035.
type PTR struct {
	Hdr Header
	rdata.PTR
}

func (rr *PTR) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.PTR.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// RP RR. See RFC 1138, Section 2.2.
type RP struct {
	Hdr Header
	rdata.RP
}

func (rr *RP) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.RP.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// SOA RR. See RFC 1035.
type SOA struct {
	Hdr Header
	rdata.SOA
}

func (rr *SOA) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.SOA.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// TXT RR. See RFC 1035.
type TXT struct {
	Hdr Header
	rdata.TXT
}

func (rr *TXT) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.TXT.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// SPF RR. See RFC 4408, Section 3.1.1.
type SPF struct{ TXT }

func (rr *SPF) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.TXT.TXT.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// AVC RR. See https://www.iana.org/assignments/dns-parameters/AVC/avc-completed-template.
type AVC struct{ TXT }

func (rr *AVC) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.TXT.TXT.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// WALLET RR. See https://www.iana.org/assignments/dns-parameters/WALLET/wallet-completed-template.
type WALLET struct{ TXT }

func (rr *WALLET) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.TXT.TXT.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// CLA RR. See https://www.iana.org/assignments/dns-parameters/CLA/cla-completed-template.
type CLA struct{ TXT }

func (rr *CLA) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.TXT.TXT.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// IPN RR. See https://www.iana.org/assignments/dns-parameters/IPN/ipn-completed-template.
type IPN struct {
	Hdr Header
	rdata.IPN
}

func (rr *IPN) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.IPN.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// SRV RR. See RFC 2782.
type SRV struct {
	Hdr Header
	rdata.SRV
}

func (rr *SRV) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.SRV.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NAPTR RR. See RFC 2915.
type NAPTR struct {
	Hdr Header
	rdata.NAPTR
}

func (rr *NAPTR) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.NAPTR.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// CERT RR. See RFC 4398.
type CERT struct {
	Hdr Header
	rdata.CERT
}

func (rr *CERT) String() string {
	sb := sprintHeader(rr)
	defer builderPool.Put(*sb)
	sb.WriteString(rr.CERT.String())
	return sb.String()
}

// DNAME RR. See RFC 2672.
type DNAME struct {
	Hdr Header
	rdata.DNAME
}

func (rr *DNAME) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.DNAME.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// A RR. See RFC 1035.
type A struct {
	Hdr Header
	rdata.A
}

func (rr *A) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.A.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// AAAA RR. See RFC 3596.
type AAAA struct {
	Hdr Header
	rdata.AAAA
}

func (rr *AAAA) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.AAAA.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// PX RR. See RFC 2163.
type PX struct {
	Hdr Header
	rdata.PX
}

func (rr *PX) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.PX.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// GPOS RR. See RFC 1712.
type GPOS struct {
	Hdr Header
	rdata.GPOS
}

func (rr *GPOS) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.GPOS.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// LOC RR. See RFC 1876.
type LOC struct {
	Hdr Header
	rdata.LOC
}

func (rr *LOC) String() string {
	sb := sprintHeader(rr)
	defer builderPool.Put(*sb)
	sb.WriteString(rr.LOC.String())
	return sb.String()
}

// SIG RR. See RFC 2535. The SIG RR is identical to RRSIG and nowadays only used for SIG(0), See RFC 2931.
type SIG struct{ RRSIG }

func (rr *SIG) String() string {
	sb := sprintHeader(rr)
	defer builderPool.Put(*sb)
	sb.WriteString(rr.RRSIG.RRSIG.String())
	return sb.String()
}

// NewSIG0 return a new SIG with initial fields set. This can be used SIG0 transaction signing.
func NewSIG0() *SIG {
	// TODO(miek)
	return nil
}

// RRSIG RR. See RFC 4034 and RFC 3755.
type RRSIG struct {
	Hdr Header
	rdata.RRSIG
}

func (rr *RRSIG) String() string {
	sb := sprintHeader(rr)
	defer builderPool.Put(*sb)
	sb.WriteString(rr.RRSIG.String())
	return sb.String()
}

// NewRRSIG returns a new RRSIG with many fields set. That can be used as a "stub" RRSIG before generating the
// signature. If incepexp, the inception and expiration dates, are not the given, now-300s and now+2w is used.
// origin (which must be in canonical form) is set as the signers name. The name of the RRSIG is set while
// signing.
func NewRRSIG(origin string, algorithm uint8, keytag uint16, incepexp ...uint32) *RRSIG {
	s := &RRSIG{RRSIG: rdata.RRSIG{Algorithm: algorithm, KeyTag: keytag, SignerName: origin}}
	if len(incepexp) == 0 {
		now := time.Now().Unix()
		s.Expiration = uint32(now + (14 * 86400))
		s.Inception = uint32(now - 300)
	} else {
		s.Inception = incepexp[0]
		s.Expiration = incepexp[1]
	}
	return s
}

// NXT RR. See RFC 2535.
type NXT struct{ NSEC }

func (rr *NXT) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.NSEC.NSEC.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NSEC RR. See RFC 4034 and RFC 3755.
type NSEC struct {
	Hdr Header
	rdata.NSEC
}

func (rr *NSEC) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.NSEC.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

func (rr *NSEC) Len() int { return rr.Hdr.Len() + rr.NSEC.Len() }

// DLV RR. See RFC 4431.
type DLV struct{ DS }

func (rr *DLV) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.DS.DS.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// CDS RR. See RFC 7344.
type CDS struct{ DS }

func (rr *CDS) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.DS.DS.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// DS RR. See RFC 4034 and RFC 3658.
type DS struct {
	Hdr Header
	rdata.DS
}

func (rr *DS) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.DS.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// KX RR. See RFC 2230.
type KX struct {
	Hdr Header
	rdata.KX
}

func (rr *KX) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.KX.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// TA RR. See http://www.watson.org/~weiler/INI1999-19.pdf.
type TA struct {
	Hdr Header
	rdata.TA
}

func (rr *TA) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.TA.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// TALINK RR. See https://www.iana.org/assignments/dns-parameters/TALINK/talink-completed-template.
type TALINK struct {
	Hdr Header
	rdata.TALINK
}

func (rr *TALINK) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.TALINK.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// SSHFP RR. See RFC 4255.
type SSHFP struct {
	Hdr Header
	rdata.SSHFP
}

func (rr *SSHFP) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.SSHFP.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// KEY RR. See RFC 2535.
type KEY struct{ DNSKEY }

func (rr *KEY) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.DNSKEY.DNSKEY.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// CDNSKEY RR. See RFC 7344.
type CDNSKEY struct{ DNSKEY }

func (rr *CDNSKEY) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.DNSKEY.DNSKEY.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// DNSKEY RR. See RFC 4034 and RFC 3755.
type DNSKEY struct {
	Hdr Header
	rdata.DNSKEY
}

func (rr *DNSKEY) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.DNSKEY.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NewDNSKEY returns a DNSKEY with good defaults for some fields. The key's flag field is set to 256.
func NewDNSKEY(z string, algorithm uint8) *DNSKEY {
	k := new(DNSKEY)
	k.Hdr.Name = z
	k.Hdr.Class = ClassINET
	k.Algorithm = algorithm
	k.Flags = 256
	k.Protocol = 3
	return k
}

// RKEY RR. See https://www.iana.org/assignments/dns-parameters/RKEY/rkey-completed-template.
type RKEY struct {
	Hdr Header
	rdata.RKEY
}

func (rr *RKEY) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.RKEY.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NSAPPTR RR. See RFC 1348.
type NSAPPTR struct {
	Hdr Header
	rdata.NSAPPTR
}

func (rr *NSAPPTR) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.NSAPPTR.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NSEC3 RR. See RFC 5155.
type NSEC3 struct {
	Hdr Header
	rdata.NSEC3
}

func (rr *NSEC3) String() string {
	sb := sprintHeader(rr)
	defer builderPool.Put(*sb)
	sb.WriteString(rr.NSEC3.String())
	return sb.String()
}

func (rr *NSEC3) Len() int { return rr.Hdr.Len() + rr.NSEC3.Len() }

// NSEC3PARAM RR. See RFC 5155.
type NSEC3PARAM struct {
	Hdr Header
	rdata.NSEC3PARAM
}

func (rr *NSEC3PARAM) String() string {
	sb := sprintHeader(rr)
	defer builderPool.Put(*sb)
	sb.WriteString(rr.NSEC3PARAM.String())
	return sb.String()
}

// TKEY RR. See RFC 2930.
type TKEY struct {
	Hdr Header
	rdata.TKEY
}

// TKEY has no official presentation format, but this will suffice.
func (rr *TKEY) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.TKEY.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// RFC3597 represents an unknown/generic RR. See RFC 3597.
type RFC3597 struct {
	Hdr Header
	rdata.RFC3597
}

func (rr *RFC3597) Data() RDATA { return rr.RFC3597 }

func (rr *RFC3597) String() string {
	sb := builderPool.Get()

	sb.WriteString(rr.Hdr.Name)
	sb.WriteByte('\t')
	sb.WriteString(strconv.FormatInt(int64(rr.Hdr.TTL), 10))
	sb.WriteByte('\t')
	sb.WriteString("CLASS" + strconv.Itoa(int(rr.Hdr.Class)))
	sb.WriteByte('\t')
	sb.WriteString("TYPE" + strconv.Itoa(int(rr.RRType)))
	sb.WriteByte('\t')

	sb.WriteString(rr.RFC3597.String())
	s := sb.String()
	builderPool.Put(sb)
	return s
}

// Type implements the Typer interface. This is mandatory for this type as its Go type isn't indicative of the
// actual type it is carrying.
func (rr *RFC3597) Type() uint16 { return rr.RRType }

// URI RR. See RFC 7553.
type URI struct {
	Hdr Header
	rdata.URI
}

func (rr *URI) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.URI.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// DHCID RR. See RFC 4701.
type DHCID struct {
	Hdr Header
	rdata.DHCID
}

func (rr *DHCID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.DHCID.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// TLSA RR. See RFC 6698.
type TLSA struct {
	Hdr Header
	rdata.TLSA
}

func (rr *TLSA) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.TLSA.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// SMIMEA RR. See RFC 8162.
type SMIMEA struct {
	Hdr Header
	rdata.SMIMEA
}

func (rr *SMIMEA) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.SMIMEA.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// HIP RR. See RFC 8005.
type HIP struct {
	Hdr Header
	rdata.HIP
}

func (rr *HIP) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.HIP.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NINFO RR. See https://www.iana.org/assignments/dns-parameters/NINFO/ninfo-completed-template.
type NINFO struct {
	Hdr Header
	rdata.NINFO
}

func (rr *NINFO) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.NINFO.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NID RR. See RFC 6742.
type NID struct {
	Hdr Header
	rdata.NID
}

func (rr *NID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.NID.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// L32 RR, See RFC 6742.
type L32 struct {
	Hdr Header
	rdata.L32
}

func (rr *L32) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.L32.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// L64 RR, See RFC 6742.
type L64 struct {
	Hdr Header
	rdata.L64
}

func (rr *L64) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.L64.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// LP RR. See RFC 6742.
type LP struct {
	Hdr Header
	rdata.LP
}

func (rr *LP) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.LP.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// EUI48 RR. See RFC 7043.
type EUI48 struct {
	Hdr Header
	rdata.EUI48
}

func (rr *EUI48) String() string { return rr.Hdr.String() + rr.EUI48.String() }

// EUI64 RR. See RFC 7043.
type EUI64 struct {
	Hdr Header
	rdata.EUI64
}

func (rr *EUI64) String() string { return rr.Hdr.String() + rr.EUI64.String() }

// CAA RR. See RFC 6844.
type CAA struct {
	Hdr Header
	rdata.CAA
}

func (rr *CAA) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.CAA.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// UID RR. Deprecated, IANA-Reserved.
type UID struct {
	Hdr Header
	rdata.UID
}

func (rr *UID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.UID.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// GID RR. Deprecated, IANA-Reserved.
type GID struct {
	Hdr Header
	rdata.GID
}

func (rr *GID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.GID.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// UINFO RR. Deprecated, IANA-Reserved.
type UINFO struct {
	Hdr Header
	rdata.UINFO
}

func (rr *UINFO) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.UINFO.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// EID RR. See http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt.
type EID struct {
	Hdr Header
	rdata.EID
}

func (rr *EID) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.EID.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NIMLOC RR. See http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt.
type NIMLOC struct {
	Hdr Header
	rdata.NIMLOC
}

func (rr *NIMLOC) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.NIMLOC.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// OPENPGPKEY RR. See RFC 7929.
type OPENPGPKEY struct {
	Hdr Header
	rdata.OPENPGPKEY
}

func (rr *OPENPGPKEY) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.OPENPGPKEY.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// CSYNC RR. See RFC 7477.
type CSYNC struct {
	Hdr Header
	rdata.CSYNC
}

func (rr *CSYNC) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.CSYNC.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

func (rr *CSYNC) Len() int { return rr.Hdr.Len() + rr.CSYNC.Len() }

// ZONEMD RR, RFC 8976.
type ZONEMD struct {
	Hdr Header
	rdata.ZONEMD
}

func (rr *ZONEMD) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.ZONEMD.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// OPT is the EDNS0 RR appended to messages to convey extra (meta) information. See RFC 6891. This record is
// not (directly) found in messages as the pack and unpack function take care of this. Any EDNS0 options are
// found in the [Pseudo] section of the message. There should be rarely the need to access specifics of this
// RR as you can just set things directly on [Msg].
type OPT struct {
	Hdr     Header
	Options []EDNS0 `dns:"opt"`
}

// See opt.go for other methods.

func (rr *OPT) Data() RDATA    { return nil }
func (rr *OPT) String() string { return "" }

func (rr *OPT) Len() int {
	l := rr.Hdr.Len()
	for i := range rr.Options {
		l += rr.Options[i].Len()
	}
	return l
}

var _ RR = &OPT{}

// RESINFO RR. See RFC 9606.
type RESINFO struct{ TXT }

func (rr *RESINFO) String() string { return rr.Hdr.String() + rr.TXT.TXT.String() }

// SVCB RR. See RFC 9460.
type SVCB struct {
	Hdr Header
	rdata.SVCB
}

func (rr *SVCB) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.SVCB.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// HTTPS RR. See RFC 9460. Everything valid for SVCB applies to HTTPS as well.
// Except that the HTTPS record is intended for use with the HTTP and HTTPS protocols.
type HTTPS struct{ SVCB }

func (rr *HTTPS) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.SVCB.SVCB.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// DELEG RR. See draft https://datatracker.ietf.org/doc/draft-ietf-deleg/.
type DELEG struct {
	Hdr Header
	rdata.DELEG
}

func (rr *DELEG) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.DELEG.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

type DELEGI struct{ DELEG }

func (rr *DELEGI) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.DELEG.DELEG.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// See RFC 9859
type DSYNC struct {
	Hdr Header
	rdata.DSYNC
}

func (rr *DSYNC) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.DSYNC.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// Meta RRs

// ANY is a wildcard record. See RFC 1035, Section 3.2.3. ANY is named "*" there.
type ANY struct {
	Hdr Header
}

func (rr *ANY) Len() int       { return rr.Hdr.Len() }
func (rr *ANY) String() string { return rr.Hdr.String() }

func (*ANY) parse(c *dnslex.Lexer, origin string) *ParseError {
	return &ParseError{err: "ANY records do not have a presentation format"}
}

// AXFR is a meta record used (solely) in question sections to ask for a zone transfer.
type AXFR struct {
	Hdr Header
}

func (rr *AXFR) Len() int       { return rr.Hdr.Len() }
func (rr *AXFR) String() string { return rr.Hdr.String() }

func (*AXFR) parse(c *dnslex.Lexer, origin string) *ParseError {
	return &ParseError{err: "AXFR records do not have a presentation format"}
}

// IXFR is a meta record used (solely) in question sections to ask for an incremental zone transfer.
type IXFR struct {
	Hdr Header
}

func (rr *IXFR) Len() int       { return rr.Hdr.Len() }
func (rr *IXFR) String() string { return rr.Hdr.String() }

func (*IXFR) parse(c *dnslex.Lexer, origin string) *ParseError {
	return &ParseError{err: "IXFR records do not have a presentation format"}
}

// TSIG is the RR the holds the transaction signature of a message. See RFC 2845 and RFC 4635.
// A TSIG RR when created must have the [ClassANY], algorithm, timesigned, and optianal fudge factor.
// The owner name is the name of the key. I.e:
//
//	tsig := &dns.TSIG{Hdr: dns.Header{Name: "keyname.", Class: dns.ClassANY}, Algorithm: dns.HmacSHA512,
//			TimeSigned: uint64(time.Now().Unix())}
//
// See [NewTSIG] for an easier way of doing this.
type TSIG struct {
	Hdr Header
	rdata.TSIG
}

func (rr *TSIG) String() string {
	sb := sprintHeader(rr)
	sb.WriteString(rr.TSIG.String())
	s := sb.String()
	builderPool.Put(*sb)
	return s
}

// NewTSIG return a new TSIG with initial fields set. If fudge is zero, the default of 300 is used.
// If timesigned isn't given the current time is used via time.Now().Unix().
func NewTSIG(z, algorithm string, fudge uint16, timesigned ...int64) *TSIG {
	t := new(TSIG)
	t.Hdr.Name = z
	t.Hdr.Class = ClassANY
	t.Algorithm = algorithm
	if fudge == 0 {
		fudge = 300
	}
	t.Fudge = fudge
	if len(timesigned) == 0 {
		t.TimeSigned = uint64(time.Now().Unix())
	} else {
		t.TimeSigned = uint64(timesigned[0])
	}
	return t
}

func (*TSIG) parse(c *dnslex.Lexer, origin string) *ParseError {
	return &ParseError{err: "TSIG records do not have a presentation format"}
}
