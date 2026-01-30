package dns

import (
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"sync/atomic"

	"codeberg.org/miekg/dns/pkg/pool"
)

//go:generate go run rr_generate.go
//go:generate go run rdata_generate.go
//go:generate go run ednsrr_generate.go
//go:generate go run dsorr_generate.go
//go:generate go run msg_generate.go
//go:generate go run pack_generate.go
//go:generate go run parse_generate.go
//go:generate go run len_generate.go
//go:generate go run dsolen_generate.go
//go:generate go run dnsutil_generate.go
//go:generate go run dnstest_generate.go
//go:generate go run compare_generate.go
//go:generate go run clone_generate.go

const (
	// DefaultMsgSize is the standard default for messages larger than 512 bytes.
	DefaultMsgSize = 4096
	// MinMsgSize is the minimal size of a DNS message.
	MinMsgSize = 512
	// MaxMsgSize is the largest possible DNS message.
	MaxMsgSize = math.MaxUint16
	// MsgHeaderSize is the length of the header in the DNS message.
	MsgHeaderSize = 12
	// MaxSerialIncrement is the maximum difference between two serial numbers. See RFC 1982.
	MaxSerialIncrement = math.MaxUint32 / 2 // 2147483647

	defaultTTL = 3600 // Default internal TTL.
)

// An RR represents a DNS resource record.
type RR interface {
	// Header returns the header of a resource record. The header contains everything up to the rdata.
	Header() *Header
	// Data return the rdata of a resource record. The Data contains everything after the header.
	Data() RDATA
	// String returns the text representation of the resource record.
	String() string
	// Len is the length of the RR when encoded in wire format, this is not a perfect metric and returning
	// a slightly too large value is OK.
	Len() int

	Cloner
}

// An RDATA represents a DNS rdata element, this is the part of the RR minus the [Header].
type RDATA interface {
	// Len is the length of the resource data when encoded in wire format.
	Len() int
	// String returns the text representation of the rdata only.
	String() string
}

// The Typer interface is used to return the type of RR in the RRToType function or the EDNS0 option
// code when the "RR" is an EDNS0 option. This is only needed for RRs that are defined outside of this package.
// Once this method is defined the following extra registration needs to happen:
//
//	dns.TypeToRR[codepoint] = func() dns.RR { return new(T) }
//	dns.TypeToString[codepoint] = "TYPE"
//	dns.StringToType["TYPE"] = codepoint
//
// For EDNS0 registration use, [CodeToRR], [CodeToString] and [StringToType].
type Typer interface {
	Type() uint16
}

// Comparer interface defines a compare function that returns -1, 0, or +1. Only externally defined RRs must
// implement this interface.
type Comparer interface {
	Compare(b RR) int
}

// The Packer interface defines the Pack and Unpack methods that are used to convert RRs to and from wire format.
type Packer interface {
	// Pack packs the RR into msg at offset off. This method only needs to deals with the RR's rdata, as the
	// header is taken care off. For examples of such code look in zmsg.go. The returned int is the new offset in
	// msg after this RR is packed. For EDNS0 types this only need to pack the data, not the type-length-value
	// (TLV) header.
	Pack(msg []byte, off int) (int, error)
	// Unpack unpacks the RR. Data is the byte slice that should contain the all the data for the RR.
	Unpack(data []byte) error
}

// Parser is used for custom RR types that are parsed from their text presentation.
type Parser interface {
	// Scan gets the current origin and a slice of all non-blank tokens left on the current line.
	Parse(tokens []string, origin string) error
}

// The Cloner interface defines a clone function that returns a deep copy of the RR.
type Cloner interface {
	Clone() RR
}

// RRset is a just list of RRs. There is no guarantee that this is an official RRset as defined in
// RFC 7719, Section 4 "RRset", use [dnsutil.IsRRset] to make that determination.
// The type is defined here to implement the [sort.Interface].
//
// Typical use for sorting a slice of RRs: sort.Sort(dns.RRset(....)).
type RRset []RR

// Header is the header in a DNS resource record. It implements the RR interface, as a header is the RR
// without any data.
type Header struct {
	Name  string `dns:"cdomain-name"` // Name is the owner name of the RR.
	TTL   uint32 // TTL is the time-to-live of the RR.
	Class uint16 // Class is the class of the RR, this is almost always [ClassINET].
}

func (h *Header) Len() int        { return len(h.Name) + 1 + 10 } // +1 because miek.nl. is actually .miek.nl.
func (h *Header) Header() *Header { return h }
func (h *Header) Data() RDATA     { return nil }
func (h *Header) Clone() RR       { return &Header{h.Name, h.TTL, h.Class} }

// String returns the string representation of h.
// Note that as the RR type is derived from the [RR] containing this header, getting the text
// representation of just the header will show TYPE0 instead of the actual type. As this not that useful
// the TYPE0 is not even added, leaving name, ttl and class.
//
// For correctly printing the header you need the RR type to correctly print it. See [codeberg.org/miekg/dns/dnsutil.TypeToString] among others.
// For a RR to be completely printed use:
//
//	s := rr.Header().String() + " " + dnsutil.TypeToString(dns.RRToType(rr)) + "\t" + rr.Data().String)
func (h *Header) String() string {
	sb := builderPool.Get()
	defer builderPool.Put(sb)
	sb.WriteString(h.Name)
	sb.WriteByte('\t')

	sb.WriteString(strconv.FormatInt(int64(h.TTL), 10))
	sb.WriteByte('\t')

	sb.WriteString(classToString(h.Class))
	return sb.String()
}

// EDNS0 determines if the "RR" is posing as an EDNS0 option. EDNS0 options are considered just RRs and must
// be added to the [Pseudo] section of a DNS message. The Len method must return the length of the octets in
// the [OPT] [RR], which is four (2 octets for the type, and 2 octets for the length) plus the encoded lengh of the option itself.
//
// Note that these types has (in this package) a presentation format and can also be parsed from a string via
// [New]. That means you can create EDNS0 options directly from a string.
type EDNS0 interface {
	RR
	// Pseudo signal that the type implementing this interface is an EDNS0 sub-type.
	Pseudo() bool
}

// DSO determines if the "RR" is posing as an DSO option. DSO options are considered just RRs and must
// be added to the [Stateful] section of a DNS message. The Len method must return the the length of the
// octets for the entire option, which is four (2 octets for the type, and 2 octets for the length) plus the
// encoded length of the option itself.
type DSO interface {
	RR
	Stateful() bool
}

// MsgHeader is the header of a DNS message. This contains most header bits, except Rcode as that needs to be
// set via a function because of the extended Rcode that lives in the pseudo section.
type MsgHeader struct {
	offset uint16

	// Both qtype and Options are moved there to aid in struct alignment.
	// aligo -s Msg view .  shows 4 bytes padding for the hijacked field

	// optimization to put the qtype directly in the message, shortcuts needing to actually have a question
	// section (this will then be zero) and avoid RRToType which is slightly slower in the hot path.
	qtype uint16
	// Option is a bit mask of options that control the unpacking. When zero the entire message is unpacked.
	Options MsgOption

	Opcode uint8

	ID uint16

	Rcode uint16 // Rcode is the message response code, extended rcodes can be set here as well.

	// Extended DNS (version 0) option that can be set directly on the message. The package takes care of
	// putting the bits in the right places and creating an OPT RR if needed.
	UDPSize uint16 // UDPSize is the OPT's RR advertised UDP size.
	Version uint8  // Version is the EDNS version, always zero.

	Response           bool
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Zero               bool
	AuthenticatedData  bool
	CheckingDisabled   bool

	// Extended DNS
	Security       bool // Security is the DNSSEC OK bit, see RFC 403{3,4,5}.
	CompactAnswers bool // Compact Answers OK, https://datatracker.ietf.org/doc/draft-ietf-dnsop-compact-denial-of-existence/.
	Delegation     bool // Delegation is the DELEG OK bit, see https://datatracker.ietf.org/doc/draft-ietf-deleg/.

}

// Msg is a DNS message. Each message has a Data field that contains the binary data buffer. This is filled when
// calling [Msg.Pack], it is read and parsed into a Msg by [Msg.Unpack]. When the server allocated Data when reading
// from the wire, the server owns the allocation. Whenever the message is written to the default
// [ResponseWriter] it is returned to the server's pool. If you need to make the Msg the sole owner of the
// allocation call [Msg.Hijack], the allocation will then not be returned. When you create a new Msg, you are
// in full control over the buffer as there is no relation to whatever server.
//
// Msg implements [iter.Seq], so you can range over it, when doing so the RRs of each section are returned,
// this includes the pseudo section.
type Msg struct {
	MsgHeader

	// Question holds a single "RR", in quotes because it is only the domain name, type and class that is
	// actually encoded here. This package takes care of taking and returning the right bit of an RR.
	// Setting the question is done like so: msg.Question = []RR{&MX{Hdr: Header{Name: "miek.nl.", Class: ClassINET}}}
	// This sets it to "miek.nl.", TypeMX, ClassINET. Just like all the other sections.
	Question []RR

	Answer []RR // Holds the RR(s) of the answer section.
	Ns     []RR // Holds the RR(s) of the authority section.
	Extra  []RR // Holds the RR(s) of the additional section, except records that go into the pseudo section.

	// The Pseudo section is a virtual section that holds the OPT EDNS0 options, that are interpreted (and shown) as RRs.
	// The OPT RR itself will never be visible in Extra, nor in the Pseudo section, this is all handled transparently.
	Pseudo []RR // Holds the RR(s) of the (virtual) pseudo section.

	// The Stateful section is a virtual section that holds the DSO option, that are interpreted (and shown)
	// as RRs. There is no OPT like record that holds these, the whole message format is slightly different.
	// Stateful []RR // Holds the DSO RR(s) for Stateful operations, see RFC 8490.

	// msgPool is the [Pooler] from the server, *iff* the message was created by reading data from the wire.
	msgPool pool.Pooler

	// Data is the data of the message that was either received from the wire or is about to be send
	// over the wire. Note that this data is a snapshot of the Msg when it was packed or unpacked.
	Data     []byte
	hijacked atomic.Bool // pool's allocation has been hijacked by caller
}

// Option is an option on how to handle a message. The options are ordered, MsgOptionUnpackQuestion will also
// unpack the header of the message. If MsgOptionUnpackQuestion is used, Unpack will track where it left off
// and then skip unpacking the question section in a subsequent Unpack that is done to get the entire message
// of which the header and question section where previously deemed valid.
type MsgOption uint8

const (
	MsgOptionUnpack         MsgOption = 0         // Unpack the entire message, mostly defined to serve as documentation.
	MsgOptionUnpackHeader   MsgOption = 1 << iota // Unpack only the header of the message.
	MsgOptionUnpackQuestion                       // Unpack up the question section of the message.
	MsgOptionUnpackAnswer                         // Unpack up to the answer section of the message.

)

// Convert a MsgHeader to a string, with dig-like headers:
//
//	;; QUERY, rcode: NOERROR, id: 51664, flags: qr rd ra do co
//	;; EDNS, version: 0, udp: 512
//	;; QUESTION: 1, PSEUDO: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0
func (h *MsgHeader) String() string {
	sb := strings.Builder{}
	sb.WriteString(";; ")
	sb.WriteString(opcodeToString(h.Opcode))
	sb.WriteString(", rcode: ")
	sb.WriteString(rcodeToString(h.Rcode))
	sb.WriteString(", id: ")
	sb.WriteString(strconv.Itoa(int(h.ID)))
	sb.WriteByte(',')

	sb.WriteString(" flags:")
	if h.Response {
		sb.WriteString(" qr")
	}
	if h.Authoritative {
		sb.WriteString(" aa")
	}
	if h.Truncated {
		sb.WriteString(" tc")
	}
	if h.RecursionDesired {
		sb.WriteString(" rd")
	}
	if h.RecursionAvailable {
		sb.WriteString(" ra")
	}
	if h.Zero {
		sb.WriteString(" z")
	}
	if h.AuthenticatedData {
		sb.WriteString(" ad")
	}
	if h.CheckingDisabled {
		sb.WriteString(" cd")
	}
	if h.Security {
		sb.WriteString(" do")
	}
	if h.CompactAnswers {
		sb.WriteString(" co")
	}
	if h.Delegation {
		sb.WriteString(" de")
	}
	sb.WriteByte('\n')
	return sb.String()
}

// ToRFC3597 converts a known RR to the unknown RR representation from RFC 3597.
func (rr *RFC3597) ToRFC3597(r RR) error {
	buf := make([]byte, r.Len())
	headerEnd, off, err := packRR(r, buf, 0, map[string]uint16{})
	if err != nil {
		return err
	}
	buf = buf[:off]

	*rr = RFC3597{Hdr: *r.Header()}
	rr.RRType = uint16(off - headerEnd)

	if rr.RRType == 0 {
		return nil
	}

	return rr.unpack(buf[headerEnd:], buf)
}

// fromRFC3597 converts an unknown RR representation from RFC 3597 to the known RR type.
func (rr *RFC3597) fromRFC3597(r RR) error {
	hdr := r.Header()
	*hdr = rr.Hdr

	// Can't overflow uint16 as the length of Rdata is validated in (*RFC3597).parse.
	// We can only get here when rr was constructed with that method.

	// rr.pack requires an extra allocation and a copy so we just decode Rdata manually, it's simpler anyway.
	msg, err := hex.DecodeString(rr.RFC3597.Data)
	if err != nil {
		return err
	}
	if len(msg) == 0 { // no rdata
		return nil
	}
	return zunpack(r, msg, msg)
}

const msgArcount = 10 // offset in the message where the Arcount is, 2 octets long.
