package dns

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"iter"
	"net"
	"strconv"

	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"codeberg.org/miekg/dns/rdata"
	"golang.org/x/crypto/cryptobyte"
)

// ID by default returns a 16-bit random number to be used as a message id. The
// number is drawn from a cryptographically secure random number generator.
// This being a variable the function can be reassigned to a custom function.
// For instance, to make it return a static value for testing:
//
//	dns.ID = func() uint16 { return 3 }
var ID = id

// id returns a 16 bits random number to be used as a message id. The random provided should be good enough.
func id() uint16 {
	var b [2]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic("dns: reading random ID failed: " + err.Error())
	}
	return uint16(b[0])<<8 | uint16(b[1])
}

// ClassToString is a maps Classes to strings for each CLASS wire type.
var ClassToString = map[uint16]string{
	ClassINET:   "IN",
	ClassCSNET:  "CS",
	ClassCHAOS:  "CH",
	ClassHESIOD: "HS",
	ClassNONE:   "NONE",
	ClassANY:    "ANY",
}

// OpcodeToString maps Opcodes to strings.
var OpcodeToString = map[uint8]string{
	OpcodeQuery:    "QUERY",
	OpcodeIQuery:   "IQUERY",
	OpcodeStatus:   "STATUS",
	OpcodeNotify:   "NOTIFY",
	OpcodeUpdate:   "UPDATE",
	OpcodeStateful: "STATEFUL",
}

// RcodeToString maps Rcodes to strings.
var RcodeToString = map[uint16]string{
	RcodeSuccess:                "NOERROR",
	RcodeFormatError:            "FORMERR",
	RcodeServerFailure:          "SERVFAIL",
	RcodeNameError:              "NXDOMAIN",
	RcodeNotImplemented:         "NOTIMPL",
	RcodeRefused:                "REFUSED",
	RcodeYXDomain:               "YXDOMAIN", // See RFC 2136.
	RcodeYXRrset:                "YXRRSET",
	RcodeNXRrset:                "NXRRSET",
	RcodeNotAuth:                "NOTAUTH",
	RcodeNotZone:                "NOTZONE",
	RcodeBadSig:                 "BADSIG", // Also known as RcodeBadVers "BADVERS", see RFC 6891.
	RcodeStatefulNotImplemented: "DSOTYPENI",
	RcodeBadKey:                 "BADKEY",
	RcodeBadTime:                "BADTIME",
	RcodeBadMode:                "BADMODE",
	RcodeBadName:                "BADNAME",
	RcodeBadAlg:                 "BADALG",
	RcodeBadTrunc:               "BADTRUNC",
	RcodeBadCookie:              "BADCOOKIE",
}

// packQuestion packs an RR into a question section.
func packQuestion(rr RR, msg []byte, off int, compression map[string]uint16) (off1 int, err error) {
	off, err = pack.Name(rr.Header().Name, msg, off, compression, false)
	if err != nil {
		return len(msg), err
	}
	rrtype := RRToType(rr)
	off, err = pack.Uint16(rrtype, msg, off)
	if err != nil {
		return len(msg), err
	}

	off, err = pack.Uint16(rr.Header().Class, msg, off)
	if err != nil {
		return len(msg), err
	}
	return off, nil
}

func packRR(rr RR, msg []byte, off int, compression map[string]uint16) (headerEnd int, off1 int, err error) {
	rrtype := RRToType(rr)
	headerEnd, err = rr.Header().packHeader(msg, off, rrtype, compression)
	if err != nil {
		return headerEnd, len(msg), err
	}
	off1, err = zpack(rr, msg, headerEnd, compression)
	if err != nil {
		return headerEnd, len(msg), err
	}

	rdlength := off1 - headerEnd
	if int(uint16(rdlength)) != rdlength { // overflow
		return headerEnd, len(msg), pack.Errorf("inconsistent rdata length")
	}

	// The RDLENGTH field is the last field in the header and we set it here.
	binary.BigEndian.PutUint16(msg[headerEnd-2:], uint16(rdlength))
	return headerEnd, off1, nil
}

func unpackRR(msg *cryptobyte.String, msgBuf []byte) (RR, error) {
	h, typ, rdlength, err := unpackHeader(msg, msgBuf)
	if err != nil {
		return nil, err
	}

	var data []byte
	if !msg.ReadBytes(&data, int(rdlength)) {
		return h, unpack.ErrTruncatedMessage
	}

	// Restrict msgBuf to the end of the RR (the current position of msg) so that we compute the correct offset
	// in unpack.Name.
	msgBuf = msgBuf[:unpack.Offset(*msg, msgBuf)]

	var rr RR
	if newFn, ok := TypeToRR[typ]; ok {
		rr = newFn()
		*rr.Header() = *h
	} else {
		rr = &RFC3597{Hdr: *h}
	}

	if len(data) == 0 {
		return rr, nil
	}

	if err := zunpack(rr, data, msgBuf); err != nil {
		return rr, err
	}

	return rr, nil
}

func (m *Msg) Pack() error {
	// Convert convenient Msg into wire-like Header.
	var dh header
	dh.ID = m.ID
	dh.Bits = uint16(m.Opcode)<<11 | uint16(m.Rcode&0xF)
	if m.Response {
		dh.Bits |= _QR
	}
	if m.Authoritative {
		dh.Bits |= _AA
	}
	if m.Truncated {
		dh.Bits |= _TC
	}
	if m.RecursionDesired {
		dh.Bits |= _RD
	}
	if m.RecursionAvailable {
		dh.Bits |= _RA
	}
	if m.Zero {
		dh.Bits |= _Z
	}
	if m.AuthenticatedData {
		dh.Bits |= _AD
	}
	if m.CheckingDisabled {
		dh.Bits |= _CD
	}

	dh.Qdcount = uint16(len(m.Question))
	dh.Ancount = uint16(len(m.Answer))
	dh.Nscount = uint16(len(m.Ns))
	dh.Arcount = uint16(len(m.Extra) + m.isPseudo())

	// We need the uncompressed length here, because we first pack it and then compress it.
	l := m.Len()
	if cap(m.Data) < l {
		m.Data = make([]byte, l)
	} else {
		m.Data = m.Data[:l]
	}

	// Pack it in: header and then the pieces.
	off := 0
	var err error
	if off, err = dh.pack(m.Data, off); err != nil {
		return err
	}

	// Is this compressible?
	var compression map[string]uint16
	if len(m.Question) > 1 || len(m.Answer) > 0 || len(m.Ns) > 0 || len(m.Extra) > 0 {
		compression = make(map[string]uint16, len(m.Answer)+len(m.Ns)+len(m.Extra)+3) // 3 is randomly choosen, as such much rdata might be compressable...
	}

	for i := range m.Question {
		if off, err = packQuestion(m.Question[i], m.Data, off, compression); err != nil {
			return err
		}
		break // allow only one
	}
	for i := range m.Answer {
		if _, off, err = packRR(m.Answer[i], m.Data, off, compression); err != nil {
			return err
		}
	}
	for i := range m.Ns {
		if _, off, err = packRR(m.Ns[i], m.Data, off, compression); err != nil {
			return err
		}
	}
	for i := range m.Extra {
		if _, off, err = packRR(m.Extra[i], m.Data, off, compression); err != nil {
			return err
		}
	}

	// Add an OPT RR if we see any of these.
	if m.isPseudo() > 0 {
		opt := &OPT{} // hack, empty name, that gets filled if we did something
		if m.UDPSize > MinMsgSize {
			opt.Hdr.Name = "."
			opt.SetUDPSize(m.UDPSize)
		}
		if m.Rcode > 0xF {
			opt.Hdr.Name = "."
			opt.SetRcode(m.Rcode) // we leave m.Rcode as packing/unpacking will set the correct bits there.
		}
		if m.Security {
			opt.Hdr.Name = "."
			opt.SetSecurity(true)
		}
		if m.CompactAnswers {
			opt.Hdr.Name = "."
			opt.SetCompactAnswers(true)
		}
		if m.Delegation {
			opt.Hdr.Name = "."
			opt.SetDelegation(true)
		}
		for i := range m.Pseudo {
			if edns0, ok := m.Pseudo[i].(EDNS0); ok {
				opt.Hdr.Name = "."
				opt.Options = append(opt.Options, edns0)
			}
		}
		// Only pack opt if something has been put into it, otherwise we may have a TSIG/SIG0.
		// Pack it here so we don't add it the m.Extra, as the options (only) should be available in pseudo.
		// Also OPT may be anywhere in m.Extra, here it will be first.
		if opt.Hdr.Name == "." {
			if _, off, err = packRR(opt, m.Data, off, nil); err != nil {
				return err
			}
		}
	}

	// records that really need to be last, TSIG or SGI0
	for i := range m.Pseudo {
		_, ok1 := m.Pseudo[i].(*TSIG)
		_, ok2 := m.Pseudo[i].(*SIG)
		if ok1 || ok2 {
			if _, off, err = packRR(m.Pseudo[i], m.Data, off, compression); err != nil {
				return err
			}
		}
	}
	m.Data = m.Data[:off]
	return nil
}

// We only allow a single question in the question section.
func (m *Msg) unpackQuestion(msg *cryptobyte.String, msgBuf []byte) (RR, error) {
	name, err := unpack.Name(msg, msgBuf)
	if err != nil {
		return nil, err
	}
	var qtype uint16
	if !msg.Empty() && !msg.ReadUint16(&qtype) {
		return nil, unpack.Errorf("overflow %s", "Question type")
	}
	m.qtype = qtype

	var qclass uint16
	if !msg.Empty() && !msg.ReadUint16(&qclass) {
		return nil, unpack.Errorf("overflow %s", "Question class")
	}

	var rr RR
	if newFn, ok := TypeToRR[qtype]; ok {
		rr = newFn()
		*rr.Header() = Header{Name: name, Class: qclass}
	} else {
		rr = &RFC3597{Header{Name: name, Class: qclass}, rdata.RFC3597{RRType: qtype}}
	}
	return rr, nil
}

func (m *Msg) unpackQuestions(cnt uint16, msg *cryptobyte.String, msgBuf []byte) ([]RR, error) {
	// We don't preallocate dst according to cnt as that value may be attacker
	// controlled. A malicious adversary could send us as 12-byte packet
	// containing only the header that claims to contain 65535 questions. As
	// Question takes 24-bytes, we'd end up allocating more than 1.5MiB from a
	// mere 12-byte packet.
	dst := make([]RR, 0, 1)
	for i := 0; i < int(cnt); i++ {
		r, err := m.unpackQuestion(msg, msgBuf)
		if err != nil {
			return dst, err
		}
		dst = append(dst, r)
	}
	return dst, nil
}

func unpackRRs(cnt uint16, msg *cryptobyte.String, msgBuf []byte) ([]RR, error) {
	if cnt == 0 {
		return []RR{}, nil
	}
	// See unpackQuestions for why we don't pre-allocate here.
	dst := make([]RR, 0, min(5, cnt))
	for i := 0; i < int(cnt); i++ {
		r, err := unpackRR(msg, msgBuf)
		if err != nil {
			return dst, err
		}
		dst = append(dst, r)
	}

	return dst, nil
}

func (m *Msg) unpack(dh header, s *cryptobyte.String, msgBuf []byte) (err error) {
	if m.offset > MsgHeaderSize {
		if !s.Skip(int(m.offset - MsgHeaderSize)) {
			return fmt.Errorf("overflow %s", "MsgHeader")
		}
		goto Rest
	}

	if m.Question, err = m.unpackQuestions(dh.Qdcount, s, msgBuf); err != nil {
		return err
	}
	if m.Options > 0 && m.Options <= MsgOptionUnpackQuestion {
		m.offset = uint16(len(msgBuf) - len(*s))
		return nil
	}

Rest:
	m.offset = 0 // reset offset here, as it has done its purpose
	if m.Answer, err = unpackRRs(dh.Ancount, s, msgBuf); err != nil {
		return err
	}
	if m.Options > 0 && m.Options <= MsgOptionUnpackAnswer {
		return nil
	}

	if m.Ns, err = unpackRRs(dh.Nscount, s, msgBuf); err != nil {
		return err
	}

	if m.Extra, err = unpackRRs(dh.Arcount, s, msgBuf); err != nil {
		return err
	}

	// Check for the OPT RR and remove it entirely, unpack the OPT for option codes and put those in the Pseudo
	// section. We will only check one OPT, any others will be left in Extra.
	for i := 0; i < len(m.Extra); i++ {
		if opt, ok := m.Extra[i].(*OPT); ok {
			m.Security = opt.Security()
			m.CompactAnswers = opt.CompactAnswers()
			m.Delegation = opt.Delegation()
			m.Rcode += opt.Rcode() // See TestMsgExtendedRcode.
			m.Version = opt.Version()
			// RFC 6891 mandates that the payload size in an OPT record less than 512 (MinMsgSize) bytes must be treated as equal to 512 bytes.
			m.UDPSize = max(opt.UDPSize(), MinMsgSize)

			m.Pseudo = make([]RR, len(opt.Options), len(opt.Options)+1) // +1 for tsig/sig zero, avoid 2x in a append
			for i := range opt.Options {
				m.Pseudo[i] = RR(opt.Options[i])
			}
			m.Extra[i] = m.Extra[len(m.Extra)-1] // opt's place taken with last rr
			m.Extra = m.Extra[:len(m.Extra)-1]   // remove the OPT RR

			break
		}
	}

	// Check for m.Extra TSIG and SIG(0) and move them to pseudo. This MUST be the the last RR in the extra section.
	// But as we may have moved things around, we need to iterate over m.Extra again.
	for i := 0; i < len(m.Extra); i++ {
		_, ok1 := m.Extra[i].(*TSIG)
		_, ok2 := m.Extra[i].(*SIG)
		if ok1 || ok2 {
			m.Pseudo = append(m.Pseudo, m.Extra[i])
			m.Extra[i] = m.Extra[len(m.Extra)-1] // sig/tsig's place taken with last rr
			m.Extra = m.Extra[:len(m.Extra)-1]   // remove the sig/tsig RR

			break
		}
	}

	if !s.Empty() {
		return unpack.Errorf("%d more octets", len(*s))
	}
	return nil
}

// Unpack unpacks a binary message that sits in m.Data to a Msg structure.
func (m *Msg) Unpack() error {
	s := cryptobyte.String(m.Data)
	var dh header
	if !dh.unpack(&s) {
		return unpack.Errorf("overflow %s", "MsgHeader")
	}
	m.setMsgHeader(dh)
	if m.Options > 0 && m.Options <= MsgOptionUnpackHeader {
		return nil
	}

	return m.unpack(dh, &s, m.Data)
}

// Convert a complete message to a string with dig-like output. String also looks at the [Msg.Options] and
// only prints up to that point, i.e. options set to [MsgOptionUnpackHeader] means String will only return the
// header. The string format isn't fixed and can change in future released, [dnsutil.StringToMsg] is
// guaranteed to work.
func (m *Msg) String() string {
	if m == nil {
		return "<nil> Msg"
	}
	sb := builderPool.Get()

	sb.WriteString(m.MsgHeader.String())
	// if core EDNS flags are set, we print this (flags are already handled in MsgHeader)
	if m.UDPSize > 0 || m.Security || m.CompactAnswers || m.Delegation {
		sb.WriteString(";; EDNS, version: ")
		sb.WriteString(strconv.Itoa(int(m.Version)))
		sb.WriteString(", udp: ")
		sb.WriteString(strconv.Itoa(int(m.UDPSize)))
		sb.WriteByte('\n')
	}

	sections := [5]string{"QUESTION", "PSEUDO", "ANSWER", "AUTHORITY", "ADDITIONAL"}
	const (
		Question = iota
		Pseudo
		Answer
		Authority
		Additional
		// Stateful
	)
	sb.WriteString(";; ")
	sb.WriteString(sections[Question])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Question)))
	sb.WriteString(", ")

	sb.WriteString(sections[Pseudo])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Pseudo)))
	sb.WriteString(", ")

	sb.WriteString(sections[Answer])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Answer)))
	sb.WriteString(", ")

	sb.WriteString(sections[Authority])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Ns)))
	sb.WriteString(", ")

	sb.WriteString(sections[Additional])
	sb.WriteString(": ")
	sb.WriteString(strconv.Itoa(len(m.Extra)))
	sb.WriteString(", ")

	sb.WriteString("DATA SIZE: ")
	sb.WriteString(strconv.Itoa(len(m.Data)))
	sb.WriteByte('\n')

	if m.Options > 0 && m.Options <= MsgOptionUnpackHeader {
		return sb.String()
	}

	if len(m.Question) > 0 {
		sb.WriteString("\n;; ")
		sb.WriteString(sections[Question])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Question {
			// as we fake RRs to be present in the question section, just manual unpack print the header without the TTL here.
			sb.WriteString(r.Header().Name)
			sb.WriteByte('\t')
			sb.WriteByte('\t')
			sb.WriteString(classToString(r.Header().Class))
			sb.WriteByte('\t')
			rrtype := RRToType(r)
			if rrtype == 0 {
				if r1, ok := r.(*RFC3597); ok {
					rrtype = r1.RRType
				}
			}
			sb.WriteString(typeToString(rrtype))
			sb.WriteByte('\n')
		}
	}
	if m.Options > 0 && m.Options <= MsgOptionUnpackQuestion {
		return sb.String()
	}
	if len(m.Pseudo) > 0 {
		sb.WriteString("\n;; ")
		sb.WriteString(sections[Pseudo])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Pseudo {
			sb.WriteString(r.String())
			sb.WriteByte('\n')
		}
	}
	if len(m.Answer) > 0 {
		sb.WriteString("\n;; ")
		sb.WriteString(sections[Answer])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Answer {
			sb.WriteString(r.String())
			sb.WriteByte('\n')
		}
	}
	if m.Options > 0 && m.Options <= MsgOptionUnpackAnswer {
		return sb.String()
	}
	if len(m.Ns) > 0 {
		sb.WriteString("\n;; ")
		sb.WriteString(sections[Authority])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Ns {
			sb.WriteString(r.String())
			sb.WriteByte('\n')
		}
	}
	if len(m.Extra) > 0 {
		sb.WriteString("\n;; ")
		sb.WriteString(sections[Additional])
		sb.WriteString(" SECTION:\n")
		for _, r := range m.Extra {
			sb.WriteString(r.String())
			sb.WriteByte('\n')
		}
	}
	s := sb.String()
	builderPool.Put(sb)
	return s
}

// isPseudo returns (1) true of we should have a pseudo section in this message, or not (0). It returns an
// int becuse we need that number of the Extra section sizing.
func (m *Msg) isPseudo() int {
	if len(m.Pseudo) > 0 || m.UDPSize > MinMsgSize || m.Security || m.CompactAnswers || m.Delegation || m.Rcode > 0xF {
		return 1
	}
	return 0
}

// Len returns the message length when in uncompressed wire format.
func (m *Msg) Len() int {
	l := MsgHeaderSize

	for i := range m.Question {
		l += m.Question[i].Len()
	}
	for i := range m.Answer {
		l += m.Answer[i].Len()
	}
	for i := range m.Ns {
		l += m.Ns[i].Len()
	}
	for i := range m.Extra {
		l += m.Extra[i].Len()
	}
	for i := range m.Pseudo {
		l += m.Pseudo[i].Len()
	}

	const minHeaderSize = 11 // smallest possible RR header where the name is the root label.

	if m.isPseudo() > 0 {
		// If we find things in pseudo we get an OPT RR (fix length) plus the length of the option. OPT is always 11, 10 + "." (root label)
		l += minHeaderSize
	}

	if l > MaxMsgSize {
		return MaxMsgSize
	}

	return l
}

func (dh *header) pack(msg []byte, off int) (int, error) {
	off, err := pack.Uint16(dh.ID, msg, off)
	if err != nil {
		return off, pack.Errorf(": %s", "header.ID")
	}
	off, err = pack.Uint16(dh.Bits, msg, off)
	if err != nil {
		return off, pack.Errorf(": %s", "header.Bits")
	}
	off, err = pack.Uint16(dh.Qdcount, msg, off)
	if err != nil {
		return off, pack.Errorf(": %s", "header.Qdcount")
	}
	off, err = pack.Uint16(dh.Ancount, msg, off)
	if err != nil {
		return off, pack.Errorf(": %s", "header.Ancount")
	}
	off, err = pack.Uint16(dh.Nscount, msg, off)
	if err != nil {
		return off, pack.Errorf(": %s", "header.Nscount")
	}
	off, err = pack.Uint16(dh.Arcount, msg, off)
	if err != nil {
		return off, pack.Errorf(": %s", "header.Arcount")
	}
	return off, nil
}

func (dh *header) unpack(msg *cryptobyte.String) bool {
	return msg.ReadUint16(&dh.ID) &&
		msg.ReadUint16(&dh.Bits) &&
		msg.ReadUint16(&dh.Qdcount) &&
		msg.ReadUint16(&dh.Ancount) &&
		msg.ReadUint16(&dh.Nscount) &&
		msg.ReadUint16(&dh.Arcount)
}

// setHdr set the header in the dns using the binary data in dh.
func (m *Msg) setMsgHeader(dh header) {
	m.ID = dh.ID
	m.Response = dh.Bits&_QR != 0
	m.Opcode = uint8(dh.Bits>>11) & 0xF
	m.Authoritative = dh.Bits&_AA != 0
	m.Truncated = dh.Bits&_TC != 0
	m.RecursionDesired = dh.Bits&_RD != 0
	m.RecursionAvailable = dh.Bits&_RA != 0
	m.Zero = dh.Bits&_Z != 0 // _Z covers the zero bit, which should be zero; not sure why we set it to the opposite.
	m.AuthenticatedData = dh.Bits&_AD != 0
	m.CheckingDisabled = dh.Bits&_CD != 0
	m.Rcode = dh.Bits & 0xF
}

// Hijack allows user hijacking the allocation in m.Data; this means that when the message is written through
// the default ResponseWriter its buffer is not returned the message pool. This is only applicable when the
// message was created by the default server.
func (m *Msg) Hijack() { m.hijacked.Store(true) }

// io.Reader and io.Writer interfaces implementation.

// Write writes the buffer p to the m.Data. If m's Data buffer is empty Pack() is called.
func (m *Msg) Write(p []byte) (n int, err error) {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return 0, err
		}
	}
	n = copy(m.Data, p)
	return n, nil
}

// Read reads the data from m.Data into p. If m's Data buffer is empty Pack() is called.
func (m *Msg) Read(p []byte) (n int, err error) {
	// TODO(miek): pool allocation here?
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return 0, err
		}
	}
	n = copy(p, m.Data)
	if len(p) > len(m.Data) {
		return n, io.EOF
	}
	return n, nil
}

// WriteTo writes the message to w. w must be a [ResponseWriter], when w is _not_ a *net.UDPConn, the write is
// prefixed with an uint16 with the length of the buffer, otherwise the m.Data is written as-is. If w is a
// [ResponseController] a write timeout is applied.
//
// If the message has not be hijacked, and m was create by the server, the Data buffer is returned
// to the server's pool and zeroed out in m.
func (m *Msg) WriteTo(w io.Writer) (int64, error) {
	r, ok := w.(ResponseWriter)
	if !ok {
		return 0, fmt.Errorf("dns: writer is not a ResponseWriter")
	}

	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return 0, err
		}
	}

	if rc, ok := w.(ResponseController); ok {
		rc.SetWriteDeadline()
	}

	if sock, ok := r.Conn().(*net.UDPConn); ok {
		sess := r.Session()
		if sess != nil {
			oob := sourceFromOOB(sess.OOB)
			n, _, err := sock.WriteMsgUDP(m.Data, oob, sess.Addr)
			if m.msgPool != nil && !m.hijacked.Load() {
				m.msgPool.Put(m.Data)
				m.Data, m.msgPool = nil, nil
			}
			return int64(n), err
		}

		n, err := r.Conn().Write(m.Data)
		if m.msgPool != nil && !m.hijacked.Load() {
			m.msgPool.Put(m.Data)
			m.Data, m.msgPool = nil, nil
		}
		return int64(n), err
	}

	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(m.Data)))
	l = append(l, m.Data...)
	n, err := r.Write(l)
	if m.msgPool != nil && !m.hijacked.Load() {
		m.msgPool.Put(m.Data)
		m.Data, m.msgPool = nil, nil
	}
	return int64(n), err
}

// ReadFrom reads from r. When r is a *net.TCPConn, first 2 bytes of length are read, then m.Data is *resized*
// to this length and the data is read. Otherwise the data is read into m.Data. It is expected any deadlines
// are set if there is an underlying socket. No read timeouts are applied.
func (m *Msg) ReadFrom(r io.Reader) (int64, error) {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return 0, err
		}
	}

	if sock, ok := r.(*net.UDPConn); ok {
		n, err := sock.Read(m.Data)
		if err != nil {
			return 0, err
		}
		m.Data = m.Data[:n]
		return int64(n), nil
	}

	// When doing io.Copy that underlaying type we get from net is net.tcpConnWithoutWriteTo, not a
	// net.TCPConn.For udp this seems not to be the case, so the fallthrough when things are not UDP like
	// is too assume TCP.

	l := uint16(0)
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return 0, err
	}
	li := int(l)
	if li < MsgHeaderSize {
		io.Copy(io.Discard, io.LimitReader(r, int64(li))) // discard the remaining octets
		return 0, fmt.Errorf("dns: TCP message size %d, can not be smaller than %d", li, MsgHeaderSize)
	}

	if len(m.Data) < li {
		m.Data = append(m.Data, make([]byte, li-len(m.Data))...)
	} else {
		m.Data = m.Data[:li]
	}
	n, err := io.ReadFull(r, m.Data)
	if err != nil {
		m.Data = m.Data[:n]
	}
	return int64(n), err
}

// RRs allows ranging over the RRs of all the sections in m. This includes the question, pseudo and stateful
// sections.
func (m *Msg) RRs() iter.Seq[RR] {
	return func(yield func(RR) bool) {
		for {
			for i := range m.Question {
				if !yield(m.Question[i]) {
					return
				}
			}
			for i := range m.Answer {
				if !yield(m.Answer[i]) {
					return
				}
			}
			for i := range m.Ns {
				if !yield(m.Ns[i]) {
					return
				}
			}
			for i := range m.Extra {
				if !yield(m.Extra[i]) {
					return
				}
			}
			for i := range m.Pseudo {
				if !yield(m.Pseudo[i]) {
					return
				}
			}
			break
		}
	}
}

// Copy returns a shallow copy of the message, specifically the RR contained in the message are copied by
// reference, not via a deep copy. If m was hijacked via [Msg.Hijack] the returned Msg will not be hijacked.
// The msgPool of m will be copied, meaning the new message when traversing a default [dns.ResponseWriter]
// will have it's buffer returned to the servers msg pool.
func (m *Msg) Copy() *Msg {
	return &Msg{
		MsgHeader: m.MsgHeader,
		Question:  m.Question,
		Answer:    m.Answer,
		Ns:        m.Ns,
		Extra:     m.Extra,
		Pseudo:    m.Pseudo,
		Data:      m.Data,
		msgPool:   m.msgPool,
	}
}

// NewMsg returns a new message with the question section sets to z (z is made fully qualified) and the type t. If the type isn't know nil
// is returned, the recursion desired bit is set.
func NewMsg(z string, t uint16) *Msg {
	var rr RR
	newFn, ok := TypeToRR[t]
	if !ok {
		return nil
	}
	m := new(Msg)
	m.ID = ID()
	m.RecursionDesired = true
	rr = newFn()
	rr.Header().Name = dnsutilFqdn(z)
	rr.Header().Class = ClassINET
	m.Question = []RR{rr}
	return m
}
