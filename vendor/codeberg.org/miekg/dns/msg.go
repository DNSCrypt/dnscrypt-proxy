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
	if rdlength <= MaxMsgSize { // overflow
		// The RDLENGTH field is the last field in the header and we set it here.
		binary.BigEndian.PutUint16(msg[headerEnd-2:], uint16(rdlength))
		return headerEnd, off1, nil
	}

	return headerEnd, len(msg), pack.Errorf("inconsistent rdata length")
}

func unpackRR(msg *cryptobyte.String, msgBuf []byte) (RR, error) {
	h := &Header{}
	typ, rdlength, err := unpackHeader(h, msg, msgBuf)
	if err != nil {
		return nil, err
	}

	// Directly use the existing buffer by slicing the cryptobyte.String
	// 1. Verify sufficient bytes remain
	if len(*msg) < int(rdlength) {
		return nil, unpack.ErrTruncatedMessage
	}

	// was: msg.ReadBytes(&data, int(rdlength)), but we want to save the buffer we allocated for that.
	data := (*msg)[:rdlength]
	*msg = (*msg)[rdlength:]
	msgBuf = msgBuf[:unpack.Offset(*msg, msgBuf)]

	var rr RR
	if newFn, ok := TypeToRR[typ]; ok {
		rr = newFn()
		*rr.Header() = *h
	} else {
		rr = &RFC3597{Hdr: *h}
	}

	if rdlength == 0 {
		return rr, nil
	}

	if err := zunpack(rr, cryptobyte.String(data), msgBuf); err != nil {
		return rr, err
	}

	return rr, nil
}

// Reset resets the message's answer, ns, extra and pseudo sections to a zero length slice, thereby emptying
// them, but keeping the capacity.
func (m *Msg) Reset() {
	m.Answer, m.Ns, m.Extra, m.Pseudo = m.Answer[:0], m.Ns[:0], m.Extra[:0], m.Pseudo[:0]
}

func (m *Msg) Pack() error {
	if l := m.Len(); cap(m.Data) < l {
		m.Data = make([]byte, l)
	} else {
		m.Data = m.Data[:l]
	}

	off, err := pack.Uint16(m.ID, m.Data, 0)
	if err != nil {
		return pack.Errorf(": %s", "MsgHeader ID")
	}

	bits := uint16(m.Opcode)<<11 | uint16(m.Rcode&0xF)
	if m.Response {
		bits |= _QR
	}
	if m.Authoritative {
		bits |= _AA
	}
	if m.Truncated {
		bits |= _TC
	}
	if m.RecursionDesired {
		bits |= _RD
	}
	if m.RecursionAvailable {
		bits |= _RA
	}
	if m.Zero {
		bits |= _Z
	}
	if m.AuthenticatedData {
		bits |= _AD
	}
	if m.CheckingDisabled {
		bits |= _CD
	}

	off, err = pack.Uint16(bits, m.Data, off)
	if err != nil {
		return pack.Errorf(": %s", "MsgHeader bits")
	}

	isPseudo := m.isPseudo()
	counts := uint64(len(m.Question)<<48) |
		uint64(len(m.Answer)<<32) |
		uint64(len(m.Ns)<<16) |
		uint64(len(m.Extra)+int(isPseudo))

	off, err = pack.Uint64(counts, m.Data, off)
	if err != nil {
		return pack.Errorf(": %s", "MsgHeader")
	}

	// Is this compressible?
	var compression map[string]uint16
	if l := len(m.Answer) + len(m.Ns) + len(m.Extra); l > 0 {
		compression = make(map[string]uint16, l+3) // 3 is randomly chosen, as that much rdata might be compressable...
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
	tsigOrsig0 := false
	if isPseudo > 0 {
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
			opt.Hdr.Name = "."
			switch x := m.Pseudo[i].(type) {
			case EDNS0:
				opt.Options = append(opt.Options, x)
			default:
				tsigOrsig0 = true
			}
		}
		// Only pack opt if something has been put into it, otherwise we may have a TSIG/SIG0.
		// Pack it here so we don't add it the m.Extra, as the options (only) should be available in pseudo.
		// Also OPT may be anywhere in m.Extra, here it will be first.
		if len(opt.Hdr.Name) != 0 {
			if _, off, err = packRR(opt, m.Data, off, nil); err != nil {
				return err
			}
		}
	}

	// records that really need to be last, TSIG or SGI0. "Checked" above, we just assume it is the last.
	if tsigOrsig0 {
		if _, off, err = packRR(m.Pseudo[len(m.Pseudo)-1], m.Data, off, compression); err != nil {
			return err
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
		return nil, nil
	}
	// See unpackQuestions for why we don't pre-allocate here.
	dst := make([]RR, 0, min(3, cnt))
	for i := 0; i < int(cnt); i++ {
		r, err := unpackRR(msg, msgBuf)
		if err != nil {
			return dst, err
		}
		dst = append(dst, r)
	}

	return dst, nil
}

// Unpack unpacks a binary message that sits in m.Data to a Msg structure.
func (m *Msg) Unpack() (err error) {
	s := cryptobyte.String(m.Data)
	var counts uint64 // read all counters into 64 bits and slice the 16 bits values out of it
	var bits uint16
	if !s.ReadUint16(&m.ID) || !s.ReadUint16(&bits) || !s.ReadUint64(&counts) {
		return unpack.Errorf("overflow %s", "MsgHeader")
	}
	m.Response = bits&_QR != 0
	m.Opcode = uint8(bits>>11) & 0xF
	m.Authoritative = bits&_AA != 0
	m.Truncated = bits&_TC != 0
	m.RecursionDesired = bits&_RD != 0
	m.RecursionAvailable = bits&_RA != 0
	m.Zero = bits&_Z != 0 // _Z covers the zero bit, which should be zero; not sure why we set it to the opposite.
	m.AuthenticatedData = bits&_AD != 0
	m.CheckingDisabled = bits&_CD != 0
	m.Rcode = bits & 0xF

	if m.Options > 0 && m.Options <= MsgOptionUnpackHeader {
		return nil
	}

	if m.offset > MsgHeaderSize {
		if !s.Skip(int(m.offset - MsgHeaderSize)) {
			return fmt.Errorf("overflow %s", "MsgHeader")
		}
		goto Rest
	}

	if m.Question, err = m.unpackQuestions(uint16((counts>>48)&0xFFFF), &s, m.Data); err != nil {
		return err
	}
	if m.Options > 0 && m.Options <= MsgOptionUnpackQuestion {
		m.offset = uint16(len(m.Data) - len(s))
		return nil
	}

Rest:
	m.offset = 0 // reset offset here, as it has done its purpose
	if m.Answer, err = unpackRRs(uint16((counts>>32)&0xFFFF), &s, m.Data); err != nil {
		return err
	}
	if m.Options > 0 && m.Options <= MsgOptionUnpackAnswer {
		return nil
	}

	if m.Ns, err = unpackRRs(uint16((counts>>16)&0xFFFF), &s, m.Data); err != nil {
		return err
	}

	if m.Extra, err = unpackRRs(uint16(counts&0xFFFF), &s, m.Data); err != nil {
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
		return unpack.Errorf("%d more octets", len(s))
	}
	return nil
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
func (m *Msg) isPseudo() uint8 {
	if lp := len(m.Pseudo); lp > 0 || m.UDPSize > MinMsgSize || m.Security || m.CompactAnswers || m.Delegation || m.Rcode > 0xF {
		if lp == 0 {
			return 1 // OPT without options, 1 record
		}
		switch m.Pseudo[lp-1].(type) {
		// OPT + one of these
		case *TSIG:
			return 2
		case *SIG:
			return 2
		}
		return 1 // OPT with options, still 1 record
	}
	return 0
}

// Len returns the message length when in uncompressed wire format.
func (m *Msg) Len() int {
	l := MsgHeaderSize

	for i := range m.Question {
		// See Header.Len() too, we always add a +1, even if the name is the root label.
		// 4 is for the type and class
		l += len(m.Question[i].Header().Name) + 1 + 4
		break
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

	// Smallest possible RR header where the name is the root label. This should actually be 11, but we return
	// len(name) +1 for all domain names, which is not correct for the root which is just 1.
	const minHeaderSize = 12

	// isPseudo call is basically already done in the above loop where we get the length, only things left
	// are the extra checks we do here. See [isPseudo] and keep in sync.
	if len(m.Pseudo) > 0 || m.UDPSize > MinMsgSize || m.Security || m.CompactAnswers || m.Delegation || m.Rcode > 0xF {
		// If we find things in pseudo we get an OPT RR (fix length) plus the length of the option. OPT is always 11, 10 + "." (root label)
		l += minHeaderSize
	}

	return min(l, MaxMsgSize)
}

// Hijack allows user hijacking the allocation in m.Data; this means that when the message is written through
// the default ResponseWriter its buffer is not returned the message pool. This is only applicable when the
// message was created by the default server.
func (m *Msg) Hijack() { m.hijacked.Store(true) }

// io.Reader and io.Writer interfaces implementation.

// Write writes the buffer p to the m.Data. If m's Data buffer is empty [Msg.Pack] is called.
func (m *Msg) Write(p []byte) (n int, err error) {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return 0, err
		}
	}
	n = copy(m.Data, p)
	return n, nil
}

// Read reads the data from m.Data into p. If m's Data buffer is empty [Msg.Pack] is called.
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
// sections. See [ZoneParser.RRs] also.
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
