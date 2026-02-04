package dnsutil

import "codeberg.org/miekg/dns"

// SetQuestion set the question section in the message m.
// It generates an ID and sets the RecursionDesired (RD) bit to true.
// If the type t isn't known to this library, nil is returned. Also see [dns.NewMsg].
func SetQuestion(m *dns.Msg, z string, t uint16) *dns.Msg {
	m.ID = dns.ID()
	m.RecursionDesired = true
	var rr dns.RR
	newFn, ok := dns.TypeToRR[t]
	if !ok {
		return nil
	}
	rr = newFn()
	rr.Header().Name = z
	rr.Header().Class = dns.ClassINET

	m.Question = []dns.RR{rr}
	return m
}

// Question returns the question name and the type from the message m.
func Question(m *dns.Msg) (z string, t uint16) {
	z = m.Question[0].Header().Name
	t = dns.RRToType(m.Question[0])
	return z, t
}

// SetReply creates a reply message from r. It copies the ID, opcode, rcode and question, r's Data buffer is not copied.
// In the header the RecursionDesired, CheckingDisabled and Security bit are copied. All other sections are
// resliced to length zero.
func SetReply(m, r *dns.Msg) *dns.Msg {
	m.ID = r.ID
	m.Response = true
	m.Opcode = r.Opcode
	if m.Opcode == dns.OpcodeQuery {
		m.RecursionDesired = r.RecursionDesired
		m.CheckingDisabled = r.CheckingDisabled
		m.Security = r.Security
	}
	m.Rcode = dns.RcodeSuccess
	m.Question = r.Question
	m.Reset()
	return m
}

// IsRRset reports whether a set of RRs is a valid RRset as defined by RFC 2181.
// This means the RRs need to have the same type, name, and class. Duplicate RRs are not detected.
// See [dns.RRset] if you need to sort an RRset.
func IsRRset(rrset []dns.RR) bool {
	if len(rrset) == 0 {
		return false
	}
	base := rrset[0].Header()
	basetype := dns.RRToType(rrset[0])
	for _, rr := range rrset[1:] {
		h := rr.Header()
		htype := dns.RRToType(rr)
		if htype != basetype || h.Class != base.Class || !dns.EqualName(h.Name, base.Name) {
			return false
		}
	}
	return true
}
