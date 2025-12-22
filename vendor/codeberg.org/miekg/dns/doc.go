/*
Package dns implements a full featured interface to the Domain Name System. Both server- and client-side programming is supported.

The package allows complete control over what is sent out to the DNS. The API follows the less-is-more principle, by presenting a small, clean interface.

It supports (asynchronous) querying/replying, incoming/outgoing zone transfers,
TSIG, EDNS0, dynamic updates, notifies and DNSSEC validation/signing.

Resource records (RRs) are native types. They are not stored in wire format, but every [Msg] holds the wire-format in its Data field.
Everything is modelled or made to look like an RR.
The question section holds an RR and the EDNS0 option codes are also (fake/pseudo) RRs. These EDNS0 option occupy
a separate section in [Msg], the pseudo section.

Basic usage pattern for creating a new resource record:

	r := &MX{Header{Name:"miek.nl.", Class: dns.ClassINET, TTL: 3600}, MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}

Or directly from a string (which is much slower):

	mx, err := dns.New("miek.nl. 3600 IN MX 10 mx.miek.nl.")

Or when the default origin (.) and TTL (3600) and class (IN) suit you:

	mx, err := dns.New("miek.nl MX 10 mx.miek.nl")

Or even:

	mx, err := dns.New("$ORIGIN nl.\nmiek 1H IN MX 10 mx.miek")

In the DNS, messages are exchanged, these messages contain RRs (RRsets). Use pattern for creating a message:

	m := new(dns.Msg)
	m.Question = []dns.RR{mx}

The message m is now a message with the question section set to ask the MX records for the miek.nl. zone. Or when making an actual request.

	m.ID = dns.ID()
	m.RecursionDesired = true

After creating a message it can be sent. Basic use pattern for synchronous querying the DNS at a server configured on 127.0.0.1 and port 53 using UDP:

	c := new(dns.Client)
	r, rtt, err := c.Exchange(m, "udp", "127.0.0.1:53")

When this functions returns you will get DNS message back. A DNS message consists out of four (five in this package) sections.

  - The question section: r.Question.
  - The answer section: r.Answer.
  - The authority section: r.Ns.
  - The additional section: r.Extra.
  - And the extra and new fifth the pseudo section: r.Pseudo, see [Msg].

The latter was added to make it easier to deal with EDNS0 option codes, which become more and more prevalent.

Each of these sections contain a []RR. Basic use pattern for accessing the rdata of a TXT RR as the first RR in
the Answer section:

	if t, ok := r.Answer[0].(*dns.TXT); ok {
		// do something with t.TXT.Txt
	}

Or if you sent an NSID EDNS0 option:

	if n, ok := r.Pseudo[0].(*dns.NSID); ok {
		// do something with n.Nsid
	}

# Domain Name and TXT Character String Representations

Domain names are converted to presentation form as-is, there is no conversion of unprintable characters, i.e.
\DDD are left as-is.

TXT character strings are converted to presentation form both when unpacked and when converted to strings.
Tabs, carriage returns and line feeds will be converted to \t, \r and \n respectively. Back slashes and
quotations marks will be escaped. Bytes below 32 and above 127 will be converted to \DDD form.

# DNSSEC

DNSSEC (DNS Security Extension) adds a layer of security to the DNS. It uses
public key cryptography to sign resource records. The public keys are stored in
DNSKEY records and the signatures in RRSIG records.

Requesting DNSSEC information for a zone is done by adding the DO (DNSSEC OK)
bit to a request.

	m := new(dns.Msg)
	m.Security = true
	m.UDPSize = 4096

When sending a message [Msg.Pack] is called, this takes care of allocating an OPT RR and setting the DO bit and the
UDPSize in there.

Signature generation, signature verification (see [RRSIG]) and key generation are all supported.

# EDNS0

EDNS0 is an extension mechanism for the DNS defined in RFC 2671 and updated by RFC 6891. It defines a RR type,
the [OPT] RR, which holds type-length-value sub-types.
In this package all EDNS0 options are implemented as RRs. Doing basic "EDNS0" things, like
setting the DNSSEC OK bit (DO) or the UDP buffer size is handled for you and these can be set directly on message as shown above.

The data of an OPT RR sits in the [Msg] Pseudo section consists out of a slice of EDNS0 (RFC 6891) interfaces.
These are just RRs with an extra Pseudo() method.

Basic use pattern for a server to check if (and which) options are set, which is similar to how to deal with RRs.

	for _, rr := range m.Pseudo {
		switch x := rr.(type) {
		case *dns.NSID:
			// do stuff with x.Nsid
		case *dns.SUBNET:
			// access x.Family, x.Address, etc.
		}
	}

# Private Resource Records

Any struct can be used as a private resource record. To make it work you need to implement the following interfaces.

  - [Typer], to give your RR a code point, and see documentation of that interface.
  - [RR], all RRs implement this, if you want to have a private EDNS0 option, implement [EDNS0] interface, this
    adds a Pseudo() bool method.
  - [Parser], so it can be parsed to and from strings.
  - [Packer], if you need to use your new RR on the wire.
  - [Comparer], if your RR will be signed with DNSSEC.

See rr_test.for a complete example.

# Further Reading

All functionality and types are documented in their respective types and functions.
*/
package dns
