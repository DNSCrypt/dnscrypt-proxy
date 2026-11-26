/*
Package dns implements a full featured interface to the Domain Name System - DNS (RFC 1033, 1034, 1035, 4033,
4034, 4035). Both server- and client-side programming is supported.

The package allows complete control over what is sent out to the DNS. The API follows the less-is-more
principle, by presenting a small, clean interface.

It supports (asynchronous) querying/replying, incoming/outgoing zone transfers, [TSIG], [EDNS0], dynamic
updates, notifies and DNSSEC validation/signing.

Resource records ([RR]s) are native types. They are not stored in wire format, but every [Msg] holds the
wire-format in its [Msg.Data] field. Everything is modelled (or made) to look like an RR: the question section
holds a [RR] and the [EDNS0] option codes are also RRs. These EDNS0 options occupy a separate section in
[Msg], the [Msg.Pseudo] section.

In the DNS, messages are exchanged, these messages contain RRs and/or RRsets ([RRset]). Basic pattern for
creating a message:

	m := dns.NewMsg("miek.nl.", dns.TypeMX)

The message m is now a message with the question section set to ask the [MX] records for the miek.nl. zone.
After creating a message it can be sent. Basic use pattern for synchronous querying the DNS at a server
configured on 127.0.0.1 and port 53 using UDP:

	c := new(dns.Client)
	r, rtt, err := c.Exchange(context.TODO(), m, "udp", "127.0.0.1:53")

When this functions returns you will get another message back. A message consists out of four (on the wire),
but five in this package, sections.

  - The question section: r.Question, see [Msg.Question].
  - The answer section: r.Answer, see [Msg.Answer].
  - The authority section: r.Ns, see [Msg.Ns].
  - The additional section: r.Extra, see [Msg.Extra].
  - And the extra and new, the pseudo section: r.Pseudo, see [Msg.Pseudo].

The latter was added to make it easier to deal with [EDNS0] option codes, which become more and more prevalent.

Each of these sections contain a []RR. Basic use pattern for accessing the rdata of a [TXT] [RR] as the first
[RR] in the Answer section:

	if t, ok := r.Answer[0].(*dns.TXT); ok {
		// do something with t.TXT.Txt
	}

Or if you sent an NSID EDNS0 option:

	if n, ok := r.Pseudo[0].(*dns.NSID); ok {
		// do something with n.Nsid
	}

Domain names are converted to presentation form as-is, there is no conversion of unprintable characters, i.e.
\DDD and \. are left as-is. The only exception is the SOA's Mbox where \. is detected and encoded.

TXT character strings are converted to presentation form both when unpacked and when converted to strings.
Tabs, carriage returns and line feeds will be converted to \t, \r and \n respectively. Back slashes and
quotations marks will be escaped. Bytes below 32 and above 127 will be converted to \DDD form.
*/
package dns
