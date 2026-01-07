# Difference with github.com/miekg/dns

- Many functions (and new ones) are moved into _dnsutil_, and _dnstest_. This copied a lot of stuff from CoreDNS.
- _dnshttp_ was added for help with DOH - DNS over HTTPs.
- `RR` lost the `Type` and `Rdlength` fields, type is derived from the Go type, `Rdlength` served no function at all.
  The `Header` is thus 4 bytes smaller than in v1. The RFC3597 (unknown RRs) has gained a `Type` field because of this.
- The rdata of each `RR` is split out in to a _rdata_ package. This makes it much more memory efficient to
  store RRSets - as the RR's header isn't duplicated. This saves a minimal of 24 bytes (empty string, ttl, and
  class) per RR stored.
- `context.Context` is used in the correct places. `ServeDNS` now has a context.Context, with `Zone(ctx)` you
  retrieve the pattern zone that lead to invocation of this Handler.
- _internal/..._ packages that hold code that used to be private, but was cluttering the top level directory; also allowed for better
  naming.
  - builtin perf testing with _internal/dnsperf_. Need `dnsperf`, on deb-based systems `apt-get install dnsperf`.
- Interfaces do not have private methods.
- No more `dns.Conn`.
- `Msg` contains a buffer named `Data` that holds the binary data for this message. This pulls TSIG/SIG(0)
  handling out of the client and server, simplifying it enormously as we can get rid of `dns.Conn`, and just
  use io.Writer and io.Reader interfaces.
- `Msg` includes `Options` that control on how you want it packed/unpacked.
- `Msg` includes all the ENDS0 OPT RR bits, as this almost was a real message header; in this package it now is.
- `Msg` has a pseudo section that holds all EDNS0 Options as (faked) resource records.
- Everything is a resource record:
  - question section: holds `[]RR`
  - pseudo section: holds `[]RR`
  - stateful section: holds `[]RR`

  Pseudo section RR (EDNS0 OPT) can also be parsed from their (also unique to this library) presentation format.

  The `Stateful` section in the message that holds DNS Stateful Operation (DSO) records, these records are
  also `RR`s.

- `New` will return an `RR`, `NewRR` is gone, `dnstest/New` will do the same, but panic on errors.
- `Client` has a `dns.Transport` just like `http.Client`, so _all_ connection management is now external.
- More:
  - `Msg` is a io.Writer.
  - `msg.Data` can be re-used between request and reply in Exchange.
  - `msg.Data` can be returned to a server buffer pool, for reuse in new messages, this is done automatically,
    see `msg.Hijack()` for hijacking the buffer.
  - private RRs are easier.
  - private EDNS0 are implementable and hopefully easier.
- SVCB record got its own package _svcb_ where all the key-values (called `svcb.Pair`) now reside.
- DELEG record also got its own package _deleg_, where its key-values (called `deleg.Info`) live.
- IsDuplicate is gone in favor of Compare and a full support for the `sort.Interface`, so you can just
  sort RRs in an RRset. This also simplified the DNSSEC signing and make wireformat even less important.
- Copied, sanitized and removed tests that accumulated over 16 years of development.
- Escapes in domain names is not supported. This added 50-100% overhead in low-level functions that are often
  used in the hot path. In rdata (TXT records) it still is.

## RRs

Create an RR.

```
OLD                                                                  | NEW
                                                                     |
r := &MX{ Header{Name:"miek.nl.", Class: dns.ClassINET, TTL: 3600},  | r := &MX{
        Preference: 10, Mx: "mx.miek.nl."}                           |   Header{Name:"miek.nl.", Class: dns.ClassINET, TTL: 3600},
                                                                     |   MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."},
                                                                     | }
```

Print RR without header.

```
OLD                                                        | NEW
                                                           |
mx, _ := dns.NewRR("miek.nl. 3600 IN MX 10 mx.miek.nl.")   | mx := dnstest.New("miek.nl. 3600 IN MX 10 mx.miek.nl.")
hdr := mx.Header().String()                                | hdr := mx.Header().String()
flds := mx.String()[len(hdr)+1:]                           | fmt.Printf("Fields: %q\n", mx.MX.String())
fmt.Printf("Fields: %q\n", flds)                           |
```

Access RR's rdata.

```
OLD                                                        | NEW
                                                           |
mx, _ := dns.NewRR("miek.nl. 3600 IN MX 10 mx.miek.nl.")   | mx := dnstest.New("miek.nl. 3600 IN MX 10 mx.miek.nl.")
num := dns.NumField(mx)                                    | rdata := mx.MX
for i := range num {                                       | rdata.Preference = 10
    fmt.Printf("%q", dns.Field(i))                         |
}                                                          |
```

## Setting EDNS0

```
OLD                                           | NEW
                                              |
m := new(dns.Msg)                             | m := dns.NewMsg("miek.nl.", dns.TypeDNSKEY)
m.SetQuestion("miek.nl.", dns.TypeDNSKEY)     | m.UDPSize, m.Security = 4096, true
m.SetEdns0(4096, true)                        |
                                              | OR
                                              |
                                              | m := new(dns.Msg)
                                              | dnsutil.SetQuestion("miek.nl.", dns.TypeDNSKEY")
                                              | m.UDPSize, m.Security = 4096, true
```

Setting the UDP buffer size.

```
OLD                                                      | NEW
                                                         |
bufsize := 0                                             | bufsize := m.UDPSize
for i := len(m.Extra) - 1; i >= 0; i-- {                 |
    if m.Extra[i].Header().Rrtype == dns.TypeOPT {       |
		bufsize = m.Extra[i].(*dns.OPT).UDPSize()        |
    }                                                    |
}                                                        |
```

Accessing ENDS0 options.

```
OLD                                                      | NEW
                                                         |
opt := 0                                                 | for i, options := range m.Pseudo {
for i := len(m.Extra) - 1; i >= 0; i-- {                 |     // ...
	if m.Extra[i].Header().Rrtype == dns.TypeOPT {       | }
	opt = m.Extra[i].(*dns.OPT)|                         |
    }                                                    |
}                                                        |
for i, options := range opt.Options {                    |
    // ...                                               |
}                                                        |
```

Checking if there _is_ an EDNS0 option added.

```
OLD                                                      | NEW
                                                         |
x := m.IsEdns0()                                         | x := len(m.Pseudo) > 0
```

Adding an EDNS0 option is just as easy, assign to the pseudo section.

```
OLD                                                               |
                                                                  |
o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}} |
o.SetDo()                                                         | m.Security = true
o.SetUDPSize(dns.DefaultMsgSize)                                  | m.UDPSize = dns.DefaultMsgSize
e := &dns.EDNS0_NSID{Code: dns.EDNS0NSID}                         | m.Pseudo = append(m.Pseudo, &dns.NSID{})
o.Option = append(o.Option, e)                                    |
m.Extra = append(m.Extra, o)                                      |
```

## Text Output

Note the `do` flag now being shown as if it was set in the message header, OPT options are displayed as RRs
and can also be created with `dns.New`.

```
OLD                                                                  | NEW
                                                                     |
;; opcode: QUERY, status: NOERROR, id: 62167                         | ;; QUERY, rcode: NOERROR, id: 3, flags: rd do
;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0 | ;; EDNS, version: 0, udp: 1024
                                                                     | ;; QUESTION: 1, PSEUDO: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0, DATA SIZE: 25
;; OPT PSEUDOSECTION:                                                |
; EDNS: version 0; flags:; udp: 512                                  | ;; PSEUDO SECTION:
; NSID: 6770646e732d616d73  (g)(p)(d)(n)(s)(-)(a)(m)(s)              | .               CLASS0  NSID    6770; "gpdns-ams"
                                                                     |
;; QUESTION SECTION:                                                 |
;miek.nl.       IN       MX                                          | ;; QUESTION SECTION:
                                                                     | miek.nl.                IN      A
```

### Copy

```
OLD                   | NEW
                      |
r := m.Copy()         | r := m.Copy() // Shallow copy!
```

## Server

Because `Msg` now carries its binary data too there is no need to do TSIG in the server it self, it can now be
done in a handler. This, again, removes a little of internal code that slowed things down.

The default implementation of `dns.ResponseWriter` is thread safe and this for TCP pipe lining, which is thusly
implemented in `dns.Server`. Writing or reading data is now done with `io.Copy` no more `ReadMsg` or `WriteMsg`.

A handler for instance:

```
OLD                                                      | NEW
                                                         |
func HelloServer(w dns.ResponseWriter, req *dns.Msg) {   | func HelloServer(ctx contect.Context, w ResponseWriter, req *Msg) {
	m := new(dns.Msg)                                    |     m := req.Copy()
	m.SetReply(req)                                      |     dnsutil.SetReply(m, req)
                                                         |
	m.Extra = make([]dns.RR, 1)                          |     m.Extra = []dns.RR{
	m.Extra[0] = &TXT{                                   |         &TXT{Hdr: dns.Header{Name: m.Question[0].Name, Class: dns.ClassINET},
        Hdr: dns.RR_Header{Name: m.Question[0].Name,     |              Txt: []string{"Hello world"}}
        Rrtype: dns.TypeTXT, Class: dns.ClassINET},      |     }
        Txt: []string{"Hello world"}                     |
    }                                                    |     m.Pack()
	w.WriteMsg(m)                                        |     io.Copy(w, m)
}                                                        | }
```
