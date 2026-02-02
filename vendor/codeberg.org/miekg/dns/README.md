[![Go Report Card](https://goreportcard.com/badge/codeberg.org/miekg/dns)](https://goreportcard.com/report/codeberg.org/miekg/dns)
[![Go Doc](https://godoc.org/coreberg.org/miekg/dns?status.svg)](https://godoc.org/codeberg.org/miekg/dns)
[![status-badge](https://ci.codeberg.org/api/badges/15045/status.svg)](https://ci.codeberg.org/repos/15045)

# Even more alternative approach to a DNS library (version 2)

# Status

> Less is more.

Complete and usable DNS library. All Resource Records are supported, including the DNSSEC types. It follows a
lean and mean philosophy. Server side and client side programming is supported, i.e. you can build servers and
resolvers with it.

Many convenience functions are included in _dns_, _dnstest_ or otherwise in _dnsutils_. The RR's resource data
(RDATA) is split off into its own package: _rdata_. This means accessing the RR's header and rdata is much
simpler now.

We try to keep the "main" branch as sane as possible and at the bleeding edge of standards, avoiding breaking
changes wherever reasonable. But because this version is young, we allow ourselves some more headroom for
making backwards incompatible changes.

Example programs are included _and_ benchmarked in `cmd`.
[`cmd/atomdns`](https://codeberg.org/miekg/dns/src/branch/main/cmd/atomdns/README.md) is a full blown
production ready name server. Because of these we are depending on a lot more external packages - at some
point these servers will be split off.

The naming of types follows the RFCs. EDNS0 types are similarly named, for instance, DHU (DS Hash Understood).
If there is a clash between an actual RR's and an EDNS0 one, the EDNS0 type will get an 'E' as prefix, e.g.
EDHU. This will also be done if the RR was named later than the EDNS0 option! The same is the for DSO (DNS
Stateful Operations), when clashing those types will be prefixed with a 'D'. If EDNS0 and DSO clash, EDNS0
wins. See PADDING and DPADDING as an example.

This new version will not soon see a v1.0.0 release because I want to be able to still make changes. In a
year or two (2028?) when things have stablized it will be blessed with a v1.0.0.

# Porting From v1

Everything from <https://github.com/miekg/dns> works. See
[README-v1-to-v2.md](https://codeberg.org/miekg/dns/src/branch/main/_doc/README-v1-to-v2.md)
for the differences, if you are porting your application.

For developers please read the
[developer README](https://codeberg.org/miekg/dns/src/branch/main/_doc/README-dev.md).

# Goals

- KISS.
- Everything is a resource record, EDNS0 pseudo RRs included.
  - Easy way to access RR's header and resource data (rdata).
- Small API.
  - Package _dnsutil_ contains functions that help programmers, but are not nessecarily in scope the the
    _dns_ package.
  - Package _dnstest_ contains functions and types that help you test, similar to the _httptest_ package.
  - Package _svcb_ holds all details of the SVCB/HTTPS record.
  - Pacakge _deleg_ holds details for the DELEG record.
  - Many helper/debug functions are moved into _internal_ packages, making the top-level much, much cleaner.
- Fast.
  - recvmmsg(2) and TCP pipeling suppport.
  - The `cmd/reflect` server does ~400K/330K qps UDP/TCP respectively on the right hardware.
    - Since a46996c I can get ~400K (UDP) qps on my laptop (M2/Asahi Linux), also see 1766e44, 86b53fe and 06e5e0f.
    - On my Dell XPS 17 (Intel) it is similar-ish (~300K/240K qps UDP/TCP).
    - On other Intel/AMD hardware it is lower (~200K (UDP) qps) - yet to understand why.
  - See `cmd/reflect` and do a `go build; make new.txt` to redo the performance test. Requires `dnsperf` to be installed.

# Users

A not-so-up-to-date-list-that-may-be-actually-current:

- atomdns - included in cmd/atomdns - a high performance DNS server, based on the principles of CoreDNS, but
  faster and simpler.
- [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) - a flexible DNS proxy, with support for
  encrypted DNS protocols such as DNSCrypt v2, DOH, Anonymized DNSCrypt and
  [ODOH](https://developers.cloudflare.com/1.1.1.1/encryption/oblivious-dns-over-https/).
- [DNSControl](https://dnscontrol.org/) - DNSControl is an opinionated platform for seamlessly managing your DNS configuration across any number of DNS hosts,
  both in the cloud or in your own infrastructure.

Send pull request if you want to be listed here.

## Comments

What users say:

> miekg/dns is probably my favorite Go module in the open source ecosystem. It is very complete (every DNS rtype is defined)
> and strict (field names match the RFCs, etc). DNSControl has used miekg/dns since the first release.

- <https://codeberg.org/miekg/dns/issues/258#issue-2471506>

> Your library is a blast and I cannot thank you enough 🙏.

- <https://infosec.exchange/@x_cli/115745919220339651>

# Features

- UDP/TCP queries, recvmmsg(2), TCP query-pipelining, IPv4 and IPv6.
- Fast.
- RFC 1035 zone file parsing ($INCLUDE, $ORIGIN, $TTL and $GENERATE - for _all_ record types) is supported.
- Server side programming (mimicking the net/http package), with `dns.Handle` and `dns.HandleFunc` allowing
  for middleware servers.
- Client side programming.
- DNSSEC: signing, validating and key generation for DSA, RSA, ECDSA and Ed25519.
- EDNS0, NSID, Cookies, etc, as pseudo RRs in the (fake) pseudo section.
- AXFR/IXFR.
- TSIG, SIG(0).
- DNS over TLS (DOT): encrypted connection between client and server over TCP.
- DNS over HTTP (DOH), see the _dnshttp_ package.
- Improved naming by embracing sub-packages.
- Improved RRs, by having the rdata specified in an _rdata_ package.
- Examples included the cmd/ directory.
- Escapes (\DDD and \x) in domain names is not supported (anymore) - the overhead (50-100%) was too high.
- Easy way for custom RRs and EDNS0 pseudo RRs.

Have fun!

Miek Gieben - 2026- - <miek@miek.nl>

See [anonymous users asking for support](https://berthub.eu/articles/posts/anonymous-help/) on why these kind
of requests/issues usually get closed pretty swiftly.

# Building/developing

This library uses Go modules and uses semantic versioning. Getting the code and working with the library is
done via:

    git clone git@codeberg.org:miekg/dns  # use https if you don't have a codeberg account
    cd dns
    # $EDTIOR *.go

If you want to use codeberg/miekg/dns in your own project, just do a `go get codeberg.org/miekg/dns@latest`
and import codeberg.org/miekg/dns in your Go files.

## Examples

A short "how to use the API" is at the beginning of doc.go. The cmd/ directory contains a reflect example
program that is used for benchmarking, and further has atomdns which is full fledged DNS server that is
developed in tandem with the library.

## Supported RFCs

_all of them_ and _then some_

- 103{4,5} - DNS standard
- 1348 - NSAP record (removed the record)
- 1982 - Serial Arithmetic
- 1876 - LOC record
- 1995 - IXFR
- 1996 - DNS notify
- 2136 - DNS Update (dynamic updates)
- 2181 - RRset definition
- 2537 - RSAMD5 DNS keys
- 2065 - DNSSEC (updated in later RFCs)
- 2671 - EDNS record
- 2782 - SRV record
- 2845 - TSIG record
- 2915 - NAPTR record
- 2929 - DNS IANA Considerations
- 3110 - RSASHA1 DNS keys
- 3123 - APL record
- 3225 - DO bit (DNSSEC OK)
- 340{1,2,3} - NAPTR record
- 3445 - Limiting the scope of (DNS)KEY
- 3596 - AAAA record
- 3597 - Unknown RRs
- 4025 - A Method for Storing IPsec Keying Material in DNS
- 403{3,4,5} - DNSSEC
- 4255 - SSHFP record
- 4343 - Case insensitivity
- 4408 - SPF record
- 4509 - SHA256 Hash in DS
- 4592 - Wildcards in the DNS
- 4635 - HMAC SHA TSIG
- 4701 - DHCID
- 4892 - id.server
- 5001 - NSID
- 5155 - NSEC3 record
- 5205 - HIP record
- 5702 - SHA2 in the DNS
- 5936 - AXFR
- 5966 - TCP implementation recommendations
- 6605 - ECDSA
- 6672 - DNAME
- 6725 - IANA Registry Update
- 6742 - ILNP DNS
- 6840 - Clarifications and Implementation Notes for DNS Security
- 6844 - CAA record
- 6891 - EDNS0 update
- 6895 - DNS IANA considerations
- 6944 - DNSSEC DNSKEY Algorithm Status
- 6975 - Algorithm Understanding in DNSSEC
- 7043 - EUI48/EUI64 records
- 7314 - DNS (EDNS) EXPIRE Option
- 7477 - CSYNC RR
- 7828 - TCP-keepalive EDNS0 Option
- 7553 - URI record
- 7719 - DNS Terminology
- 7858 - DNS over TLS: Initiation and Performance Considerations
- 7871 - EDNS0 Client Subnet
- 7873 - Domain Name System (DNS) Cookies
- 8080 - EdDSA for DNSSEC
- 8482 - Minimal Answers for ANY
- 8484 - DOH
- 8499 - DNS Terminology
- 8659 - DNS Certification Authority Authorization (CAA) Resource Record
- 8777 - DNS Reverse IP Automatic Multicast Tunneling (AMT) Discovery
- 8914 - Extended DNS Errors
- 8976 - Message Digest for DNS Zones (ZONEMD RR)
- 9250 - DOQ (not implemented, waiting until Go supports QUIC)
- 9461 - Service Binding Mapping for DNS Servers
- 9462 - Discovery of Designated Resolvers
- 9460 - SVCB and HTTPS Records
- 9499 - DNS Terminology
- 9567 - DNS Error Reporting
- 9606 - DNS Resolver Information
- 9660 - Zone version
- 9859 - DSYNC RR
- draft-ietf-compact-denial - CO bit
- draft-ietf-deleg - DELEG RR
