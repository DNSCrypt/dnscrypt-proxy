# Even more alternative approach to a DNS library (version 2)

Version 1 of miekg/dns didn't have any development guidelines, and although this went remarkably well for
years it is nice to give some guidance to new contributors and to lay out some of the design decisions.

## Source Layout

The main codebase sits in _dns_ and package _rdata_, which defines the rdata for all RRs only. Helper
functions are put in _dnsutil_, unless this is impossible because of cyclic dependencies. A dnsutil
function/method that is _also_ useful in _dns_ should be put in `dnsutil/shared.go`; this file is "go
generated" to various other locations.

Useful helper function? -> _dnsutil_.
Useful helper function, that can help with testing (and other things) -> _dnstest_.
Helper function -> new package in _internal/..._.

## Go Generate

Al lot of things are generated from the RR struct tags, see `dns.go` for ~12 we currently have. They all reuse
the _internal/generate_ package.

### Cloner Interface

When adding an RR run a `go generate ./...`, this might fail on `zclone.go`, in that case remove the file
zclone.go and in dns.go remove `Cloner` from then `RR` interface. Run go generate, and re-add `Cloner` again
when done.

## "Big" RRs

RR that have a lot of different rdata "types", like the SVCB record a sub-package should be created where
most of the types and methods should be located. For SVCB, the _svcb_ package exist. Each sub-type should
be capitalized, as-if it is an RR. The public API for these sub-types should match the `RR` interface:

- Header() \*Header
- String() string
- Len() int

Due to cyclic dependencies this creates some friction, but in the end it will be easier for end-users. It's
important to put as much of the details in this sub-package. The top-level RR should be put in types.go.

The sub-types in that RR should all capitial letters as their name, as-if they are (also) RRs. For the
in-progress DELEG RR, a _deleg_ package exists which houses most of the complexity.

## Custom types for uint8/16

The `type Key uint16` looks nice and _is_ more type-safe, but then you need to convert to and from uint16 all
over the place - negating the type safety entirely. It might be helpful for documenting a type, but that
uint16 is probably not the most important details of your new resource record.

## Naming

### Values like Rcode, Class etc.

If you have a bunch of values that certain types can take the are named: `ValueThing` and will need a
`ValueToString`/`StringToValue` map or function. `Thing` may or may not be capitalized. E.g. we have
`RcodeScucces` and `ClassINET`.

Naming constants for RRs needs to have the RR's mnemonic prefixed and in upper case letters, i.e.
ZONEMDSchemeSimple, for a constants used in the ZONEMD RR.

Methods on RR types have `rr` as the receiver's name. For EDNS0 "RRs", the receiver is named `o`. For DSO `d`
is used. Methods on `Msg` use `m`. (There are a few historical exceptions).

### Tests

For tests name them after the sub-system and the something more specific. This makes it easy to just run the
tests for that sub-system. `TestZoneParserXXX`, `TestMsgXXX`, etc.

Most tests are table driven with (optional) subtests, the main tests are usually put in a struct called
`testcases` and while ranging over them at test is named `tc`.
