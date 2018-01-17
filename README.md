[![Build Status](https://travis-ci.org/jedisct1/dnscrypt-proxy.svg?branch=master)](https://travis-ci.org/jedisct1/dnscrypt-proxy?branch=master)

# ![dnscrypt-proxy 2](https://raw.github.com/jedisct1/dnscrypt-proxy/master/logo.png?2)

A modern client implementation of the [DNSCrypt](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/DNSCRYPT-V2-PROTOCOL.txt) protocol.

## [dnscrypt-proxy 2.0.0alpha8 is available for download!](https://github.com/jedisct1/dnscrypt-proxy/releases/latest)

## Current status/features

| Features                                                    | dnscrypt-proxy 1.x                                                           | dnscrypt-proxy 2.x                                      |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------- |
| Status                                                      | Old PoC, barely maintained any more                                          | Very new, but quickly evolving                          |
| Code quality                                                | Big ugly mess                                                                | Readable, easy to work on                               |
| Reliability                                                 | Poor, due to completely broken handling of edge cases                        | Excellent                                               |
| Security                                                    | Written in C, bundles patched versions from old branches of system libraries | Written in standard and portable Go                     |
| Dependencies                                                | Specific versions of dnscrypt-proxy, libldns and libtool                     | None                                                    |
| Upstream connections using TCP                              | Catastrophic, requires client retries                                        | Implemented as anyone would expect, works well with TOR |
| XChaCha20 support                                           | Only if compiled with recent versions of libsodium                           | Yes, always available                                   |
| Support of links with small MTU                             | Unreliable due to completely broken padding                                  | Reliable, properly implemented                          |
| Support for multiple servers                                | Nonexistent                                                                  | Yes, with automatic failover and load-balancing         |
| Custom additions                                            | C API, requires libldns for sanity                                           | Simple Go structures using miekg/dns                    |
| AAAA blocking for IPv4-only networks                        | Yes                                                                          | Yes                                                     |
| DNS caching                                                 | Yes, with ugly hacks for DNSSEC support                                      | Yes, without ugly hacks                                 |
| EDNS support                                                | Broken with custom records                                                   | Yes                                                     |
| Asynchronous filters                                        | Lol, no, filters block everything                                            | Of course, thanks to Go                                 |
| Session-local storage for extensions                        | Impossible                                                                   | Yes                                                     |
| Multicore support                                           | Nonexistent                                                                  | Yes, thanks to Go                                       |
| Efficient padding of queries                                | Couldn't be any worse                                                        | Yes                                                     |
| Multiple local sockets                                      | Impossible                                                                   | Of course. IPv4, IPv6, as many as you like              |
| Automatically picks the fastest servers                     | Lol, it supports only one at a time, anyway                                  | Yes, out of the box                                     |
| Official, always up-to-date pre-built libraries             | None                                                                         | Yes, for many platforms. See below.                     |
| Automatically downloads and verifies servers lists          | No. Requires custom scripts, cron jobs and dependencies (minisign)           | Yes, built-in, including signature verification         |
| Advanced expressions in blacklists (ads*.example[0-9]*.com) | No                                                                           | Yes                                                     |
| Forwarding with load balancing                              | No                                                                           | Yes                                                     |

## Planned features

* New super simple (to copy&paste), extensible format for servers parameters: "stamps"
* Offline responses
* Local DNSSEC validation
* Flexible logging
* Windows support that doesn't suck
* [DNS-over-HTTPS (DoH)](https://datatracker.ietf.org/wg/doh/about/)
* Some real documentation

## Pre-built binaries

Up-to-date, pre-built binaries are available for:

* Dragonfly BSD
* FreeBSD/x86
* FreeBSD/x86_64
* Linux/arm
* Linux/x86
* Linux/x86_64
* MacOS X
* NetBSD/x86
* NetBSD/x86_64
* OpenBSD/x86
* OpenBSD/x86_64
* Windows
* Windows 64 bit
