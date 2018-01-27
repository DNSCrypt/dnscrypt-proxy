[![Build Status](https://travis-ci.org/jedisct1/dnscrypt-proxy.svg?branch=master)](https://travis-ci.org/jedisct1/dnscrypt-proxy?branch=master)

# ![dnscrypt-proxy 2](https://raw.github.com/jedisct1/dnscrypt-proxy/master/logo.png?2)

A flexible DNS proxy, with support for encrypted DNS protocols such as [DNSCrypt](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/DNSCRYPT-V2-PROTOCOL.txt).

## [dnscrypt-proxy 2.0.0beta10 is available for download!](https://github.com/jedisct1/dnscrypt-proxy/releases/latest)

## Installation

### How do I install DNSCrypt?

You can't. Because [DNSCrypt](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/DNSCRYPT-V2-PROTOCOL.txt) is just a specification.

That specification has been implemented in software such as [unbound](https://www.unbound.net/), [dnsdist](https://dnsdist.org/), [dnscrypt-wrapper](https://github.com/cofyc/dnscrypt-wrapper) and [dnscrypt-proxy](https://github.com/jedisct1/dnscrypt-proxy).

dnscrypt-proxy is a flexible DNS proxy. It runs on your computer or router, and can locally block unwanted content, reveal where your devices are silently sending data to, make applications feel faster by caching DNS responses, and improve security and confidentiality by communicating to upstream DNS servers over secure channels.

### Setting up dnscrypt-proxy

1. Modify the [`dnscrypt-proxy.toml`](https://raw.githubusercontent.com/jedisct1/dnscrypt-proxy/master/dnscrypt-proxy/dnscrypt-proxy.toml) configuration file according to your needs.
2. Make sure that nothing else is already listening to port 53 on your system and run (in a console with elevated privileges on Windows) the `dnscrypt-proxy` application. Change your DNS settings to the configured IP address and check that everything works as expected. A DNS query for `resolver.00f.net` should return one of the chosen DNS servers instead of your ISP's resolver.
3. Register as a system service (see below).

### Installing as a system service (Windows, Linux, MacOS)

With administrator privileges, type `dnscrypt-proxy -service install` to register dnscrypt-proxy as a system service, and `dnscrypt-proxy -service start` to start it.

On Windows, this is not even required: you can just double-click on `server-install.bat` to install the service.

Done. It will automatically start at boot.

This setup procedure is compatible with Windows, Linux (systemd, Upstart, SysV), and macOS (launchd).

Other commands include `stop`, `restart` (useful after a configuration change) and `uninstall`.

### Running it as a non-root user on Linux

The following command adds the required attributes to the dnscrypt-proxy file so that it can run as a non-root user:

```sh
sudo setcap cap_net_bind_service=+pe dnscrypt-proxy
```

## Current status/features

The current 2.0.0 beta version includes all the major features from dnscrypt-proxy 1.9.5 (support for dnscrypt v2, synthetic IPv6 responses, logging, blocking, forwarding and caching), with improved reliability, flexbility, usability and performance.

| Features                                                    | dnscrypt-proxy 1.x                                                           | dnscrypt-proxy 2.x                                                                                            |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Status                                                      | Old PoC, barely maintained any more                                          | Very new, but quickly evolving                                                                                |
| Code quality                                                | Big ugly mess                                                                | Readable, easy to work on                                                                                     |
| Reliability                                                 | Poor, due to completely broken handling of edge cases                        | Excellent                                                                                                     |
| Security                                                    | Written in C, bundles patched versions from old branches of system libraries | Written in standard and portable Go                                                                           |
| Dependencies                                                | Specific versions of dnscrypt-proxy, libldns and libtool                     | None                                                                                                          |
| Upstream connections using TCP                              | Catastrophic, requires client retries                                        | Implemented as anyone would expect, works well with TOR                                                       |
| XChaCha20 support                                           | Only if compiled with recent versions of libsodium                           | Yes, always available                                                                                         |
| Support of links with small MTU                             | Unreliable due to completely broken padding                                  | Reliable, properly implemented                                                                                |
| Support for multiple servers                                | Nonexistent                                                                  | Yes, with automatic failover and load-balancing                                                               |
| Custom additions                                            | C API, requires libldns for sanity                                           | Simple Go structures using miekg/dns                                                                          |
| AAAA blocking for IPv4-only networks                        | Yes                                                                          | Yes                                                                                                           |
| DNS caching                                                 | Yes, with ugly hacks for DNSSEC support                                      | Yes, without ugly hacks                                                                                       |
| EDNS support                                                | Broken with custom records                                                   | Yes                                                                                                           |
| Asynchronous filters                                        | Lol, no, filters block everything                                            | Of course, thanks to Go                                                                                       |
| Session-local storage for extensions                        | Impossible                                                                   | Yes                                                                                                           |
| Multicore support                                           | Nonexistent                                                                  | Yes, thanks to Go                                                                                             |
| Efficient padding of queries                                | Couldn't be any worse                                                        | Yes                                                                                                           |
| Multiple local sockets                                      | Impossible                                                                   | Of course. IPv4, IPv6, as many as you like                                                                    |
| Automatically picks the fastest servers                     | Lol, it supports only one at a time, anyway                                  | Yes, out of the box                                                                                           |
| Official, always up-to-date pre-built libraries             | None                                                                         | Yes, for many platforms. See below.                                                                           |
| Automatically downloads and verifies servers lists          | No. Requires custom scripts, cron jobs and dependencies (minisign)           | Yes, built-in, including signature verification                                                               |
| Advanced expressions in blacklists (ads*.example[0-9]*.com) | No                                                                           | Yes                                                                                                           |
| Forwarding with load balancing                              | No                                                                           | Yes                                                                                                           |
| Built-in system installer                                   | Only on Windows                                                              | Install/uninstall/start/stop/restart as a service on Windows, Linux/(systemd,Upstart,SysV), and macOS/launchd |
| Built-in servers latency benchmark                          | No                                                                           | Yes                                                                                                           |
| Query type filter: only log a relevant set of query types   | No                                                                           | Yes                                                                                                           |
| Support for the Windows Event Log                           | No                                                                           | Yes                                                                                                           |
| Log suspicious queries (leading to NXDOMAIN)                | No                                                                           | Yes                                                                                                           |
| IP filtering                                                | Yes, but can be bypassed due to a vulnerability                              | Yes, doesn't have the vulnerability from v1                                                                   |
| Systemd support                                             | Yes, but don't complain about it                                             | Yes, but don't complain about it either                                                                       |
| Stamps, as a simple way to provide server parameters        | No                                                                           | Yes                                                                                                           |

## Experimental

* [DNS-over-HTTP2 (DoH)](https://datatracker.ietf.org/wg/doh/about/), the successor to DNS-over-TLS

## Planned features

* Offline responses
* Local DNSSEC validation
* Support for the V1 plugin API
* Real documentation

## Pre-built binaries

Up-to-date, pre-built binaries are available for:

* Dragonfly BSD
* FreeBSD/x86
* FreeBSD/x86_64
* Linux/arm
* Linux/arm64
* Linux/mips
* Linux/mips64
* Linux/mips64le
* Linux/x86
* Linux/x86_64
* MacOS X
* NetBSD/x86
* NetBSD/x86_64
* OpenBSD/x86
* OpenBSD/x86_64
* Windows
* Windows 64 bit
