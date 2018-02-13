[![Build Status](https://travis-ci.org/jedisct1/dnscrypt-proxy.svg?branch=master)](https://travis-ci.org/jedisct1/dnscrypt-proxy?branch=master)

# ![dnscrypt-proxy 2](https://raw.github.com/jedisct1/dnscrypt-proxy/master/logo.png?2)

A flexible DNS proxy, with support for modern encrypted DNS protocols such as [DNSCrypt v2](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/DNSCRYPT-V2-PROTOCOL.txt) and [DNS-over-HTTP/2](https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-03).

# EXPERIMENTAL POST-QUANTUM BRANCH

This branch implements an experimental version of the DNSCrypt protocol that adds support for post-quantum key exchange using Supersingular isogeny Diffie–Hellman.

## [dnscrypt-proxy 2.0.0 final is available for download!](https://github.com/jedisct1/dnscrypt-proxy/releases/latest)

## [Documentation](https://dnscrypt.info/doc)

## Features

* DNS traffic encryption and authentication. Supports DNS-over-HTTPS (DoH) and DNSCrypt.
* DNSSEC compatible
* DNS query monitoring, with separate log files for regular and suspicious queries
* Pattern-based local blocking of DNS names and IP addresses
* Time-based filtering, with a flexible weekly schedule
* Transparent redirection of specific domains to specific resolvers
* DNS caching, to reduce latency and improve privacy
* Local IPv6 blocking to reduce latency on IPv4-only networks
* Load balancing: pick a set of resolvers, dnscrypt-proxy will automatically measure and keep track of their speed, and balance the traffic across the fastest available ones.
* Cloaking: like a `HOSTS` file on steroids, that can return preconfigured addresses for specific names, or resolve and return the IP address of other names. This can be used for local development as well as to enforce safe search results on Google, Yahoo and Bing.
* Automatic background updates of resolvers lists
* Can force outgoing connections to use TCP; useful with tunnels such as Tor.

It includes all the major features from dnscrypt-proxy 1.9.5, with improved reliability, flexibility, usability and performance.

## Pre-built binaries

Up-to-date, pre-built binaries are available for:

* Dragonfly BSD
* FreeBSD/x86
* FreeBSD/x86_64
* Linux/arm
* Linux/arm64
* Linux/mips
* Linux/mipsle
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
