[![Build Status](https://travis-ci.org/jedisct1/dnscrypt-proxy.svg?branch=master)](https://travis-ci.org/jedisct1/dnscrypt-proxy?branch=master)

# ![dnscrypt-proxy 2](https://raw.github.com/jedisct1/dnscrypt-proxy/master/logo.png?2)

A flexible DNS proxy, with support for modern encrypted DNS protocols such as [DNSCrypt v2](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/DNSCRYPT-V2-PROTOCOL.txt) and [DNS-over-HTTP/2](https://datatracker.ietf.org/wg/doh/about/).

## [dnscrypt-proxy 2.0.0beta12 is available for download!](https://github.com/jedisct1/dnscrypt-proxy/releases/latest)

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

It includes support for DNS-over-HTTP/2 (DoH), the successor to DNS-over-TLS.

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
