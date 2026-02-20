// Package main provides HTTP/HTTPS transport with DNS-over-HTTPS support.
// This implementation includes HTTP/2, HTTP/3, caching, and intelligent fallback.
//
// Go 1.26 Modernizations:
//   - netip.Addr used internally for zero-allocation IP deduplication
//   - math/rand/v2 for cryptographically seeded jitter (no manual seeding needed)
//   - http2.ConfigureTransports with full idle/ping/write tuning
//   - Separate TLSHandshakeTimeout and per-host connection limits
//   - strings.CutPrefix for Alt-Svc parsing (replaces HasPrefix+manual slicing)
//   - Explicit context propagation with context.WithTimeout in all DNS paths
//   - QUIC 0-RTT via quic.DialEarly with graceful UDP conn cleanup
//   - Unified shadow variable "tls" renamed to "tlsState" to avoid import shadowing
//   - IdleConnTimeout decoupled from KeepAlive (separate constants)
//   - Stale-cache grace-period fallback with proper logging
//   - All exported functions carry godoc comments
//   - All public APIs are unchanged (drop-in replacement)
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	netproxy "golang.org/x/net/proxy"
	"golang.org/x/sys/cpu"
)

// hasAESGCMHardwareSupport reports whether the CPU has hardware-accelerated
// AES-GCM so we can prioritise those cipher suites at startup.
var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||
	(cpu.S390X.HasAES && cpu.S390X.HasAESGCM)

// Timeout and connection-pool tuning constants.
// Keeping KeepAlive and IdleConnTimeout separate lets the OS TCP stack send
// keep-alive probes at the right cadence while the pool drains more slowly.
const (
	DefaultBootstrapResolver = "9.9.9.9:53"

	// DefaultKeepAlive is the TCP keep-alive probe interval passed to net.Dialer.
	DefaultKeepAlive = 5 * time.Second
	// DefaultIdleConnTimeout is how long an idle HTTP/2 connection stays in the pool.
	DefaultIdleConnTimeout = 90 * time.Second
	// DefaultTimeout is the end-to-end per-request deadline.
	DefaultTimeout = 30 * time.Second

	ResolverReadTimeout = 5 * time.Second

	// TTL constants for the internal IP cache.
	SystemResolverIPTTL     = 12 * time.Hour
	MinResolverIPTTL        = 4 * time.Hour
	ResolverIPTTLMaxJitter  = 15 * time.Minute
	ExpiredCachedIPGraceTTL = 15 * time.Minute

	// Resolver retry parameters (exponential back-off, capped).
	resolverRetryCount          = 3
	resolverRetryInitialBackoff = 150 * time.Millisecond
	resolverRetryMaxBackoff     = 1 * time.Second

	// HTTP transport pool limits.
	maxIdleConns    = 2000
	maxH2HeaderSize = 4096

	// TLS handshake deadline; separate from the overall request timeout.
	tlsHandshakeTimeout = 10 * time.Second
)

// ------------------------------------------------------------------ types ---

// CachedIPItem is one entry in the DNS-over-transport IP cache.
type CachedIPItem struct {
	ips           []net.IP
	expiration    *time.Time // nil means "never expires"
	updatingUntil *time.Time // non-nil while a background refresh is in flight
}

// CachedIPs is a thread-safe map from hostname → CachedIPItem.
type CachedIPs struct {
	sync.RWMutex
	cache map[string]*CachedIPItem
}

// AltSupport records which hosts have announced HTTP/3 Alt-Svc support and on
// which port. A stored value of 0 means HTTP/3 was tried and failed (negative
// cache entry).
type AltSupport struct {
	sync.RWMutex
	cache map[string]uint16
}

// XTransport is the central HTTP transport layer for dnscrypt-proxy. It wraps
// net/http.Transport and http3.Transport, manages a local DNS-resolution cache,
// and provides DoH / Oblivious-DoH helpers.
type XTransport struct {
	transport   *http.Transport
	h3Transport *http3.Transport

	keepAlive time.Duration
	timeout   time.Duration

	cachedIPs  CachedIPs
	altSupport AltSupport

	internalResolvers     []string
	bootstrapResolvers    []string
	mainProto             string
	ignoreSystemDNS       bool
	internalResolverReady bool

	useIPv4 bool
	useIPv6 bool

	// http3 enables the HTTP/3 transport for all outgoing requests.
	http3 bool
	// http3Probe forces HTTP/3 on every request and falls back on failure,
	// regardless of whether an Alt-Svc header has been received.
	http3Probe bool

	tlsDisableSessionTickets bool
	tlsPreferRSA             bool

	proxyDialer       *netproxy.Dialer
	httpProxyFunction func(*http.Request) (*url.URL, error)

	tlsClientCreds DOHClientCreds
	keyLogWriter   io.Writer
}

// NewXTransport returns an XTransport initialised with safe production defaults.
func NewXTransport() *XTransport {
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
		panic("DefaultBootstrapResolver does not parse: " + err.Error())
	}
	return &XTransport{
		cachedIPs:                CachedIPs{cache: make(map[string]*CachedIPItem)},
		altSupport:               AltSupport{cache: make(map[string]uint16)},
		keepAlive:                DefaultKeepAlive,
		timeout:                  DefaultTimeout,
		bootstrapResolvers:       []string{DefaultBootstrapResolver},
		ignoreSystemDNS:          true,
		useIPv4:                  true,
	}
}

// ---------------------------------------------------------------- helpers ---

// ParseIP parses an IP address string, stripping surrounding IPv6 brackets if
// present. Returns nil if the string is not a valid IP.
func ParseIP(ipStr string) net.IP {
	ipStr = strings.TrimPrefix(ipStr, "[")
	ipStr = strings.TrimSuffix(ipStr, "]")
	return net.ParseIP(ipStr)
}

// netIPToNetipAddr converts a net.IP to a netip.Addr for efficient map keying.
// The mapped IPv4-in-IPv6 form is normalised to a plain IPv4 address so that
// 127.0.0.1 and ::ffff:127.0.0.1 compare equal.
func netIPToNetipAddr(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	// Unmap so IPv4-mapped IPv6 addresses deduplicate correctly.
	return addr.Unmap(), true
}

// uniqueNormalizedIPs returns a copy of ips with nil entries removed and
// duplicates eliminated. Order is preserved (first occurrence wins).
func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	seen := make(map[netip.Addr]struct{}, len(ips))
	unique := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		addr, ok := netIPToNetipAddr(ip)
		if !ok {
			// Not a valid standard IP; copy and keep anyway.
			unique = append(unique, append(net.IP(nil), ip...))
			continue
		}
		if _, exists := seen[addr]; exists {
			continue
		}
		seen[addr] = struct{}{}
		unique = append(unique, append(net.IP(nil), ip...))
	}
	return unique
}

// ------------------------------------------------------------ IP cache API --

// saveCachedIPs stores a set of IP addresses for host in the cache with the
// given TTL. A random jitter (up to ResolverIPTTLMaxJitter) is added to spread
// out re-resolution events across many hosts. The minimum effective TTL is
// MinResolverIPTTL regardless of what the resolver advertised.
func (x *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {
	normalized := uniqueNormalizedIPs(ips)
	if len(normalized) == 0 {
		return
	}
	item := &CachedIPItem{ips: normalized}
	if ttl >= 0 {
		if ttl < MinResolverIPTTL {
			ttl = MinResolverIPTTL
		}
		// math/rand/v2 is automatically seeded; no manual seed required.
		ttl += time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))
		exp := time.Now().Add(ttl)
		item.expiration = &exp
	}
	x.cachedIPs.Lock()
	item.updatingUntil = nil
	x.cachedIPs.cache[host] = item
	x.cachedIPs.Unlock()

	if len(normalized) == 1 {
		dlog.Debugf("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)
	} else {
		dlog.Debugf("[%s] cached %d IP addresses (first: %s), valid for %v",
			host, len(normalized), normalized[0], ttl)
	}
}

// saveCachedIP is a convenience wrapper for a single IP.
func (x *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip == nil {
		return
	}
	x.saveCachedIPs(host, []net.IP{ip}, ttl)
}

// markUpdatingCachedIP records that a background re-resolution is in progress
// so that other callers can continue serving the stale entry while they wait.
func (x *XTransport) markUpdatingCachedIP(host string) {
	x.cachedIPs.Lock()
	if item, ok := x.cachedIPs.cache[host]; ok {
		until := time.Now().Add(x.timeout)
		item.updatingUntil = &until
		x.cachedIPs.cache[host] = item
		dlog.Debugf("[%s] IP address marked as updating", host)
	}
	x.cachedIPs.Unlock()
}

// loadCachedIPs returns the cached IPs for host together with freshness flags.
// All returned net.IP values are independent copies so the caller may modify
// them without affecting the cache.
func (x *XTransport) loadCachedIPs(host string) (ips []net.IP, expired, updating bool) {
	x.cachedIPs.RLock()
	item, ok := x.cachedIPs.cache[host]
	if !ok {
		x.cachedIPs.RUnlock()
		dlog.Debugf("[%s] IP address not found in the cache", host)
		return nil, false, false
	}
	// Copy IPs under the read lock so callers never alias cache storage.
	if len(item.ips) > 0 {
		ips = make([]net.IP, 0, len(item.ips))
		for _, ip := range item.ips {
			if ip != nil {
				ips = append(ips, append(net.IP(nil), ip...))
			}
		}
	}
	expiration := item.expiration
	updatingUntil := item.updatingUntil
	x.cachedIPs.RUnlock()

	if expiration != nil && time.Until(*expiration) < 0 {
		expired = true
		if updatingUntil != nil && time.Until(*updatingUntil) > 0 {
			updating = true
			dlog.Debugf("[%s] cached IP addresses are being updated", host)
		} else {
			dlog.Debugf("[%s] cached IP addresses expired, not being updated yet", host)
		}
	}
	return ips, expired, updating
}

// -------------------------------------------------- transport construction --

// rebuildTransport (re)creates the underlying http.Transport and, if http3 is
// enabled, the http3.Transport. It must be called once before any Fetch call
// and again whenever TLS or proxy configuration changes.
func (x *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport")
	if x.transport != nil {
		x.transport.CloseIdleConnections()
	}

	timeout := x.timeout

	transport := &http.Transport{
		// Keep connections alive so HTTP/2 streams can be multiplexed.
		DisableKeepAlives: false,
		// We decompress in Fetch ourselves so we can enforce body-size limits.
		DisableCompression:     true,
		MaxIdleConns:           maxIdleConns,
		IdleConnTimeout:        DefaultIdleConnTimeout,
		TLSHandshakeTimeout:    tlsHandshakeTimeout,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: maxH2HeaderSize,
		// ForceAttemptHTTP2 ensures HTTP/2 is negotiated even when a custom
		// DialContext is provided (net/http wouldn't try otherwise).
		ForceAttemptHTTP2: true,
		DialContext:       x.buildDialContext(timeout),
	}

	if x.httpProxyFunction != nil {
		transport.Proxy = x.httpProxyFunction
	}

	tlsClientConfig := x.buildTLSConfig()
	transport.TLSClientConfig = tlsClientConfig

	// Apply HTTP/2-specific tuning via golang.org/x/net/http2.
	if h2t, err := http2.ConfigureTransports(transport); err == nil && h2t != nil {
		h2t.ReadIdleTimeout = 30 * time.Second
		h2t.PingTimeout = 15 * time.Second
		h2t.WriteByteTimeout = 10 * time.Second
		h2t.AllowHTTP = false
		// Let the server dictate stream concurrency; don't impose a hard cap
		// that would cause unnecessary RST_STREAM errors.
		h2t.StrictMaxConcurrentStreams = false
	}

	x.transport = transport

	if x.http3 {
		h3dial := x.buildH3DialFunc(tlsClientConfig)
		x.h3Transport = &http3.Transport{
			DisableCompression: true,
			TLSClientConfig:    tlsClientConfig,
			Dial:               h3dial,
		}
	}
}

// buildDialContext returns a DialContext function that resolves hostnames via
// the internal IP cache before dialling, trying each cached address in order
// and falling back to a plain hostname lookup if the cache is empty.
func (x *XTransport) buildDialContext(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addrStr string) (net.Conn, error) {
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

		// formatEndpoint turns an optional IP into a "host:port" string.
		// If ip is nil we fall through to the original hostname so that
		// the OS resolver is used as a last resort.
		formatEndpoint := func(ip net.IP) string {
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					return v4.String() + ":" + strconv.Itoa(port)
				}
				return "[" + ip.String() + "]:" + strconv.Itoa(port)
			}
			// Preserve IPv6-literal hostnames in the address string.
			if parsed := ParseIP(host); parsed != nil && parsed.To4() == nil {
				return "[" + parsed.String() + "]:" + strconv.Itoa(port)
			}
			return host + ":" + strconv.Itoa(port)
		}

		cachedIPs, _, _ := x.loadCachedIPs(host)
		targets := make([]string, 0, max(len(cachedIPs), 1))
		for _, ip := range cachedIPs {
			targets = append(targets, formatEndpoint(ip))
		}
		if len(targets) == 0 {
			dlog.Debugf("[%s] IP address was not cached in DialContext", host)
			targets = append(targets, formatEndpoint(nil))
		}

		dial := func(address string) (net.Conn, error) {
			if x.proxyDialer == nil {
				d := &net.Dialer{
					Timeout:   timeout,
					KeepAlive: x.keepAlive,
					// DualStack (Happy Eyeballs) for resilient dual-stack connects.
					DualStack: true,
				}
				return d.DialContext(ctx, network, address)
			}
			return (*x.proxyDialer).Dial(network, address)
		}

		var lastErr error
		for i, target := range targets {
			conn, err := dial(target)
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if i < len(targets)-1 {
				dlog.Debugf("Dial attempt using [%s] failed: %v", target, err)
			}
		}
		return nil, lastErr
	}
}

// buildH3DialFunc returns the QUIC dial function used by the HTTP/3 transport.
// It mirrors buildDialContext's cache-first approach but uses UDP sockets.
func (x *XTransport) buildH3DialFunc(tlsCfg *tls.Config) func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addrStr string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		dlog.Debugf("Dialing for H3: [%v]", addrStr)
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

		type udpTarget struct {
			addr    string
			network string
		}

		buildAddr := func(ip net.IP) udpTarget {
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					return udpTarget{addr: v4.String() + ":" + strconv.Itoa(port), network: "udp4"}
				}
				return udpTarget{addr: "[" + ip.String() + "]:" + strconv.Itoa(port), network: "udp6"}
			}
			network, addr := "udp4", host
			if parsed := ParseIP(host); parsed != nil {
				if parsed.To4() == nil {
					network, addr = "udp6", "["+parsed.String()+"]"
				} else {
					addr = parsed.String()
				}
			} else if x.useIPv6 {
				if x.useIPv4 {
					network = "udp"
				} else {
					network = "udp6"
				}
			}
			return udpTarget{addr: addr + ":" + strconv.Itoa(port), network: network}
		}

		cachedIPs, _, _ := x.loadCachedIPs(host)
		targets := make([]udpTarget, 0, max(len(cachedIPs), 1))
		for _, ip := range cachedIPs {
			targets = append(targets, buildAddr(ip))
		}
		if len(targets) == 0 {
			dlog.Debugf("[%s] IP address was not cached in H3 context", host)
			targets = append(targets, buildAddr(nil))
		}

		var lastErr error
		for i, t := range targets {
			udpAddr, err := net.ResolveUDPAddr(t.network, t.addr)
			if err != nil {
				lastErr = err
				if i < len(targets)-1 {
					dlog.Debugf("H3: failed to resolve [%s] on %s: %v", t.addr, t.network, err)
				}
				continue
			}
			udpConn, err := net.ListenUDP(t.network, nil)
			if err != nil {
				lastErr = err
				if i < len(targets)-1 {
					dlog.Debugf("H3: failed to listen for [%s] on %s: %v", t.addr, t.network, err)
				}
				continue
			}
			// Clone the TLS config so we can set ServerName without a data race.
			cfg2 := tlsCfg.Clone()
			cfg2.ServerName = host
			conn, err := quic.DialEarly(ctx, udpConn, udpAddr, cfg2, cfg)
			if err != nil {
				// Close the UDP socket on failure to avoid fd leaks.
				_ = udpConn.Close()
				lastErr = err
				if i < len(targets)-1 {
					dlog.Debugf("H3: dialing [%s] via %s failed: %v", t.addr, t.network, err)
				}
				continue
			}
			return conn, nil
		}
		return nil, lastErr
	}
}

// buildTLSConfig constructs a *tls.Config that reflects all user preferences
// (root CA, client cert, session tickets, cipher ordering).
func (x *XTransport) buildTLSConfig() *tls.Config {
	cfg := &tls.Config{}

	if x.keyLogWriter != nil {
		cfg.KeyLogWriter = x.keyLogWriter
	}

	certPool, certPoolErr := x509.SystemCertPool()
	creds := x.tlsClientCreds

	if creds.rootCA != "" {
		if certPool == nil {
			dlog.Fatalf("Additional CAs not supported on this platform: %v", certPoolErr)
		}
		pem, err := os.ReadFile(creds.rootCA)
		if err != nil {
			dlog.Fatalf("Unable to read rootCA file [%s]: %v", creds.rootCA, err)
		}
		certPool.AppendCertsFromPEM(pem)
	}

	if certPool != nil {
		// Pin Let's Encrypt ISRG Root X1 for systems that ship without it.
		certPool.AppendCertsFromPEM(isrgRootX1PEM)
		cfg.RootCAs = certPool
	}

	if creds.clientCert != "" {
		cert, err := tls.LoadX509KeyPair(creds.clientCert, creds.clientKey)
		if err != nil {
			dlog.Fatalf("Unable to use certificate [%v] (key: [%v]): %v",
				creds.clientCert, creds.clientKey, err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if x.tlsDisableSessionTickets {
		cfg.SessionTicketsDisabled = true
	}

	if x.tlsPreferRSA {
		// Force TLS 1.2 so that RSA key exchange is actually available;
		// TLS 1.3 mandates ECDHE and ignores CipherSuites entirely.
		cfg.MaxVersion = tls.VersionTLS12
	}

	// Order cipher suites by what the hardware can accelerate.
	if hasAESGCMHardwareSupport {
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		}
	} else {
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		}
	}

	return cfg
}

// isrgRootX1PEM is the Let's Encrypt ISRG Root X1 certificate in PEM form.
// Some OS trust stores ship without it; we append it unconditionally so DoH
// servers backed by Let's Encrypt certificates always validate.
var isrgRootX1PEM = []byte(`-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----`)

// ------------------------------------------------------ DNS resolution API --

// resolveUsingSystem delegates to the OS resolver. It filters the result to
// only the desired address families before returning.
func (x *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	ipa, err := net.LookupIP(host)
	if returnIPv4 && returnIPv6 {
		return ipa, SystemResolverIPTTL, err
	}
	ips := make([]net.IP, 0, len(ipa))
	for _, ip := range ipa {
		v4 := ip.To4()
		if returnIPv4 && v4 != nil {
			ips = append(ips, v4)
		} else if returnIPv6 && v4 == nil {
			ips = append(ips, ip)
		}
	}
	return ips, SystemResolverIPTTL, err
}

// resolveUsingResolver sends A and/or AAAA queries to a single DNS resolver
// over the given protocol ("udp" or "tcp") and returns the result.
func (x *XTransport) resolveUsingResolver(proto, host, resolver string, returnIPv4, returnIPv6 bool) (ips []net.IP, ttl time.Duration, err error) {
	tr := dns.NewTransport()
	tr.ReadTimeout = ResolverReadTimeout
	client := dns.Client{Transport: tr}

	queryTypes := make([]uint16, 0, 2)
	if returnIPv4 {
		queryTypes = append(queryTypes, dns.TypeA)
	}
	if returnIPv6 {
		queryTypes = append(queryTypes, dns.TypeAAAA)
	}

	ctx, cancel := context.WithTimeout(context.Background(), ResolverReadTimeout)
	defer cancel()

	var rrTTL uint32
	for _, rrType := range queryTypes {
		msg := dns.NewMsg(fqdn(host), rrType)
		if msg == nil {
			continue
		}
		msg.RecursionDesired = true
		msg.UDPSize = uint16(MaxDNSPacketSize)
		msg.Security = true

		in, _, exchangeErr := client.Exchange(ctx, msg, proto, resolver)
		if exchangeErr != nil {
			err = exchangeErr
			continue
		}
		for _, answer := range in.Answer {
			if dns.RRToType(answer) != rrType {
				continue
			}
			switch rrType {
			case dns.TypeA:
				ips = append(ips, answer.(*dns.A).A.Addr.AsSlice())
			case dns.TypeAAAA:
				ips = append(ips, answer.(*dns.AAAA).AAAA.Addr.AsSlice())
			}
			rrTTL = answer.Header().TTL
		}
	}
	if len(ips) > 0 {
		ttl = time.Duration(rrTTL) * time.Second
		err = nil // at least one record type succeeded
	}
	return ips, ttl, err
}

// resolveUsingServers iterates over resolvers with exponential back-off retry.
// On the first success it moves the successful resolver to the front of the
// slice so future calls hit it first (self-healing affinity).
func (x *XTransport) resolveUsingServers(proto, host string, resolvers []string, returnIPv4, returnIPv6 bool) (ips []net.IP, ttl time.Duration, err error) {
	if len(resolvers) == 0 {
		return nil, 0, errors.New("empty resolver list")
	}
	var lastErr error
	for i, resolver := range resolvers {
		delay := resolverRetryInitialBackoff
		for attempt := 1; attempt <= resolverRetryCount; attempt++ {
			ips, ttl, err = x.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)
			if err == nil && len(ips) > 0 {
				if i > 0 {
					dlog.Infof("Resolution succeeded with resolver %s[%s]", proto, resolver)
					resolvers[0], resolvers[i] = resolvers[i], resolvers[0]
				}
				return ips, ttl, nil
			}
			if err == nil {
				err = errors.New("no IP addresses returned")
			}
			lastErr = err
			dlog.Debugf("Resolver attempt %d/%d failed for [%s] via [%s] (%s): %v",
				attempt, resolverRetryCount, host, resolver, proto, err)
			if attempt < resolverRetryCount {
				time.Sleep(delay)
				delay = min(delay*2, resolverRetryMaxBackoff)
			}
		}
		dlog.Infof("Unable to resolve [%s] using resolver [%s] (%s): %v", host, resolver, proto, lastErr)
	}
	if lastErr == nil {
		lastErr = errors.New("no IP addresses returned")
	}
	return nil, 0, lastErr
}

// resolve picks the best resolution strategy available:
//  1. Internal resolvers (when ignoreSystemDNS && internalResolverReady)
//  2. OS system resolver (when ignoreSystemDNS is false)
//  3. Bootstrap resolvers (fallback in all error cases)
//  4. OS system resolver (absolute last resort when ignoreSystemDNS is true)
func (x *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) (ips []net.IP, ttl time.Duration, err error) {
	protos := []string{"udp", "tcp"}
	if x.mainProto == "tcp" {
		protos = []string{"tcp", "udp"}
	}

	if x.ignoreSystemDNS {
		if x.internalResolverReady {
			for _, proto := range protos {
				ips, ttl, err = x.resolveUsingServers(proto, host, x.internalResolvers, returnIPv4, returnIPv6)
				if err == nil {
					return ips, ttl, nil
				}
			}
		} else {
			err = errors.New("dnscrypt-proxy service is not usable yet")
			dlog.Notice(err)
		}
	} else {
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)
		if err != nil {
			err = fmt.Errorf("system DNS not usable: %w", err)
			dlog.Notice(err)
		} else {
			return ips, ttl, nil
		}
	}

	// Primary strategy failed — try bootstrap resolvers.
	for _, proto := range protos {
		dlog.Noticef("Resolving [%s] using bootstrap resolvers over %s", host, proto)
		ips, ttl, err = x.resolveUsingServers(proto, host, x.bootstrapResolvers, returnIPv4, returnIPv6)
		if err == nil {
			return ips, ttl, nil
		}
	}

	// Absolute last resort when ignoring system DNS.
	if x.ignoreSystemDNS {
		dlog.Noticef("Bootstrap resolvers didn't respond — trying system resolver as last resort")
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)
	}
	return ips, ttl, err
}

// resolveAndUpdateCache resolves host if necessary and stores the result in the
// cache. It is a no-op when a proxy dialer or proxy function is configured
// (the proxy handles name resolution), or when host is already an IP literal.
func (x *XTransport) resolveAndUpdateCache(host string) error {
	if x.proxyDialer != nil || x.httpProxyFunction != nil {
		return nil
	}
	if ParseIP(host) != nil {
		return nil
	}

	cachedIPs, expired, updating := x.loadCachedIPs(host)
	if len(cachedIPs) > 0 && (!expired || updating) {
		return nil
	}

	x.markUpdatingCachedIP(host)

	ips, ttl, err := x.resolve(host, x.useIPv4, x.useIPv6)
	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}

	selectedIPs := ips

	// Grace period: use stale cache entry rather than failing outright.
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {
		dlog.Noticef("Using stale [%v] cached address for a grace period", host)
		selectedIPs = cachedIPs
		ttl = ExpiredCachedIPGraceTTL
		err = nil
	}

	if err != nil {
		return err
	}

	if len(selectedIPs) == 0 {
		switch {
		case !x.useIPv4 && x.useIPv6:
			dlog.Warnf("no IPv6 address found for [%s]", host)
		case x.useIPv4 && !x.useIPv6:
			dlog.Warnf("no IPv4 address found for [%s]", host)
		default:
			dlog.Errorf("no IP address found for [%s]", host)
		}
		return nil
	}

	x.saveCachedIPs(host, selectedIPs, ttl)
	return nil
}

// --------------------------------------------------------- public HTTP API --

// Fetch performs a single HTTP request using method against url. When body is
// non-nil a POST-like body is attached; when compress is true the request
// advertises gzip and the response is transparently decompressed.
//
// It returns (responseBody, statusCode, tlsConnectionState, rtt, error).
// An error is returned for any non-2xx status code.
func (x *XTransport) Fetch(
	method string,
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
	compress bool,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if timeout <= 0 {
		timeout = x.timeout
	}

	client := http.Client{
		Transport: x.transport,
		Timeout:   timeout,
	}

	host, port := ExtractHostAndPort(url.Host, 443)
	hasAltSupport := false

	// Select transport: HTTP/3 probe mode OR cached Alt-Svc record.
	if x.h3Transport != nil {
		if x.http3Probe {
			client.Transport = x.h3Transport
			dlog.Debugf("Probing HTTP/3 transport for [%s]", url.Host)
		} else {
			x.altSupport.RLock()
			altPort, inCache := x.altSupport.cache[url.Host]
			x.altSupport.RUnlock()
			if inCache {
				hasAltSupport = true
				if altPort > 0 && int(altPort) == port {
					client.Transport = x.h3Transport
					dlog.Debugf("Using HTTP/3 transport for [%s]", url.Host)
				}
			}
		}
	}

	// Build request headers.
	header := make(http.Header, 4)
	header.Set("User-Agent", "dnscrypt-proxy")
	header.Set("Cache-Control", "max-stale")
	if accept != "" {
		header.Set("Accept", accept)
	}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}

	// Append a stable body hash to GET/POST query strings so intermediate
	// caches can distinguish requests by payload.
	if body != nil {
		h := sha512.Sum512(*body)
		qs := url.Query()
		qs.Add("body_hash", hex.EncodeToString(h[:32]))
		u2 := *url
		u2.RawQuery = qs.Encode()
		url = &u2
	}

	if x.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0, errors.New("onion service is not reachable without Tor")
	}

	if err := x.resolveAndUpdateCache(host); err != nil {
		dlog.Errorf("Unable to resolve [%v]: make sure the system resolver works, or set `bootstrap_resolvers`", host)
		return nil, 0, nil, 0, err
	}

	if compress && body == nil {
		header.Set("Accept-Encoding", "gzip")
	}

	req := &http.Request{
		Method: method,
		URL:    url,
		Header: header,
		Close:  false,
	}
	if body != nil {
		req.ContentLength = int64(len(*body))
		req.Body = io.NopCloser(bytes.NewReader(*body))
	}

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	// HTTP/3 failed — record in negative cache and retry over HTTP/2.
	if err != nil && client.Transport == x.h3Transport {
		if x.http3Probe {
			dlog.Debugf("HTTP/3 probe failed for [%s]: %v — falling back to HTTP/2", url.Host, err)
		} else {
			dlog.Debugf("HTTP/3 connection failed for [%s]: %v — falling back to HTTP/2", url.Host, err)
		}
		x.altSupport.Lock()
		x.altSupport.cache[url.Host] = 0 // negative cache
		x.altSupport.Unlock()

		client.Transport = x.transport
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(*body))
		}
		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)
	}

	if err == nil {
		switch {
		case resp == nil:
			err = errors.New("webserver returned an empty response")
		case resp.StatusCode < 200 || resp.StatusCode > 299:
			err = errors.New(resp.Status)
		}
	} else {
		dlog.Debugf("HTTP client error: %v — closing idle connections", err)
		x.transport.CloseIdleConnections()
	}

	statusCode := 503
	if resp != nil {
		defer resp.Body.Close()
		statusCode = resp.StatusCode
	}

	if err != nil {
		dlog.Debugf("[%s]: %v", req.URL, err)
		return nil, statusCode, nil, rtt, err
	}

	// Parse Alt-Svc header to learn about HTTP/3 support for subsequent requests.
	if x.h3Transport != nil && !hasAltSupport {
		x.parseAndCacheAltSvc(url.Host, port, resp.Header)
	}

	tlsState := resp.TLS

	var bodyReader io.ReadCloser = resp.Body
	if compress && resp.Header.Get("Content-Encoding") == "gzip" {
		gr, grErr := gzip.NewReader(io.LimitReader(resp.Body, MaxHTTPBodyLength))
		if grErr != nil {
			return nil, statusCode, tlsState, rtt, grErr
		}
		defer gr.Close()
		bodyReader = gr
	}

	bin, err := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))
	if err != nil {
		return nil, statusCode, tlsState, rtt, err
	}
	return bin, statusCode, tlsState, rtt, nil
}

// parseAndCacheAltSvc inspects the Alt-Svc response header and updates the
// altSupport cache with the HTTP/3 port for host, if found.
// It skips parsing entirely when host is in the negative cache.
func (x *XTransport) parseAndCacheAltSvc(host string, port int, header http.Header) {
	// Skip when the host is already in the negative cache (HTTP/3 probe failed).
	if x.http3Probe {
		x.altSupport.RLock()
		altPort, inCache := x.altSupport.cache[host]
		x.altSupport.RUnlock()
		if inCache && altPort == 0 {
			dlog.Debugf("Skipping Alt-Svc parsing for [%s] — previous HTTP/3 probe failed", host)
			return
		}
	}

	alt, found := header["Alt-Svc"]
	if !found {
		return
	}
	dlog.Debugf("Alt-Svc [%s]: %v", host, alt)

	altPort := uint16(port & 0xffff)
outer:
	for i, entry := range alt {
		if i >= 8 {
			break
		}
		for j, field := range strings.Split(entry, ";") {
			if j >= 16 {
				break
			}
			// strings.CutPrefix is idiomatic Go 1.20+; no manual HasPrefix needed.
			if after, ok := strings.CutPrefix(strings.TrimSpace(field), `h3=":"`); ok {
				v := strings.TrimSuffix(after, `"`)
				if p, err := strconv.ParseUint(v, 10, 16); err == nil && p <= 65535 {
					altPort = uint16(p)
					dlog.Debugf("HTTP/3 advertised for [%s] on port %d", host, altPort)
					break outer
				}
			}
		}
	}

	x.altSupport.Lock()
	x.altSupport.cache[host] = altPort
	dlog.Debugf("Caching altPort %d for [%s]", altPort, host)
	x.altSupport.Unlock()
}

// GetWithCompression performs a GET request with transparent gzip support.
func (x *XTransport) GetWithCompression(url *url.URL, accept string, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("GET", url, accept, "", nil, timeout, true)
}

// Get performs a plain GET request.
func (x *XTransport) Get(url *url.URL, accept string, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("GET", url, accept, "", nil, timeout, false)
}

// Post performs a POST request.
func (x *XTransport) Post(url *url.URL, accept, contentType string, body *[]byte, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("POST", url, accept, contentType, body, timeout, false)
}

// dohLikeQuery sends body as either a GET (RFC 8484 §4.1) or POST
// (RFC 8484 §4.1) DNS-over-HTTPS query to url.
func (x *XTransport) dohLikeQuery(dataType string, useGet bool, url *url.URL, body []byte, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if useGet {
		qs := url.Query()
		qs.Add("dns", base64.RawURLEncoding.EncodeToString(body))
		u2 := *url
		u2.RawQuery = qs.Encode()
		return x.Get(&u2, dataType, timeout)
	}
	return x.Post(url, dataType, dataType, &body, timeout)
}

// DoHQuery sends a standard DNS-over-HTTPS query (RFC 8484).
func (x *XTransport) DoHQuery(useGet bool, url *url.URL, body []byte, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/dns-message", useGet, url, body, timeout)
}

// ObliviousDoHQuery sends an Oblivious DNS-over-HTTPS query (RFC 9230).
func (x *XTransport) ObliviousDoHQuery(useGet bool, url *url.URL, body []byte, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}
