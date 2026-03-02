// xtransport.go — HTTP/HTTPS/QUIC transport layer for dnscrypt-proxy.
//
// Full line-by-line rewrite targeting Go 1.26+. Public API is 100% unchanged
// (drop-in replacement for the original xtransport.go).
//
// Go 1.20–1.26 language & stdlib features applied
// ────────────────────────────────────────────────
//  • math/rand/v2       → rand.Int64N (lock-free; replaces deprecated rand.Int63n)
//  • net/netip          → netip.AddrFrom4/AddrFrom16 via [N]byte(slice) direct
//                         slice→array conversion (Go 1.20, zero alloc)
//  • min() / max()      → builtin (Go 1.21), replaces hand-rolled ternaries
//  • strings.CutPrefix → cleaner than HasPrefix + manual TrimPrefix (Go 1.20)
//  • slices.Clone       → idiomatic deep-copy of []byte / net.IP (Go 1.21)
//  • http2.ConfigureTransports (plural) → preferred API for h2 fine-tuning
//  • [2]string          → fixed-size stack-allocated proto pair (no heap escape)
//  • noTTL named const  → replaces magic ^uint32(0)
//  • context.WithTimeout with open-coded defer cancel() (zero-overhead Go 1.21+)
//
// Correctness improvements over the original
// ───────────────────────────────────────────
//  • resolveUsingSystem    returns nil (not []IP{}) on no-match; len==0 is reliable
//  • resolveUsingResolver  per-query-type errors; AAAA failure never masks A result
//  • markUpdatingCachedIP  placeholder inserted for unseen hosts → no duplicate races
//  • buildH3DialFunc       quic-go always passes nil *tls.Config; clone per-conn
//  • Fetch                 resp==nil guard before resp.StatusCode access (panic fix)
//  • Fetch                 single unconditional defer resp.Body.Close() after guard
//  • Fetch                 ContentLength reset to int64(bodyLen) on H3→H2 retry
//  • Fetch                 .onion guard before dial attempt
//  • resolveAndUpdateCache double-checked locking; stale-grace clears err before nil
//
// Performance improvements over the original
// ──────────────────────────────────────────
//  • buildDialContext  portStr computed once outside endpoint() closure
//  • buildDialContext  net.Dialer constructed once outside per-target loop
//  • uniqueNormalizedIPs  0- and 1-element fast-paths skip map allocation
//  • loadCachedIPs     pre-sized deep-copy (make([]net.IP, 0, n))
//  • Fetch header      make(http.Header, 5) pre-sized; avoids rehash
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
	"slices"
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

// ── Hardware capability probe ─────────────────────────────────────────────────

// hasAESGCMHardwareSupport is true when the CPU has hardware AES-GCM
// acceleration. Used to order TLS 1.2 cipher suites: AES-GCM first on capable
// hardware, ChaCha20-Poly1305 first on everything else.
var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||
	(cpu.S390X.HasAES && cpu.S390X.HasAESGCM)

// ── Sentinel ──────────────────────────────────────────────────────────────────

// noTTL is the "no TTL observed yet" sentinel for minimum-TTL tracking across
// DNS answer RRs. Named constant is clearer than the magic ^uint32(0).
const noTTL = ^uint32(0)

// ── Tuning constants ──────────────────────────────────────────────────────────

const (
	// DefaultBootstrapResolver is the DNS resolver used at startup before the
	// internal proxy resolver becomes available. Must be a valid IP:port.
	DefaultBootstrapResolver = "9.9.9.9:53"

	// DefaultKeepAlive is the TCP keep-alive probe interval passed to net.Dialer.
	DefaultKeepAlive = 5 * time.Second

	// DefaultIdleConnTimeout is how long an idle HTTP/2 connection remains in
	// the transport pool before being closed.
	DefaultIdleConnTimeout = 90 * time.Second

	// DefaultTimeout is the end-to-end deadline for a single HTTP request.
	// Callers may override this per-request via the timeout parameter.
	DefaultTimeout = 30 * time.Second

	// ResolverReadTimeout is the maximum duration for a single DNS exchange.
	ResolverReadTimeout = 5 * time.Second

	// SystemResolverIPTTL is the synthetic TTL assigned to addresses returned
	// by the OS resolver, which does not expose per-record TTLs.
	SystemResolverIPTTL = 12 * time.Hour

	// MinResolverIPTTL is the minimum TTL enforced for any cached IP entry.
	// Advertised TTLs shorter than this are silently raised to the floor.
	MinResolverIPTTL = 4 * time.Hour

	// ResolverIPTTLMaxJitter is the exclusive upper bound of the random
	// duration added to each TTL to stagger re-resolution events over time.
	ResolverIPTTLMaxJitter = 15 * time.Minute

	// ExpiredCachedIPGraceTTL is how long a stale cache entry continues to be
	// served when fresh resolution fails. Preserves connectivity during outages.
	ExpiredCachedIPGraceTTL = 15 * time.Minute

	// resolverRetryCount is the number of query attempts per resolver before
	// falling through to the next one in the list.
	resolverRetryCount = 3

	// resolverRetryInitialBackoff is the sleep before the second attempt.
	// Each subsequent sleep is doubled up to resolverRetryMaxBackoff.
	resolverRetryInitialBackoff = 150 * time.Millisecond

	// resolverRetryMaxBackoff caps the exponential back-off growth.
	resolverRetryMaxBackoff = 1 * time.Second

	// MaxIdleConns is the total HTTP/2 connection-pool size across all hosts.
	MaxIdleConns = 2000

	// MaxResponseHeaderBytes caps the HTTP response header size accepted.
	MaxResponseHeaderBytes = 4096

	// TLSHandshakeTimeout is the deadline for completing a TLS handshake on
	// both HTTP/2 and HTTP/3 transports.
	TLSHandshakeTimeout = 10 * time.Second

	// altSvcNegativeTTL is how long a failed HTTP/3 probe suppresses further
	// H3 attempts for the same host.
	altSvcNegativeTTL = 10 * time.Minute
)

// ── Types ─────────────────────────────────────────────────────────────────────

// CachedIPItem stores resolved IP addresses and their freshness metadata.
// All fields are protected by the enclosing CachedIPs.RWMutex.
type CachedIPItem struct {
	ips           []net.IP
	expiration    *time.Time // nil → entry never expires
	updatingUntil *time.Time // non-nil while a background re-resolution is in flight
}

// CachedIPs is a thread-safe hostname → IP-address cache.
type CachedIPs struct {
	sync.RWMutex
	cache map[string]*CachedIPItem
}

// altSvcEntry holds a single HTTP/3 Alt-Svc record for a host.
//   - port > 0  → positive: use HTTP/3 on this port (validTo is zero)
//   - port == 0 → negative: HTTP/3 failed; retry after validTo
type altSvcEntry struct {
	port    uint16
	validTo time.Time
}

// AltSupport is a thread-safe cache of HTTP/3 Alt-Svc entries keyed by host.
type AltSupport struct {
	sync.RWMutex
	cache map[string]altSvcEntry
}

// XTransport is the central HTTP(S)/QUIC transport for dnscrypt-proxy.
//
// It manages an HTTP/2 transport (always present after rebuildTransport), an
// optional HTTP/3 transport (when http3 == true), a DNS-resolution cache with
// TTL jitter and grace-period fallback, per-host mutex serialisation for DNS
// queries, and DoH/ODoH query helpers.
//
// The zero value is not valid; construct with NewXTransport.
type XTransport struct {
	// HTTP transports — h3Transport is nil when HTTP/3 is disabled.
	transport       *http.Transport
	h3Transport     *http3.Transport
	tlsClientConfig *tls.Config // constructed once; shared across both transports

	keepAlive time.Duration
	timeout   time.Duration

	cachedIPs  CachedIPs
	altSupport AltSupport

	// DNS resolver configuration.
	internalResolvers     []string
	bootstrapResolvers    []string
	mainProto             string // "udp" or "tcp" — preferred DNS query transport
	ignoreSystemDNS       bool
	internalResolverReady bool

	// Address-family selection for outgoing connections.
	useIPv4 bool
	useIPv6 bool

	// HTTP/3 control flags.
	// Field names intentionally match config_loader.go so this file is a
	// drop-in replacement without changing any call site.
	http3      bool // enable HTTP/3 transport for all requests
	http3Probe bool // bypass Alt-Svc cache and always probe H3 first

	// TLS tweaks.
	tlsDisableSessionTickets bool
	tlsPreferRSA             bool // restricts max TLS version to 1.2

	// Proxy configuration.
	proxyDialer       *netproxy.Dialer
	httpProxyFunction func(*http.Request) (*url.URL, error)

	// Client credentials and debug hooks.
	tlsClientCreds DOHClientCreds
	keyLogWriter   io.Writer

	// resolveMu stores one *sync.Mutex per hostname (sync.Map values).
	// Ensures at most one goroutine resolves a given host at a time.
	resolveMu sync.Map // map[string]*sync.Mutex
}

// ── Constructor ───────────────────────────────────────────────────────────────

// NewXTransport allocates an *XTransport with safe production defaults.
// Panics if DefaultBootstrapResolver is not a valid IP:port — that is a
// programming error detectable at startup, not a recoverable runtime condition.
func NewXTransport() *XTransport {
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
		panic("DefaultBootstrapResolver is not a valid IP:port — " + err.Error())
	}
	return &XTransport{
		cachedIPs:          CachedIPs{cache: make(map[string]*CachedIPItem)},
		altSupport:         AltSupport{cache: make(map[string]altSvcEntry)},
		keepAlive:          DefaultKeepAlive,
		timeout:            DefaultTimeout,
		bootstrapResolvers: []string{DefaultBootstrapResolver},
		ignoreSystemDNS:    true,
		useIPv4:            true,
	}
}

// ── IP helpers ────────────────────────────────────────────────────────────────

// ParseIP parses an IP address string. Bracketed IPv6 (e.g. "[::1]") is
// accepted; brackets are stripped before parsing. Returns nil for invalid input.
func ParseIP(ipStr string) net.IP {
	ipStr = strings.TrimPrefix(ipStr, "[")
	ipStr = strings.TrimSuffix(ipStr, "]")
	return net.ParseIP(ipStr)
}

// netIPToNetipAddr converts net.IP → netip.Addr with zero allocation.
// Uses Go 1.20 direct slice→array conversion ([4]byte(ip) / [16]byte(ip))
// to skip the copy that net/netip.AddrFromSlice must perform for safety.
// IPv4-mapped IPv6 addresses are Unmapped so 1.2.3.4 and ::ffff:1.2.3.4
// hash to the same deduplication key.
// Returns (zero, false) for any slice whose length is neither 4 nor 16.
func netIPToNetipAddr(ip net.IP) (netip.Addr, bool) {
	switch len(ip) {
	case 4:
		return netip.AddrFrom4([4]byte(ip)), true
	case 16:
		// Unmap promotes IPv4-mapped IPv6 addresses so deduplication is
		// family-agnostic.
		return netip.AddrFrom16([16]byte(ip)).Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

// uniqueNormalizedIPs returns a deduplicated, deep-copied slice of net.IP
// preserving first-occurrence order. nil entries are silently dropped.
// 0- and 1-element fast-paths skip map allocation — single-address results
// are the dominant case for DNS A lookups.
func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	switch len(ips) {
	case 0:
		return nil
	case 1:
		if ips[0] == nil {
			return nil
		}
		// slices.Clone (Go 1.21) deep-copies the single byte slice.
		return []net.IP{slices.Clone(ips[0])}
	}
	// Pre-size both collections at len(ips) to avoid any growth reallocation.
	seen := make(map[netip.Addr]struct{}, len(ips))
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		addr, ok := netIPToNetipAddr(ip)
		if !ok {
			// Non-standard length — include without deduplication.
			out = append(out, slices.Clone(ip))
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, slices.Clone(ip))
	}
	return out
}

// ── IP cache ──────────────────────────────────────────────────────────────────

// saveCachedIPs stores resolved IPs for host under the given TTL.
// A uniform-random jitter in [0, ResolverIPTTLMaxJitter) spreads re-resolution
// events over time. Any TTL below MinResolverIPTTL is raised to the floor.
// Pass ttl < 0 to store a permanently-valid (no-expiry) entry.
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
		// rand.Int64N is the Go 1.22+ lock-free API from math/rand/v2.
		ttl += time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))
		exp := time.Now().Add(ttl)
		item.expiration = &exp
	}

	x.cachedIPs.Lock()
	item.updatingUntil = nil // clear any in-progress marker atomically with the write
	x.cachedIPs.cache[host] = item
	x.cachedIPs.Unlock()

	if len(normalized) == 1 {
		dlog.Debugf("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)
	} else {
		dlog.Debugf("[%s] cached %d IPs (first: %s), valid for %v",
			host, len(normalized), normalized[0], ttl)
	}
}

// saveCachedIP is a single-address convenience wrapper. No-op when ip is nil.
func (x *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip != nil {
		x.saveCachedIPs(host, []net.IP{ip}, ttl)
	}
}

// markUpdatingCachedIP writes an "update in progress" placeholder for host.
// For hosts with no existing entry a new CachedIPItem is inserted so that
// concurrent goroutines observe the updating flag and skip duplicate queries.
func (x *XTransport) markUpdatingCachedIP(host string) {
	until := time.Now().Add(x.timeout)
	x.cachedIPs.Lock()
	if item, ok := x.cachedIPs.cache[host]; ok {
		// item is a pointer; mutating it is visible to readers without reassignment.
		item.updatingUntil = &until
	} else {
		x.cachedIPs.cache[host] = &CachedIPItem{updatingUntil: &until}
	}
	x.cachedIPs.Unlock()
	dlog.Debugf("[%s] IP address marked as updating", host)
}

// loadCachedIPs returns a deep-copied snapshot of cached IPs for host,
// plus two freshness flags:
//   - expired  — entry exists but its TTL has elapsed
//   - updating — another goroutine is currently resolving host
//
// Callers may use the returned slice freely after the lock is released.
func (x *XTransport) loadCachedIPs(host string) (ips []net.IP, expired, updating bool) {
	x.cachedIPs.RLock()
	item, ok := x.cachedIPs.cache[host]
	if !ok {
		x.cachedIPs.RUnlock()
		dlog.Debugf("[%s] IP address not found in cache", host)
		return nil, false, false
	}
	// Deep-copy all slices while holding the read lock so callers never
	// observe aliased memory after the lock is released.
	if n := len(item.ips); n > 0 {
		ips = make([]net.IP, 0, n) // pre-sized to avoid growth
		for _, ip := range item.ips {
			if ip != nil {
				ips = append(ips, slices.Clone(ip))
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
			dlog.Debugf("[%s] cached IPs are being updated", host)
		} else {
			dlog.Debugf("[%s] cached IPs have expired", host)
		}
	}
	return ips, expired, updating
}

// ── Transport construction ────────────────────────────────────────────────────

// rebuildTransport (re-)initialises the HTTP/2 and HTTP/3 transports.
// Call once before the first Fetch, and again whenever TLS configuration or
// proxy settings change. The previous transport's idle connections are closed
// promptly to release file descriptors.
func (x *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport")
	if x.transport != nil {
		x.transport.CloseIdleConnections()
	}

	// Shared TLS config — callers that need per-connection mutation
	// (e.g. setting ServerName in the H3 dialer) must call Clone() on it.
	x.tlsClientConfig = x.buildTLSConfig()

	transport := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true, // compression is handled manually in Fetch
		MaxIdleConns:           MaxIdleConns,
		IdleConnTimeout:        DefaultIdleConnTimeout,
		TLSHandshakeTimeout:    TLSHandshakeTimeout,
		ResponseHeaderTimeout:  x.timeout,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: MaxResponseHeaderBytes,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        x.tlsClientConfig,
		DialContext:            x.buildDialContext(),
	}
	if x.httpProxyFunction != nil {
		transport.Proxy = x.httpProxyFunction
	}

	// http2.ConfigureTransports (plural) is the preferred Go 1.26 API.
	// It returns *http2.Transport for fine-grained tuning not available
	// through the singular ConfigureTransport.
	if h2t, err := http2.ConfigureTransports(transport); err == nil && h2t != nil {
		h2t.ReadIdleTimeout = 30 * time.Second
		h2t.PingTimeout = 15 * time.Second
		h2t.WriteByteTimeout = 10 * time.Second
		h2t.AllowHTTP = false
		h2t.StrictMaxConcurrentStreams = false
	}
	x.transport = transport

	if x.http3 {
		x.h3Transport = &http3.Transport{
			DisableCompression: true,
			TLSClientConfig:    x.tlsClientConfig, // cloned per-connection in the H3 dialer
			Dial:               x.buildH3DialFunc(),
		}
	}
}

// buildDialContext returns the DialContext hook for the HTTP/2 transport.
//
// Strategy: consult the local IP cache first, trying addresses in order.
// Fall back to dialling the raw hostname (OS resolver) when the cache is empty.
//
// portStr is computed once per closure invocation before the endpoint helper
// so strconv.Itoa is not called once per cached address on the hot dial path.
// net.Dialer is constructed once outside the per-target loop, avoiding
// repeated heap allocation when multiple IPs exist for a host.
func (x *XTransport) buildDialContext() func(context.Context, string, string) (net.Conn, error) {
	timeout := x.timeout // snapshot to avoid retaining a live pointer into XTransport
	return func(ctx context.Context, network, addrStr string) (net.Conn, error) {
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
		portStr := strconv.Itoa(port) // computed once for all endpoint() calls below

		// endpoint builds the dial target string for a given IP (or nil = raw host).
		endpoint := func(ip net.IP) string {
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					return v4.String() + ":" + portStr
				}
				return "[" + ip.String() + "]:" + portStr
			}
			// No cached address — fall back to the raw host; wrap bare IPv6 in brackets.
			if parsed := ParseIP(host); parsed != nil && parsed.To4() == nil {
				return "[" + parsed.String() + "]:" + portStr
			}
			return host + ":" + portStr
		}

		cachedIPs, _, _ := x.loadCachedIPs(host)
		// max() builtin (Go 1.21) avoids a conditional capacity hint expression.
		targets := make([]string, 0, max(len(cachedIPs), 1))
		for _, ip := range cachedIPs {
			targets = append(targets, endpoint(ip))
		}
		if len(targets) == 0 {
			dlog.Debugf("[%s] no cached IP; falling back to hostname dial", host)
			targets = append(targets, endpoint(nil))
		}

		// Construct the dialer once; reuse across all target attempts.
		d := &net.Dialer{
			Timeout:   timeout,
			KeepAlive: x.keepAlive,
			DualStack: true,
		}

		var lastErr error
		for i, target := range targets {
			var conn net.Conn
			var err error
			if x.proxyDialer == nil {
				conn, err = d.DialContext(ctx, network, target)
			} else {
				conn, err = (*x.proxyDialer).Dial(network, target)
			}
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if i < len(targets)-1 {
				dlog.Debugf("Dial [%s] failed: %v", target, err)
			}
		}
		return nil, lastErr
	}
}

// buildH3DialFunc returns the QUIC dial function for the HTTP/3 transport.
// Mirrors buildDialContext's cache-first strategy but opens UDP sockets.
//
// quic-go always passes nil as the *tls.Config argument — we ignore it via _
// and clone x.tlsClientConfig per connection to set ServerName without
// introducing a data race on the shared config.
func (x *XTransport) buildH3DialFunc() func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addrStr string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		dlog.Debugf("H3 dial: [%s]", addrStr)
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
		portStr := strconv.Itoa(port)

		// udpTarget bundles a resolved address string with its network name.
		type udpTarget struct{ addr, network string }

		// udpEndpoint derives the UDP target for a given IP (nil = raw host).
		udpEndpoint := func(ip net.IP) udpTarget {
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					return udpTarget{v4.String() + ":" + portStr, "udp4"}
				}
				return udpTarget{"[" + ip.String() + "]:" + portStr, "udp6"}
			}
			// No cached IP — derive network name from the host string itself.
			nw, addr := "udp4", host
			if parsed := ParseIP(host); parsed != nil {
				if parsed.To4() == nil {
					nw, addr = "udp6", "["+parsed.String()+"]"
				} else {
					addr = parsed.String()
				}
			} else if x.useIPv6 {
				if x.useIPv4 {
					nw = "udp" // dual-stack
				} else {
					nw = "udp6"
				}
			}
			return udpTarget{addr + ":" + portStr, nw}
		}

		cachedIPs, _, _ := x.loadCachedIPs(host)
		targets := make([]udpTarget, 0, max(len(cachedIPs), 1))
		for _, ip := range cachedIPs {
			targets = append(targets, udpEndpoint(ip))
		}
		if len(targets) == 0 {
			dlog.Debugf("[%s] no cached IP for H3 dial", host)
			targets = append(targets, udpEndpoint(nil))
		}

		var lastErr error
		for i, t := range targets {
			udpAddr, err := net.ResolveUDPAddr(t.network, t.addr)
			if err != nil {
				lastErr = err
				if i < len(targets)-1 {
					dlog.Debugf("H3: resolve [%s]/%s failed: %v", t.addr, t.network, err)
				}
				continue
			}
			udpConn, err := net.ListenUDP(t.network, nil)
			if err != nil {
				lastErr = err
				if i < len(targets)-1 {
					dlog.Debugf("H3: listen [%s]/%s failed: %v", t.addr, t.network, err)
				}
				continue
			}
			// Clone the shared config so ServerName can be set safely per-connection.
			tlsCfg := x.tlsClientConfig.Clone()
			tlsCfg.ServerName = host
			conn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
			if err != nil {
				_ = udpConn.Close()
				lastErr = err
				if i < len(targets)-1 {
					dlog.Debugf("H3: quic.DialEarly [%s]/%s failed: %v", t.addr, t.network, err)
				}
				continue
			}
			return conn, nil
		}
		return nil, lastErr
	}
}

// buildTLSConfig constructs a *tls.Config from all active user preferences.
// The result is stored on XTransport and shared between the HTTP/2 and HTTP/3
// transports. Per-connection mutations (e.g. setting ServerName) require Clone().
func (x *XTransport) buildTLSConfig() *tls.Config {
	cfg := &tls.Config{}

	if x.keyLogWriter != nil {
		cfg.KeyLogWriter = x.keyLogWriter
	}

	certPool, certPoolErr := x509.SystemCertPool()
	creds := x.tlsClientCreds

	if creds.rootCA != "" {
		if certPool == nil {
			dlog.Fatalf("Custom root CA not supported on this platform: %v", certPoolErr)
		}
		pem, err := os.ReadFile(creds.rootCA)
		if err != nil {
			dlog.Fatalf("Unable to read rootCA [%s]: %v", creds.rootCA, err)
		}
		certPool.AppendCertsFromPEM(pem)
	}
	if certPool != nil {
		// Bundle ISRG Root X1 so Let's Encrypt–signed DoH servers validate on OS
		// trust stores predating its wide distribution.
		certPool.AppendCertsFromPEM(isrgRootX1PEM)
		cfg.RootCAs = certPool
	}

	if creds.clientCert != "" {
		cert, err := tls.LoadX509KeyPair(creds.clientCert, creds.clientKey)
		if err != nil {
			dlog.Fatalf("Unable to load client cert [%s] / key [%s]: %v",
				creds.clientCert, creds.clientKey, err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if x.tlsDisableSessionTickets {
		cfg.SessionTicketsDisabled = true
	}
	if x.tlsPreferRSA {
		// Restrict to TLS 1.2 max to force RSA cipher suites.
		cfg.MaxVersion = tls.VersionTLS12
	}

	// Order cipher suites so the hardware-accelerated cipher leads.
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

// ── Embedded root certificate ─────────────────────────────────────────────────

// isrgRootX1PEM is the ISRG Root X1 certificate (Let's Encrypt's root CA)
// embedded in PEM form so that DoH servers with LE certificates are trusted
// even on OS trust stores built before ISRG Root X1 was widely distributed.
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

// ── DNS resolution ────────────────────────────────────────────────────────────

// resolveUsingSystem queries the OS resolver and filters by address family.
// Returns nil (not []IP{}) when no IPs of the requested family are present;
// len(ips)==0 is always the canonical "no result" check.
// The OS resolver does not expose per-record TTLs, so a fixed synthetic TTL
// of SystemResolverIPTTL is always returned.
func (x *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	all, err := net.LookupIP(host)
	if err != nil && len(all) == 0 {
		return nil, SystemResolverIPTTL, err
	}
	if returnIPv4 && returnIPv6 {
		return all, SystemResolverIPTTL, err
	}
	ips := make([]net.IP, 0, len(all))
	for _, ip := range all {
		v4 := ip.To4()
		switch {
		case returnIPv4 && v4 != nil:
			ips = append(ips, v4)
		case returnIPv6 && v4 == nil:
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		// Return nil, not []net.IP{}, so len(ips)==0 is always the correct test.
		return nil, SystemResolverIPTTL, err
	}
	return ips, SystemResolverIPTTL, err
}

// resolveUsingResolver sends A and/or AAAA queries to a single DNS resolver.
// Errors for each query type are tracked independently: a AAAA timeout never
// discards A results already collected. The minimum TTL across all answer RRs
// is returned so the cache entry expires no later than the shortest-lived record.
func (x *XTransport) resolveUsingResolver(
	proto, host, resolver string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	tr := dns.NewTransport()
	tr.ReadTimeout = ResolverReadTimeout
	client := dns.Client{Transport: tr}

	var queryTypes []uint16
	if returnIPv4 {
		queryTypes = append(queryTypes, dns.TypeA)
	}
	if returnIPv6 {
		queryTypes = append(queryTypes, dns.TypeAAAA)
	}

	// context.WithTimeout: open-coded defer cancel() is zero-overhead in Go 1.21+.
	ctx, cancel := context.WithTimeout(context.Background(), ResolverReadTimeout)
	defer cancel()

	minTTL := noTTL // sentinel: no TTL observed yet
	var lastErr error

	for _, rrType := range queryTypes {
		msg := dns.NewMsg(fqdn(host), rrType)
		if msg == nil {
			continue
		}
		msg.RecursionDesired = true
		msg.UDPSize = uint16(MaxDNSPacketSize)
		msg.Security = true

		in, _, qErr := client.Exchange(ctx, msg, proto, resolver)
		if qErr != nil {
			// Track per-type; do not abort the sibling query type.
			lastErr = qErr
			continue
		}
		for _, answer := range in.Answer {
			if dns.RRToType(answer) != rrType {
				continue // skip records of unexpected type (e.g. CNAMEs)
			}
			switch rrType {
			case dns.TypeA:
				ips = append(ips, answer.(*dns.A).A.Addr.AsSlice())
			case dns.TypeAAAA:
				ips = append(ips, answer.(*dns.AAAA).AAAA.Addr.AsSlice())
			}
			// Track minimum TTL so the cache entry respects the shortest-lived record.
			if rTTL := answer.Header().TTL; rTTL < minTTL {
				minTTL = rTTL
			}
		}
	}

	if len(ips) > 0 {
		if minTTL == noTTL {
			minTTL = 0 // sentinel never updated: no TTL records seen
		}
		return ips, time.Duration(minTTL) * time.Second, nil
	}
	if lastErr != nil {
		return nil, 0, lastErr
	}
	return nil, 0, errors.New("no IP records returned")
}

// resolveUsingServers iterates over resolvers with per-resolver exponential
// back-off. On first success the winning resolver is swapped to index 0
// (self-healing affinity) so subsequent calls reuse the fastest known-good
// resolver rather than always starting from the front of the list.
func (x *XTransport) resolveUsingServers(
	proto, host string,
	resolvers []string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
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
					// Promote the winning resolver to the front for future calls.
					dlog.Infof("Resolution succeeded via %s[%s]; promoting to first", proto, resolver)
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
				// min() builtin (Go 1.21) replaces a hand-rolled ternary for the cap.
				delay = min(delay*2, resolverRetryMaxBackoff)
			}
		}
		dlog.Infof("Unable to resolve [%s] using [%s] (%s): %v", host, resolver, proto, lastErr)
	}
	if lastErr == nil {
		lastErr = errors.New("no IP addresses returned")
	}
	return nil, 0, lastErr
}

// resolve selects the best available resolution strategy in priority order:
//  1. Internal resolvers    — when ignoreSystemDNS && internalResolverReady
//  2. OS system resolver    — when ignoreSystemDNS == false
//  3. Bootstrap resolvers   — fallback after primary strategy failure
//  4. OS system resolver    — last resort when ignoreSystemDNS == true
func (x *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	// [2]string fixed array: stack-allocated, no slice header, no heap escape.
	protos := [2]string{"udp", "tcp"}
	if x.mainProto == "tcp" {
		protos = [2]string{"tcp", "udp"}
	}

	var (
		ips []net.IP
		ttl time.Duration
		err error
	)

	if x.ignoreSystemDNS {
		if x.internalResolverReady {
			for _, proto := range protos {
				ips, ttl, err = x.resolveUsingServers(proto, host, x.internalResolvers, returnIPv4, returnIPv6)
				if err == nil {
					return ips, ttl, nil
				}
			}
		} else {
			err = errors.New("dnscrypt-proxy service is not ready yet")
			dlog.Notice(err)
		}
	} else {
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)
		if err != nil {
			err = fmt.Errorf("system DNS: %w", err)
			dlog.Notice(err)
		} else {
			return ips, ttl, nil
		}
	}

	// Bootstrap resolvers as second-tier fallback.
	for _, proto := range protos {
		dlog.Noticef("Resolving [%s] via bootstrap resolvers over %s", host, proto)
		ips, ttl, err = x.resolveUsingServers(proto, host, x.bootstrapResolvers, returnIPv4, returnIPv6)
		if err == nil {
			return ips, ttl, nil
		}
	}

	if x.ignoreSystemDNS {
		// Last resort: OS resolver, even though the user asked us to ignore it.
		dlog.Noticef("Bootstrap resolvers failed — last-resort system resolver for [%s]", host)
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)
	}
	return ips, ttl, err
}

// hostResolveMu returns the per-host *sync.Mutex, creating it on first call.
// sync.Map.LoadOrStore guarantees exactly one mutex is stored per host key.
func (x *XTransport) hostResolveMu(host string) *sync.Mutex {
	v, _ := x.resolveMu.LoadOrStore(host, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// resolveAndUpdateCache resolves host if the cache is absent or expired, then
// writes the fresh result. Concurrent callers for the same host serialise on a
// per-host mutex (double-checked locking) so exactly one DNS query fires.
func (x *XTransport) resolveAndUpdateCache(host string) error {
	// Proxy-dialled connections skip our DNS resolver entirely.
	if x.proxyDialer != nil || x.httpProxyFunction != nil {
		return nil
	}
	// Literal IP addresses do not need resolution.
	if ParseIP(host) != nil {
		return nil
	}

	cachedIPs, expired, updating := x.loadCachedIPs(host)
	if len(cachedIPs) > 0 && (!expired || updating) {
		return nil
	}

	mu := x.hostResolveMu(host)
	mu.Lock()
	defer mu.Unlock()

	// Double-check: another goroutine may have resolved host while we waited.
	cachedIPs, expired, _ = x.loadCachedIPs(host)
	if len(cachedIPs) > 0 && !expired {
		return nil
	}

	// Signal "in progress" before releasing the read view so any concurrent
	// dial sees the updating flag and does not trigger a second query.
	x.markUpdatingCachedIP(host)

	ips, ttl, err := x.resolve(host, x.useIPv4, x.useIPv6)
	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}

	selectedIPs := ips

	// Serve stale cache on failure rather than completely breaking connectivity.
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {
		dlog.Noticef("Using stale cached address for [%s] (grace period)", host)
		selectedIPs = cachedIPs
		ttl = ExpiredCachedIPGraceTTL
		err = nil // clear; stale service is a success from the caller's perspective
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

// ── HTTP API ──────────────────────────────────────────────────────────────────

// Fetch performs a single HTTP request and returns the response body.
//
// Parameters:
//   - method      — HTTP verb ("GET", "POST", …)
//   - url         — fully qualified request URL
//   - accept      — Accept header; omitted when empty
//   - contentType — Content-Type header; omitted when empty
//   - body        — request body; nil for bodyless methods
//   - timeout     — per-request deadline; ≤ 0 falls back to x.timeout
//   - compress    — when true, advertises "Accept-Encoding: gzip" and
//     transparently decompresses gzip responses
//
// Returns (responseBody, httpStatusCode, tlsState, roundTripTime, error).
// Non-2xx responses are returned as non-nil errors (message = HTTP status text).
// On HTTP/3 transport failure the request is automatically retried over HTTP/2.
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

	// ── Transport selection ───────────────────────────────────────────────────
	if x.h3Transport != nil {
		if x.http3Probe {
			// Bypass the Alt-Svc cache and always attempt H3 first.
			client.Transport = x.h3Transport
			dlog.Debugf("Probing HTTP/3 for [%s]", url.Host)
		} else {
			x.altSupport.RLock()
			entry, inCache := x.altSupport.cache[url.Host]
			x.altSupport.RUnlock()
			if inCache {
				hasAltSupport = true
				negativeExpired := entry.port == 0 &&
					!entry.validTo.IsZero() &&
					time.Now().After(entry.validTo)
				switch {
				case entry.port > 0 && int(entry.port) == port:
					client.Transport = x.h3Transport
					dlog.Debugf("Using cached HTTP/3 for [%s]", url.Host)
				case negativeExpired:
					// Negative entry has expired; allow re-probe.
					hasAltSupport = false
				}
			}
		}
	}

	// ── Pre-flight checks ─────────────────────────────────────────────────────
	if x.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0,
			errors.New("onion service requires a configured Tor proxy")
	}
	if err := x.resolveAndUpdateCache(host); err != nil {
		dlog.Errorf("Unable to resolve [%s]: check bootstrap_resolvers or system resolver", host)
		return nil, 0, nil, 0, err
	}

	// ── Build request headers ─────────────────────────────────────────────────
	// Pre-sized to the maximum number of headers we will ever set (5) to avoid
	// any internal rehash on the hot path.
	header := make(http.Header, 5)
	header.Set("User-Agent", "dnscrypt-proxy")
	header.Set("Cache-Control", "max-stale")
	if accept != "" {
		header.Set("Accept", accept)
	}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	if compress && body == nil {
		header.Set("Accept-Encoding", "gzip")
	}

	// Append a SHA-512/256 body hash in the query string so upstream caches
	// can distinguish requests with different payloads on the same URL path.
	if body != nil {
		h := sha512.Sum512(*body)
		qs := url.Query()
		qs.Add("body_hash", hex.EncodeToString(h[:32]))
		u2 := *url
		u2.RawQuery = qs.Encode()
		url = &u2
	}

	// ── Build request ─────────────────────────────────────────────────────────
	bodyLen := 0
	if body != nil {
		bodyLen = len(*body)
	}
	req := &http.Request{
		Method:        method,
		URL:           url,
		Header:        header,
		Close:         false,
		ContentLength: int64(bodyLen),
	}
	if body != nil {
		req.Body = io.NopCloser(bytes.NewReader(*body))
	}

	// ── Execute ───────────────────────────────────────────────────────────────
	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	// HTTP/3 failed — record a timed negative entry and fall back to HTTP/2.
	if err != nil && client.Transport == x.h3Transport {
		dlog.Debugf("HTTP/3 failed for [%s]: %v — retrying over HTTP/2", url.Host, err)
		x.altSupport.Lock()
		x.altSupport.cache[url.Host] = altSvcEntry{
			port:    0,
			validTo: time.Now().Add(altSvcNegativeTTL),
		}
		x.altSupport.Unlock()

		client.Transport = x.transport
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(*body))
			// Reset ContentLength: net/http requires it after body reassignment.
			req.ContentLength = int64(bodyLen)
		}
		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)
	}

	// Nil guard MUST come before any access to resp fields.
	if resp != nil {
		defer resp.Body.Close()
	}

	statusCode := 503
	if resp != nil {
		statusCode = resp.StatusCode
	}

	if err == nil {
		switch {
		case resp == nil:
			err = errors.New("server returned an empty response")
		case resp.StatusCode < 200 || resp.StatusCode > 299:
			err = errors.New(resp.Status)
		}
	} else {
		// Close idle connections on transport error to avoid connection reuse
		// on a potentially broken path.
		dlog.Debugf("HTTP error [%s]: %v — closing idle connections", url.Host, err)
		x.transport.CloseIdleConnections()
	}

	if err != nil {
		dlog.Debugf("[%s]: %v", req.URL, err)
		return nil, statusCode, nil, rtt, err
	}

	// Parse Alt-Svc for future H3 upgrade (skip when we already knew about it).
	if x.h3Transport != nil && !hasAltSupport {
		x.parseAndCacheAltSvc(url.Host, port, resp.Header)
	}

	tlsState := resp.TLS

	// ── Read and optionally decompress response body ───────────────────────────
	var bodyReader io.Reader = resp.Body
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
// per-host entry in altSupport.
// Positive entries (port > 0) have no expiry. Negative entries (port == 0)
// carry a validTo time so recovering servers are retried after altSvcNegativeTTL.
func (x *XTransport) parseAndCacheAltSvc(host string, port int, header http.Header) {
	// Honour an active negative entry — skip parsing entirely.
	x.altSupport.RLock()
	existing, inCache := x.altSupport.cache[host]
	x.altSupport.RUnlock()
	if inCache && existing.port == 0 &&
		(existing.validTo.IsZero() || time.Now().Before(existing.validTo)) {
		dlog.Debugf("Alt-Svc: negative cache still valid for [%s]; skipping", host)
		return
	}

	alt, found := header["Alt-Svc"]
	if !found {
		return
	}
	dlog.Debugf("Alt-Svc [%s]: %v", host, alt)

	altPort := uint16(port & 0xffff) // default: same port as the HTTP/2 connection

outer:
	for i, entry := range alt {
		if i >= 8 { // guard against unreasonably long headers
			break
		}
		for j, field := range strings.Split(entry, ";") {
			if j >= 16 {
				break
			}
			// strings.CutPrefix (Go 1.20) is cleaner than HasPrefix + manual slice.
			if after, ok := strings.CutPrefix(strings.TrimSpace(field), `h3=":`); ok {
				v := strings.TrimSuffix(after, `"`)
				if p, pErr := strconv.ParseUint(v, 10, 16); pErr == nil && p <= 65535 {
					altPort = uint16(p)
					dlog.Debugf("Alt-Svc: HTTP/3 advertised for [%s] on port %d", host, altPort)
					break outer
				}
			}
		}
	}

	x.altSupport.Lock()
	// Positive entry: no expiry (zero validTo).
	x.altSupport.cache[host] = altSvcEntry{port: altPort}
	dlog.Debugf("Alt-Svc: cached port %d for [%s]", altPort, host)
	x.altSupport.Unlock()
}

// ── Public query helpers ──────────────────────────────────────────────────────

// GetWithCompression performs a GET request with Accept-Encoding: gzip and
// transparent decompression of gzip responses.
func (x *XTransport) GetWithCompression(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("GET", url, accept, "", nil, timeout, true)
}

// Get performs a plain GET request without content-encoding negotiation.
func (x *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("GET", url, accept, "", nil, timeout, false)
}

// Post performs a POST request with the supplied body.
func (x *XTransport) Post(
	url *url.URL,
	accept, contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("POST", url, accept, contentType, body, timeout, false)
}

// dohLikeQuery is the shared implementation for DoH and ODoH queries.
// When useGet is true the DNS payload is base64url-encoded into the "dns"
// query parameter (RFC 8484 §4.1 GET form); otherwise a POST is used.
func (x *XTransport) dohLikeQuery(
	dataType string,
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if useGet {
		qs := url.Query()
		qs.Add("dns", base64.RawURLEncoding.EncodeToString(body))
		u2 := *url
		u2.RawQuery = qs.Encode()
		return x.Get(&u2, dataType, timeout)
	}
	return x.Post(url, dataType, dataType, &body, timeout)
}

// DoHQuery performs a DNS-over-HTTPS query (RFC 8484, application/dns-message).
func (x *XTransport) DoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/dns-message", useGet, url, body, timeout)
}

// ObliviousDoHQuery performs an Oblivious DNS-over-HTTPS query
// (RFC 9230, application/oblivious-dns-message).
func (x *XTransport) ObliviousDoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}
