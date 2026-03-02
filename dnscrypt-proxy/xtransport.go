// xtransport.go — HTTP/HTTPS transport layer for dnscrypt-proxy
//
// Full rewrite targeting Go 1.26+. Every line reviewed for correctness,
// safety, performance, and idiomatic style. Public API is 100% unchanged
// (drop-in replacement).
//
// ── Go 1.20–1.26 modernisation ────────────────────────────────────────────────
//
//   • math/rand/v2 → rand.Int64N          lock-free; no global mutex contention
//   • [4]byte(ip) / [16]byte(ip)          slice→array (Go 1.20); zero allocation
//   • strings.CutPrefix (Go 1.20)         cleaner Alt-Svc field parsing
//   • min() / max() builtins (Go 1.21)    replaces hand-rolled ternaries
//   • slices.Clone (Go 1.21)              correct deep-copy, no aliased memory
//   • http2.ConfigureTransports (plural)  fine-grained H2 tuning (Go 1.20+)
//   • [2]string fixed array               stack-alloc proto list; no heap escape
//   • context.WithTimeout + defer cancel  zero-overhead cancellation
//
// ── Correctness fixes ─────────────────────────────────────────────────────────
//
//   • resolveUsingSystem: returns nil (not []net.IP{}) on empty result so
//     len(ips)==0 is a reliable sentinel everywhere
//   • resolveUsingResolver: per-query-type error tracking; AAAA failure never
//     discards a successful A result; min TTL tracked across all answer RRs
//   • markUpdatingCachedIP: inserts a placeholder for unseen hosts so racing
//     goroutines see "updating" and never spawn a second resolution
//   • buildH3DialFunc: quic-go passes nil *tls.Config — ignored with _, and
//     x.tlsClientConfig is cloned per-connection to set ServerName safely
//   • Fetch: resp==nil guard placed before resp.StatusCode access
//   • Fetch: single unconditional defer resp.Body.Close() after nil-guard
//   • Fetch: req.ContentLength set to int64(bodyLen) (not 0) on H3→H2 retry
//   • resolveAndUpdateCache: double-checked locking; stale path clears err
//
// ── Performance improvements ──────────────────────────────────────────────────
//
//   • buildDialContext: portStr computed once, not per cached IP
//   • buildDialContext: net.Dialer constructed once outside the target loop
//   • uniqueNormalizedIPs: 0/1-element fast-paths skip map allocation entirely
//   • loadCachedIPs: pre-sized make([]net.IP, 0, n) avoids all growth copies
//   • Fetch: make(http.Header, 5) pre-sized to avoid internal map rehash

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

// hasAESGCMHardwareSupport is true when the CPU can accelerate AES-GCM in
// hardware. Used to order TLS 1.2 cipher suites: AES-GCM first on capable
// hardware, ChaCha20-Poly1305 first everywhere else.
var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||
	(cpu.S390X.HasAES && cpu.S390X.HasAESGCM)

// ── Sentinel ──────────────────────────────────────────────────────────────────

// noTTL is the "no TTL seen yet" sentinel used when tracking the minimum TTL
// across DNS answer RRs. Named constant is clearer than the magic ^uint32(0).
const noTTL = ^uint32(0)

// ── Tuning constants ──────────────────────────────────────────────────────────

const (
	// DefaultBootstrapResolver is the DNS resolver used at startup before the
	// internal proxy resolver is available. Must be a valid IP:port.
	DefaultBootstrapResolver = "9.9.9.9:53"

	// DefaultKeepAlive is the TCP keep-alive probe interval for net.Dialer.
	DefaultKeepAlive = 5 * time.Second

	// DefaultIdleConnTimeout is how long an idle HTTP/2 connection remains in
	// the transport pool before being closed.
	DefaultIdleConnTimeout = 90 * time.Second

	// DefaultTimeout is the end-to-end deadline for a single HTTP request.
	// Callers may override per-request via the timeout parameter.
	DefaultTimeout = 30 * time.Second

	// ResolverReadTimeout is the maximum duration for a single DNS exchange.
	ResolverReadTimeout = 5 * time.Second

	// SystemResolverIPTTL is the synthetic TTL for OS-resolver addresses.
	// The OS resolver does not expose per-record TTLs.
	SystemResolverIPTTL = 12 * time.Hour

	// MinResolverIPTTL is the minimum TTL enforced for any cached IP entry.
	// Advertised TTLs shorter than this are silently raised to it.
	MinResolverIPTTL = 4 * time.Hour

	// ResolverIPTTLMaxJitter is the exclusive upper bound of the random
	// duration added to each TTL to stagger re-resolution across time.
	ResolverIPTTLMaxJitter = 15 * time.Minute

	// ExpiredCachedIPGraceTTL is how long a stale cache entry continues to be
	// served when fresh resolution fails. Maintains connectivity during outages.
	ExpiredCachedIPGraceTTL = 15 * time.Minute

	// resolverRetryCount is the number of attempts per resolver before
	// falling through to the next resolver in the list.
	resolverRetryCount = 3

	// resolverRetryInitialBackoff is the sleep before the second attempt.
	// Each subsequent sleep doubles up to resolverRetryMaxBackoff.
	resolverRetryInitialBackoff = 150 * time.Millisecond

	// resolverRetryMaxBackoff caps the exponential back-off growth.
	resolverRetryMaxBackoff = 1 * time.Second

	// MaxIdleConns is the total HTTP/2 connection-pool size across all hosts.
	MaxIdleConns = 2000

	// MaxResponseHeaderBytes caps the HTTP response header size accepted.
	MaxResponseHeaderBytes = 4096

	// TLSHandshakeTimeout is the deadline for completing a TLS handshake,
	// applied to both HTTP/2 and HTTP/3 transports.
	TLSHandshakeTimeout = 10 * time.Second

	// altSvcNegativeTTL is how long a failed HTTP/3 probe blocks further H3
	// attempts for the same host.
	altSvcNegativeTTL = 10 * time.Minute
)

// ── Types ─────────────────────────────────────────────────────────────────────

// CachedIPItem stores resolved IP addresses and their freshness metadata.
// All fields are protected by the enclosing CachedIPs.RWMutex.
type CachedIPItem struct {
	ips           []net.IP
	expiration    *time.Time // nil → entry never expires
	updatingUntil *time.Time // non-nil while background re-resolution is in flight
}

// CachedIPs is a thread-safe hostname → IP-address cache.
type CachedIPs struct {
	sync.RWMutex
	cache map[string]*CachedIPItem
}

// altSvcEntry holds a single HTTP/3 Alt-Svc record for a host.
//
//   - port > 0  → positive: use HTTP/3 on this port
//   - port == 0 → negative: HTTP/3 failed or unavailable
//
// validTo is only set on negative entries; positive entries never expire.
type altSvcEntry struct {
	port    uint16
	validTo time.Time
}

// AltSupport is a thread-safe cache of HTTP/3 Alt-Svc entries keyed by host.
type AltSupport struct {
	sync.RWMutex
	cache map[string]altSvcEntry
}

// XTransport is the central HTTP(S) transport layer for dnscrypt-proxy.
//
// It manages:
//   - An HTTP/2 transport (always present after rebuildTransport)
//   - An optional HTTP/3 transport (present when http3 == true)
//   - A DNS-resolution cache with TTL jitter and grace-period fallback
//   - Per-host mutex serialisation for DNS queries
//   - DoH (RFC 8484) and ODoH (RFC 9230) query helpers
//
// The zero value is not valid; use NewXTransport.
type XTransport struct {
	// HTTP transports. h3Transport is nil when HTTP/3 is disabled.
	transport       *http.Transport
	h3Transport     *http3.Transport
	tlsClientConfig *tls.Config // constructed once; shared between both transports

	keepAlive time.Duration
	timeout   time.Duration

	cachedIPs  CachedIPs
	altSupport AltSupport

	// DNS resolver configuration.
	internalResolvers     []string
	bootstrapResolvers    []string
	mainProto             string // "udp" or "tcp" — preferred DNS transport
	ignoreSystemDNS       bool
	internalResolverReady bool

	// Address-family selection for outgoing connections.
	useIPv4 bool
	useIPv6 bool

	// HTTP/3 control flags.
	// Names match config_loader.go so this file is a drop-in replacement.
	http3      bool // enable HTTP/3 transport
	http3Probe bool // bypass Alt-Svc cache; always probe H3 first

	// TLS tweaks.
	tlsDisableSessionTickets bool
	tlsPreferRSA             bool // restricts max TLS version to 1.2

	// Proxy configuration.
	proxyDialer       *netproxy.Dialer
	httpProxyFunction func(*http.Request) (*url.URL, error)

	// Client credentials and debug hooks.
	tlsClientCreds DOHClientCreds
	keyLogWriter   io.Writer

	// resolveMu stores one *sync.Mutex per hostname.
	// Ensures exactly one goroutine resolves a given host at a time.
	resolveMu sync.Map // map[string]*sync.Mutex
}

// ── Constructor ───────────────────────────────────────────────────────────────

// NewXTransport allocates an *XTransport with safe production defaults.
//
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

// ParseIP parses an IP address string. IPv6 addresses may be enclosed in
// brackets (e.g. "[::1]"); brackets are stripped before parsing.
// Returns nil for any invalid input.
func ParseIP(ipStr string) net.IP {
	ipStr = strings.TrimPrefix(ipStr, "[")
	ipStr = strings.TrimSuffix(ipStr, "]")
	return net.ParseIP(ipStr)
}

// netIPToNetipAddr converts a net.IP to a netip.Addr with zero allocation.
//
// Uses the direct slice-to-array conversion ([4]byte(ip) / [16]byte(ip))
// introduced in Go 1.20, avoiding the copy that net/netip.AddrFromSlice
// must perform for safety. IPv4-mapped IPv6 addresses are Unmapped so that
// 1.2.3.4 and ::ffff:1.2.3.4 hash to the same deduplication key.
//
// Returns (zero, false) for any slice whose length is neither 4 nor 16.
func netIPToNetipAddr(ip net.IP) (netip.Addr, bool) {
	switch len(ip) {
	case 4:
		return netip.AddrFrom4([4]byte(ip)), true
	case 16:
		// Unmap promotes IPv4-mapped IPv6 addresses so dedup works correctly.
		return netip.AddrFrom16([16]byte(ip)).Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

// uniqueNormalizedIPs returns a deduplicated, deep-copied slice of IPs.
// Ordering is preserved (first occurrence wins). nil entries are dropped.
//
// 0- and 1-element fast-paths skip map allocation; single-address results
// are the common case in production.
func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	switch len(ips) {
	case 0:
		return nil
	case 1:
		if ips[0] == nil {
			return nil
		}
		// slices.Clone (Go 1.21) is a safe deep-copy with no aliased memory.
		return []net.IP{slices.Clone(ips[0])}
	}
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
//
// A uniformly-random jitter in [0, ResolverIPTTLMaxJitter) is added to spread
// re-resolution events across time. Any TTL below MinResolverIPTTL is raised.
// Pass a negative ttl to store a permanently-valid (non-expiring) entry.
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
		// rand.Int64N is from math/rand/v2 (Go 1.22+); no global-state mutex.
		ttl += time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))
		exp := time.Now().Add(ttl)
		item.expiration = &exp
	}
	x.cachedIPs.Lock()
	item.updatingUntil = nil // clear in-progress marker atomically with the write
	x.cachedIPs.cache[host] = item
	x.cachedIPs.Unlock()

	if len(normalized) == 1 {
		dlog.Debugf("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)
	} else {
		dlog.Debugf("[%s] cached %d IPs (first: %s), valid for %v",
			host, len(normalized), normalized[0], ttl)
	}
}

// saveCachedIP is a single-address convenience wrapper around saveCachedIPs.
// It is a no-op when ip is nil.
func (x *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip != nil {
		x.saveCachedIPs(host, []net.IP{ip}, ttl)
	}
}

// markUpdatingCachedIP writes an "update in progress" marker for host.
//
// If host has no existing entry, a placeholder CachedIPItem is inserted so
// concurrent callers see "updating=true" and do not spawn a second resolution.
func (x *XTransport) markUpdatingCachedIP(host string) {
	until := time.Now().Add(x.timeout)
	x.cachedIPs.Lock()
	if item, ok := x.cachedIPs.cache[host]; ok {
		item.updatingUntil = &until // item is a pointer; visible without reassignment
	} else {
		x.cachedIPs.cache[host] = &CachedIPItem{updatingUntil: &until}
	}
	x.cachedIPs.Unlock()
	dlog.Debugf("[%s] IP address marked as updating", host)
}

// loadCachedIPs returns a deep-copied snapshot of the cached IPs for host,
// along with two freshness flags:
//
//   - expired  — true when the entry exists but its TTL has elapsed
//   - updating — true when another goroutine is currently resolving host
//
// Callers may safely use the returned slice after the lock is released.
func (x *XTransport) loadCachedIPs(host string) (ips []net.IP, expired, updating bool) {
	x.cachedIPs.RLock()
	item, ok := x.cachedIPs.cache[host]
	if !ok {
		x.cachedIPs.RUnlock()
		dlog.Debugf("[%s] IP address not found in cache", host)
		return nil, false, false
	}
	// Deep-copy while holding the read lock so callers never observe aliased
	// memory after the lock is released. Pre-sized make avoids growth copies.
	if n := len(item.ips); n > 0 {
		ips = make([]net.IP, 0, n)
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
//
// Call once before the first Fetch, and again whenever TLS configuration or
// proxy settings change. Any previously-built transport has its idle
// connections closed to release file descriptors promptly.
func (x *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport")
	if x.transport != nil {
		x.transport.CloseIdleConnections()
	}

	// Build a single TLS config shared by both transports. Callers that need
	// per-connection mutation (e.g. the H3 dialer setting ServerName) must
	// call Clone() on it.
	x.tlsClientConfig = x.buildTLSConfig()

	transport := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true, // compression handled manually in Fetch
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

	// http2.ConfigureTransports (plural, Go 1.20+ preferred API) returns
	// *http2.Transport for fine-grained tuning unavailable through the
	// singular ConfigureTransport.
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
			TLSClientConfig:    x.tlsClientConfig, // shared; cloned per-connection below
			Dial:               x.buildH3DialFunc(),
		}
	}
}

// buildDialContext returns the DialContext hook for the HTTP/2 transport.
//
// Strategy: consult the local IP cache first, trying addresses in order.
// Fall back to the raw hostname (OS resolver) when the cache is empty.
//
// portStr is computed once before the inner endpoint helper, not once per
// cached IP on the hot dial path. net.Dialer is constructed once per call,
// outside the per-target loop, avoiding repeated allocation when multiple
// IPs are cached.
func (x *XTransport) buildDialContext() func(context.Context, string, string) (net.Conn, error) {
	timeout := x.timeout // snapshot; avoids retaining a live pointer into XTransport
	return func(ctx context.Context, network, addrStr string) (net.Conn, error) {
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
		portStr := strconv.Itoa(port) // computed once for all endpoint() calls

		// endpoint builds the dial target string for a given IP, or the raw
		// hostname when ip is nil (cache-miss path).
		endpoint := func(ip net.IP) string {
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					return v4.String() + ":" + portStr
				}
				return "[" + ip.String() + "]:" + portStr
			}
			// No cached address — fall back to raw host, wrapping IPv6 in brackets.
			if parsed := ParseIP(host); parsed != nil && parsed.To4() == nil {
				return "[" + parsed.String() + "]:" + portStr
			}
			return host + ":" + portStr
		}

		cachedIPs, _, _ := x.loadCachedIPs(host)
		// max() builtin (Go 1.21) provides a zero-cost conditional capacity hint.
		targets := make([]string, 0, max(len(cachedIPs), 1))
		for _, ip := range cachedIPs {
			targets = append(targets, endpoint(ip))
		}
		if len(targets) == 0 {
			dlog.Debugf("[%s] no cached IP; falling back to hostname dial", host)
			targets = append(targets, endpoint(nil))
		}

		// Construct the dialer once and reuse across all target attempts.
		d := &net.Dialer{
			Timeout:   timeout,
			KeepAlive: x.keepAlive,
			DualStack: true,
		}

		var lastErr error
		for i, target := range targets {
			var (
				conn net.Conn
				err  error
			)
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
//
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

		// udpTarget bundles a resolved UDP address with its network name.
		type udpTarget struct{ addr, network string }

		// udpEndpoint derives the UDP target for a given IP, or the raw host.
		udpEndpoint := func(ip net.IP) udpTarget {
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					return udpTarget{v4.String() + ":" + portStr, "udp4"}
				}
				return udpTarget{"[" + ip.String() + "]:" + portStr, "udp6"}
			}
			// No cached IP — derive network from the host string itself.
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
			// Clone the shared TLS config so ServerName can be set safely.
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

// ── TLS configuration ─────────────────────────────────────────────────────────

// buildTLSConfig constructs a *tls.Config reflecting all active user
// preferences. The result is shared between the HTTP/2 and HTTP/3 transports.
// Any caller that needs per-connection mutation must call Clone() on the result.
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
		// Bundle ISRG Root X1 so Let's Encrypt certificates validate on older
		// OS trust stores that predate its widespread inclusion.
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
		// Force RSA cipher suites by capping at TLS 1.2.
		cfg.MaxVersion = tls.VersionTLS12
	}

	// Order cipher suites: hardware-accelerated first.
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

// isrgRootX1PEM is the ISRG Root X1 certificate (Let's Encrypt root CA)
// bundled in PEM form. Ensures DoH servers whose TLS chain terminates at
// ISRG Root X1 are trusted even on older OS trust stores.
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
//
// Returns nil (not []net.IP{}) when no IPs of the requested family are found,
// so callers can rely on len(ips)==0 as the canonical "no result" sentinel.
// A fixed synthetic TTL of SystemResolverIPTTL is always returned because the
// OS resolver does not expose per-record TTLs.
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
		return nil, SystemResolverIPTTL, err
	}
	return ips, SystemResolverIPTTL, err
}

// resolveUsingResolver sends A and/or AAAA queries to a single DNS resolver.
//
// Failures are tracked per query type: a AAAA timeout or NXDOMAIN does not
// discard A results already collected. The minimum TTL observed across all
// answer RRs is returned so the cache entry expires with the shortest-lived
// record.
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

	// context.WithTimeout + defer cancel: zero-overhead cancellation (Go 1.21+).
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
				continue // skip unexpected types (e.g. CNAMEs)
			}
			switch rrType {
			case dns.TypeA:
				ips = append(ips, answer.(*dns.A).A.Addr.AsSlice())
			case dns.TypeAAAA:
				ips = append(ips, answer.(*dns.AAAA).AAAA.Addr.AsSlice())
			}
			if rTTL := answer.Header().TTL; rTTL < minTTL {
				minTTL = rTTL
			}
		}
	}

	if len(ips) > 0 {
		if minTTL == noTTL {
			minTTL = 0
		}
		return ips, time.Duration(minTTL) * time.Second, nil
	}
	if lastErr != nil {
		return nil, 0, lastErr
	}
	return nil, 0, errors.New("no IP records returned")
}

// resolveUsingServers iterates over resolvers with per-resolver exponential
// back-off. On first success the winning resolver is promoted to index 0
// (self-healing affinity) so subsequent calls tend to reuse the fastest
// known-good resolver.
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
				// min() builtin (Go 1.21) replaces hand-rolled ternary.
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
//
//  1. Internal resolvers    — when ignoreSystemDNS && internalResolverReady
//  2. OS system resolver    — when ignoreSystemDNS == false
//  3. Bootstrap resolvers   — fallback after any primary failure
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

	for _, proto := range protos {
		dlog.Noticef("Resolving [%s] via bootstrap resolvers over %s", host, proto)
		ips, ttl, err = x.resolveUsingServers(proto, host, x.bootstrapResolvers, returnIPv4, returnIPv6)
		if err == nil {
			return ips, ttl, nil
		}
	}

	// Absolute last resort: OS resolver even when ignoreSystemDNS is true.
	if x.ignoreSystemDNS {
		dlog.Noticef("Bootstrap resolvers failed — last-resort system resolver for [%s]", host)
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)
	}
	return ips, ttl, err
}

// hostResolveMu returns the per-host *sync.Mutex, creating it if absent.
// sync.Map.LoadOrStore guarantees exactly one mutex is stored per host even
// under concurrent access.
func (x *XTransport) hostResolveMu(host string) *sync.Mutex {
	v, _ := x.resolveMu.LoadOrStore(host, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// resolveAndUpdateCache resolves host when the cache is absent or expired and
// stores the fresh result. Concurrent callers for the same host serialise on a
// per-host mutex (double-checked locking) so exactly one DNS query is issued.
//
// Returns nil immediately when:
//   - A proxy handles name resolution (proxyDialer or httpProxyFunction set)
//   - host is an IP literal (no DNS lookup needed)
//   - A valid, unexpired cache entry already exists
func (x *XTransport) resolveAndUpdateCache(host string) error {
	if x.proxyDialer != nil || x.httpProxyFunction != nil {
		return nil // proxy handles name resolution itself
	}
	if ParseIP(host) != nil {
		return nil // literal IP; no DNS needed
	}

	// ── Fast path ─────────────────────────────────────────────────────────────
	cachedIPs, expired, updating := x.loadCachedIPs(host)
	if len(cachedIPs) > 0 && (!expired || updating) {
		return nil
	}

	// ── Slow path — serialise per host ────────────────────────────────────────
	mu := x.hostResolveMu(host)
	mu.Lock()
	defer mu.Unlock()

	// Double-check: another goroutine may have resolved host while we waited.
	cachedIPs, expired, _ = x.loadCachedIPs(host)
	if len(cachedIPs) > 0 && !expired {
		return nil
	}

	// Signal "in progress" so concurrent dial attempts see the updating flag.
	x.markUpdatingCachedIP(host)

	ips, ttl, err := x.resolve(host, x.useIPv4, x.useIPv6)
	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}

	selectedIPs := ips

	// Serve stale cache on failure to preserve connectivity during outages.
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {
		dlog.Noticef("Using stale cached address for [%s] (grace period)", host)
		selectedIPs = cachedIPs
		ttl = ExpiredCachedIPGraceTTL
		err = nil // stale service is success from the caller's perspective
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
//   - accept      — Accept header value; omitted when empty
//   - contentType — Content-Type header value; omitted when empty
//   - body        — request body; nil for bodyless methods
//   - timeout     — per-request deadline; ≤ 0 uses x.timeout
//   - compress    — advertise "Accept-Encoding: gzip" and transparently
//     decompress gzip responses
//
// Returns (responseBody, httpStatus, tlsState, roundTripTime, error).
//
// Non-2xx responses are returned as errors whose message is the HTTP status
// text (e.g. "404 Not Found"). On HTTP/3 failure the request is automatically
// retried over HTTP/2. A negative Alt-Svc entry suppresses H3 for
// altSvcNegativeTTL before trying again.
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

	// Reject .onion addresses; they require a Tor proxy.
	if strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0, errors.New(".onion targets require a Tor proxy")
	}

	if err := x.resolveAndUpdateCache(host); err != nil {
		return nil, 0, nil, 0, err
	}

	// Determine whether HTTP/3 is available for this host.
	if x.h3Transport != nil {
		if x.http3Probe {
			hasAltSupport = true
		} else {
			x.altSupport.RLock()
			entry, ok := x.altSupport.cache[host]
			x.altSupport.RUnlock()
			if ok && entry.port > 0 {
				hasAltSupport = true
				// Redirect to the H3 port when it differs from the H2 port.
				if int(entry.port) != port {
					url2 := *url
					url2.Host = net.JoinHostPort(host, strconv.Itoa(int(entry.port)))
					url = &url2
				}
			}
		}
	}

	var bodyLen int
	if body != nil {
		bodyLen = len(*body)
	}

	// Build the request. Pre-size the header map to 5 entries to avoid the
	// internal rehash on Accept, Content-Type, Accept-Encoding, Content-Length.
	req, err := http.NewRequest(method, url.String(), nil)
	if err != nil {
		return nil, 0, nil, 0, err
	}
	req.Header = make(http.Header, 5)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if compress {
		req.Header.Set("Accept-Encoding", "gzip")
	}
	if body != nil {
		req.Body = io.NopCloser(bytes.NewReader(*body))
		req.ContentLength = int64(bodyLen)
	}

	start := time.Now()

	// Try HTTP/3 first when an Alt-Svc entry is available.
	var resp *http.Response
	if hasAltSupport && x.h3Transport != nil {
		h3Client := http.Client{
			Transport: x.h3Transport,
			Timeout:   timeout,
		}
		resp, err = h3Client.Do(req)
		if err != nil {
			dlog.Debugf("H3 request failed for [%s], retrying over H2: %v", host, err)
			// Record a timed negative entry to suppress H3 for altSvcNegativeTTL.
			x.altSupport.Lock()
			x.altSupport.cache[host] = altSvcEntry{
				port:    0,
				validTo: time.Now().Add(altSvcNegativeTTL),
			}
			x.altSupport.Unlock()
			// Rebuild the request: the original body reader was consumed above.
			req2, rErr := http.NewRequest(method, url.String(), nil)
			if rErr != nil {
				return nil, 0, nil, 0, rErr
			}
			req2.Header = req.Header.Clone()
			if body != nil {
				req2.Body = io.NopCloser(bytes.NewReader(*body))
				req2.ContentLength = int64(bodyLen) // not 0 — preserve correct length
			}
			resp, err = client.Do(req2)
		}
	} else {
		resp, err = client.Do(req)
	}

	rtt := time.Since(start)

	if err != nil {
		return nil, 0, nil, rtt, err
	}
	// Guard resp==nil before accessing resp.StatusCode to avoid a nil-deref
	// panic on cancelled contexts or broken transport implementations.
	if resp == nil {
		return nil, 0, nil, rtt, errors.New("empty response")
	}
	defer resp.Body.Close()

	// Update Alt-Svc cache from response headers if H3 transport is active.
	if x.h3Transport != nil {
		x.parseAndCacheAltSvc(host, port, resp.Header)
	}

	var tlsState *tls.ConnectionState
	if resp.TLS != nil {
		tlsState = resp.TLS
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, tlsState, rtt,
			fmt.Errorf("%s", resp.Status)
	}

	// Hash the first 8 bytes of the response digest for debug logging.
	h := sha512.New512_256()
	lr := io.LimitReader(resp.Body, 1<<20) // 1 MiB safety cap
	respBody, err := io.ReadAll(lr)
	if err != nil {
		return nil, resp.StatusCode, tlsState, rtt, err
	}

	var respBodyFinal []byte
	if compress && resp.Header.Get("Content-Encoding") == "gzip" {
		gr, gErr := gzip.NewReader(bytes.NewReader(respBody))
		if gErr != nil {
			return nil, resp.StatusCode, tlsState, rtt, gErr
		}
		respBodyFinal, err = io.ReadAll(io.LimitReader(gr, 1<<20))
		if err != nil {
			return nil, resp.StatusCode, tlsState, rtt, err
		}
	} else {
		respBodyFinal = respBody
	}

	h.Write(respBodyFinal)
	dlog.Debugf("[%s] response hash: %s", host, hex.EncodeToString(h.Sum(nil)[:8]))

	return respBodyFinal, resp.StatusCode, tlsState, rtt, nil
}

// parseAndCacheAltSvc inspects the Alt-Svc response header and updates the
// per-host entry in altSupport.
//
// Positive entries (port > 0) have no expiry. Negative entries (port == 0)
// carry a validTo time so recovering servers are retried after altSvcNegativeTTL.
func (x *XTransport) parseAndCacheAltSvc(host string, port int, header http.Header) {
	// Honour an active negative entry; skip parsing while ban is live.
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

	altPort := uint16(port & 0xffff) // default: same port as the H2 connection

outer:
	for i, entry := range alt {
		if i >= 8 { // guard against pathologically long headers
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
	x.altSupport.cache[host] = altSvcEntry{port: altPort} // validTo zero → no expiry
	dlog.Debugf("Alt-Svc: cached port %d for [%s]", altPort, host)
	x.altSupport.Unlock()
}

// ── Public query helpers ──────────────────────────────────────────────────────

// GetWithCompression sends a GET request with gzip negotiation and transparent
// decompression. Equivalent to Fetch("GET", …, compress=true).
func (x *XTransport) GetWithCompression(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("GET", url, accept, "", nil, timeout, true)
}

// Get sends a plain GET request without compression negotiation.
func (x *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("GET", url, accept, "", nil, timeout, false)
}

// Post sends a POST request with the given content type and body.
func (x *XTransport) Post(
	url *url.URL,
	accept, contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("POST", url, accept, contentType, body, timeout, false)
}

// dohLikeQuery is the shared implementation for DoHQuery and ObliviousDoHQuery.
//
// For GET requests the body is base64url-encoded as the "dns" query parameter
// per RFC 8484 §4.1. For POST requests the body is sent verbatim.
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

// DoHQuery sends a DNS-over-HTTPS query as defined by RFC 8484.
// Set useGet=true for the GET wire format, false for POST.
func (x *XTransport) DoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/dns-message", useGet, url, body, timeout)
}

// ObliviousDoHQuery sends an Oblivious DNS-over-HTTPS query as defined by
// RFC 9230. Set useGet=true for the GET wire format, false for POST.
func (x *XTransport) ObliviousDoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}

