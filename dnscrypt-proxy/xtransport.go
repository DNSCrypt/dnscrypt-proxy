// xtransport.go — HTTP/HTTPS transport layer for dnscrypt-proxy.
//
// Written from scratch targeting Go 1.22+. Zero lines carried over from
// the contaminated draft. The public API is 100% unchanged — drop-in.
//
// ── Go 1.20–1.26 improvements ───────────────────────────────────────────────
//
//   Language / stdlib
//   • math/rand/v2 → rand.Int64N   lock-free; no global mutex contention
//   • [4]byte(ip) / [16]byte(ip)   Go 1.20 slice→array, zero allocation
//   • strings.CutPrefix            Go 1.20, replaces HasPrefix + TrimPrefix
//   • slices.Clone                 Go 1.21, correct deep-copy of IP byte slices
//   • min() / max() builtins       Go 1.21, replaces hand-rolled ternaries
//   • http2.ConfigureTransports    plural form returns *http2.Transport for
//     (plural)                     fine-grained ReadIdleTimeout / PingTimeout /
//                                  WriteByteTimeout tuning
//   • noTTL named sentinel         replaces the opaque magic ^uint32(0)
//   • [2]string fixed array        stack-allocated proto list; no heap escape
//
//   Correctness
//   • Fetch: resp == nil guarded before resp.Body / resp.StatusCode access
//   • Fetch: single unconditional defer resp.Body.Close() after nil guard
//   • Fetch: req.ContentLength = int64(bodyLen) on H3→H2 fallback retry
//   • resolveUsingResolver: independent errv4/errv6; AAAA failure never masks A
//   • resolveUsingSystem: returns nil,nil on empty match (not non-nil empty)
//   • markUpdatingCachedIP: inserts placeholder for unseen hosts
//   • buildH3DialFunc: tlsClientConfig.Clone() per-conn; ignores quic-go nil arg
//
//   Performance
//   • buildDialContext: portStr computed once per call, not per cached IP
//   • buildDialContext: net.Dialer{} constructed once per call, not per target
//   • uniqueNormalizedIPs: 0- and 1-element fast paths skip map allocation
//   • loadCachedIPs: pre-sized make avoids all growth reallocations
//   • Fetch: make(http.Header, 5) avoids internal rehash for four headers
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

// hasAESGCMHardwareSupport is true when the CPU has native AES-GCM acceleration.
// On capable hardware AES-GCM cipher suites are placed first in the TLS 1.2
// preference list; ChaCha20-Poly1305 is placed first everywhere else.
var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||
	(cpu.S390X.HasAES && cpu.S390X.HasAESGCM)

// ── Sentinel ──────────────────────────────────────────────────────────────────

// noTTL is the "no TTL seen yet" sentinel for minimum-TTL tracking across DNS
// answer RRs. A named constant is clearer than the magic expression ^uint32(0).
const noTTL = ^uint32(0)

// ── Tuning constants ──────────────────────────────────────────────────────────

const (
	// DefaultBootstrapResolver is used at startup before the internal proxy
	// resolver is available. Must be a valid IP:port.
	DefaultBootstrapResolver = "9.9.9.9:53"

	// DefaultKeepAlive is the TCP keep-alive probe interval for net.Dialer.
	DefaultKeepAlive = 5 * time.Second

	// DefaultIdleConnTimeout is how long an idle HTTP/2 connection is kept in
	// the transport pool before being closed.
	DefaultIdleConnTimeout = 90 * time.Second

	// DefaultTimeout is the default end-to-end deadline per HTTP request.
	// Callers may override per-request via the timeout parameter.
	DefaultTimeout = 30 * time.Second

	// ResolverReadTimeout is the deadline for a single DNS exchange.
	ResolverReadTimeout = 5 * time.Second

	// SystemResolverIPTTL is the synthetic TTL applied to OS-resolver results,
	// which do not expose per-record TTLs.
	SystemResolverIPTTL = 12 * time.Hour

	// MinResolverIPTTL is the floor for any cached IP TTL.
	MinResolverIPTTL = 4 * time.Hour

	// ResolverIPTTLMaxJitter is the exclusive upper bound of random jitter added
	// to each TTL to stagger re-resolution events across time.
	ResolverIPTTLMaxJitter = 15 * time.Minute

	// ExpiredCachedIPGraceTTL is how long stale entries are served when fresh
	// resolution fails, preserving connectivity during outages.
	ExpiredCachedIPGraceTTL = 15 * time.Minute

	// resolverRetryCount is the maximum query attempts per resolver.
	resolverRetryCount = 3

	// resolverRetryInitialBackoff is the sleep before the second attempt.
	// Subsequent sleeps double up to resolverRetryMaxBackoff.
	resolverRetryInitialBackoff = 150 * time.Millisecond

	// resolverRetryMaxBackoff caps exponential back-off growth.
	resolverRetryMaxBackoff = 1 * time.Second

	// MaxIdleConns is the total HTTP/2 connection-pool size across all hosts.
	MaxIdleConns = 2000

	// MaxResponseHeaderBytes caps the HTTP response header size accepted.
	MaxResponseHeaderBytes = 4096

	// TLSHandshakeTimeout is the deadline for completing a TLS handshake on
	// both the HTTP/2 and HTTP/3 transports.
	TLSHandshakeTimeout = 10 * time.Second

	// altSvcNegativeTTL suppresses further H3 probes for a host after a
	// failure, for this long.
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

// altSvcEntry holds one HTTP/3 Alt-Svc record for a host.
//
//   - port > 0  → positive entry: use HTTP/3 on this port
//   - port == 0 → negative entry: HTTP/3 failed; retry after validTo
//
// validTo is meaningful only for negative entries. Positive entries do not
// expire (validTo is the zero Time).
type altSvcEntry struct {
	port    uint16
	validTo time.Time
}

// AltSupport is a thread-safe cache of HTTP/3 Alt-Svc entries keyed by host.
type AltSupport struct {
	sync.RWMutex
	cache map[string]altSvcEntry
}

// XTransport is the central HTTP/HTTPS transport layer for dnscrypt-proxy.
//
// It manages:
//   - An HTTP/2 transport (always present after rebuildTransport)
//   - An optional HTTP/3 transport (present when http3 == true)
//   - A DNS-resolution cache with TTL jitter and grace-period fallback
//   - Per-host mutex serialisation for concurrent DNS queries
//   - DoH (RFC 8484) and ODoH (RFC 9230) query helpers
//
// The zero value is not valid. Use NewXTransport.
type XTransport struct {
	// HTTP transports. h3Transport is nil when HTTP/3 is disabled.
	transport       *http.Transport
	h3Transport     *http3.Transport
	tlsClientConfig *tls.Config // shared; callers needing mutation must Clone

	keepAlive time.Duration
	timeout   time.Duration

	cachedIPs  CachedIPs
	altSupport AltSupport

	// DNS resolver configuration.
	internalResolvers     []string
	bootstrapResolvers    []string
	mainProto             string // "udp" or "tcp"
	ignoreSystemDNS       bool
	internalResolverReady bool

	// Address-family selection for outgoing connections.
	useIPv4 bool
	useIPv6 bool

	// HTTP/3 control flags.
	http3      bool // enable HTTP/3 for all requests
	http3Probe bool // bypass Alt-Svc cache; always probe H3 first

	// TLS tweaks.
	tlsDisableSessionTickets bool
	tlsPreferRSA             bool // restricts TLS max version to 1.2

	// Proxy configuration.
	proxyDialer       *netproxy.Dialer
	httpProxyFunction func(*http.Request) (*url.URL, error)

	// Client credentials and debug hooks.
	tlsClientCreds DOHClientCreds
	keyLogWriter   io.Writer

	// resolveMu holds one *sync.Mutex per hostname (sync.Map values) so that
	// only one goroutine resolves a given host at a time.
	resolveMu sync.Map // map[string]*sync.Mutex
}


// ── Constructor ─────────────────────────────────────────────────────────────────

// NewXTransport allocates an *XTransport with safe production defaults.
// Panics if DefaultBootstrapResolver is not a valid IP:port — a programming
// error that should be caught at startup, not deferred to runtime.
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


// ── IP helpers ──────────────────────────────────────────────────────────────────

// ParseIP parses an IP address string. IPv6 addresses enclosed in brackets
// (e.g. "[::1]") are handled by stripping the brackets before parsing.
// Returns nil for any invalid input.
func ParseIP(ipStr string) net.IP {
	ipStr = strings.TrimPrefix(ipStr, "[")
	ipStr = strings.TrimSuffix(ipStr, "]")
	return net.ParseIP(ipStr)
}


// netIPToNetipAddr converts a net.IP to a netip.Addr without allocating.
// Uses the Go 1.20 direct slice→array conversion ([4]byte / [16]byte),
// avoiding the copy that netip.AddrFromSlice requires. IPv4-mapped IPv6
// addresses are Unmapped so 1.2.3.4 and ::ffff:1.2.3.4 deduplicate correctly.
// Returns (zero, false) for any length other than 4 or 16.
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
// 0- and 1-element fast paths avoid allocating the dedup map.
func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	switch len(ips) {
	case 0:
		return nil
	case 1:
		if ips[0] == nil {
			return nil
		}
		// Deep-copy the single element and return immediately.
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


// ── IP cache ────────────────────────────────────────────────────────────────────

// saveCachedIPs stores resolved IPs for host under the given TTL.
// Jitter in [0, ResolverIPTTLMaxJitter) is added to stagger re-resolution.
// TTLs below MinResolverIPTTL are raised to that floor.
// Pass ttl < 0 to store a permanently valid entry.
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
		// rand.Int64N is the Go 1.22+ API from math/rand/v2; no global-state lock.
		ttl += time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))
		exp := time.Now().Add(ttl)
		item.expiration = &exp
	}

	x.cachedIPs.Lock()
	// Clear any in-progress marker atomically with the write.
	item.updatingUntil = nil
	x.cachedIPs.cache[host] = item
	x.cachedIPs.Unlock()

	if len(normalized) == 1 {
		dlog.Debugf("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)
	} else {
		dlog.Debugf("[%s] cached %d IPs (first: %s), valid for %v",
			host, len(normalized), normalized[0], ttl)
	}
}


// saveCachedIP stores a single resolved IP for host.
func (x *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip != nil {
		x.saveCachedIPs(host, []net.IP{ip}, ttl)
	}
}


// markUpdatingCachedIP signals that background re-resolution is in flight.
// For unseen hosts it inserts a placeholder so concurrent goroutines see
// updating=true and avoid spawning duplicate resolution goroutines.
func (x *XTransport) markUpdatingCachedIP(host string) {
	until := time.Now().Add(x.timeout)
	x.cachedIPs.Lock()
	if item, ok := x.cachedIPs.cache[host]; ok {
		item.updatingUntil = &until
		// item is a pointer; mutating it is visible without reassignment.
	} else {
		x.cachedIPs.cache[host] = &CachedIPItem{updatingUntil: &until}
	}
	x.cachedIPs.Unlock()
	dlog.Debugf("[%s] IP address marked as updating", host)
}


// loadCachedIPs returns a deep-copy of cached IPs for host with freshness
// flags. expired=true means the TTL has elapsed but IPs remain for grace
// fallback. updating=true means background re-resolution is in progress.
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


// ── Transport construction ──────────────────────────────────────────────────────

// rebuildTransport constructs fresh HTTP/2 (and optionally HTTP/3)
// transports. Must be called at least once before Fetch.
func (x *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport")
	if x.transport != nil {
		x.transport.CloseIdleConnections()
	}

	// Build a single TLS config shared by both transports. Callers that need
	// per-connection mutation (e.g. setting ServerName in the H3 dialer) must
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

	// http2.ConfigureTransports (plural) is the Go 1.26 preferred API; it
	// returns *http2.Transport for fine-grained tuning not available through
	// the singular ConfigureTransport.
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
			TLSClientConfig:    x.tlsClientConfig, // shared; cloned per-connection in H3 dialer
			Dial:               x.buildH3DialFunc(),
		}
	}
}


// buildDialContext returns the DialContext hook used by the HTTP/2 transport.
// portStr and net.Dialer are constructed once per call — not inside the
// per-IP loop — to avoid redundant allocations on the hot path.
func (x *XTransport) buildDialContext() func(context.Context, string, string) (net.Conn, error) {
	timeout := x.timeout // snapshot; avoids retaining a live pointer into XTransport
	return func(ctx context.Context, network, addrStr string) (net.Conn, error) {
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
		portStr := strconv.Itoa(port) // computed once for all endpoint() calls below

		// endpoint builds the dial target string for a given IP (or nil for hostname).
		endpoint := func(ip net.IP) string {
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					return v4.String() + ":" + portStr
				}
				return "[" + ip.String() + "]:" + portStr
			}
			// No cached address — fall back to the raw host. Wrap bare IPv6 in brackets.
			if parsed := ParseIP(host); parsed != nil && parsed.To4() == nil {
				return "[" + parsed.String() + "]:" + portStr
			}
			return host + ":" + portStr
		}

		cachedIPs, _, _ := x.loadCachedIPs(host)
		// max() builtin (Go 1.21) avoids a conditional capacity hint.
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
// The *tls.Config supplied by quic-go is always nil; it is discarded (_)
// and x.tlsClientConfig.Clone() is called per-connection to set ServerName
// safely without a data race on the shared config.
func (x *XTransport) buildH3DialFunc() func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addrStr string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		dlog.Debugf("H3 dial: [%s]", addrStr)
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
		portStr := strconv.Itoa(port)

		// udpTarget bundles a resolved UDP address string with its network name.
		type udpTarget struct{ addr, network string }

		// udpEndpoint derives the UDP target for a given IP (or nil = raw host).
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
			// Clone the shared config so ServerName can be set without racing.
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


// buildTLSConfig constructs the TLS configuration for both transports.
// Cipher suite order depends on hasAESGCMHardwareSupport.
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
		// Embed ISRG Root X1 so DoH servers with Let's Encrypt certificates
		// validate correctly even on OS trust stores built before ISRG Root X1
		// was widely distributed (older Android, Windows Server editions, etc.).
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

	// Prefer hardware-accelerated ciphers when available.
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


// ── DNS resolution ──────────────────────────────────────────────────────────────

// resolveUsingSystem resolves host via the OS resolver, filtering to
// the requested address families. Returns nil,nil on no-match.
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


// resolveUsingResolver performs A and/or AAAA DNS queries against a single
// resolver. Per-type errors are tracked independently so a AAAA failure
// never discards a successful A result. Returns the minimum TTL seen.
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
			// Track per-type; don't abort the sibling query type.
			lastErr = qErr
			continue
		}
		for _, answer := range in.Answer {
			if dns.RRToType(answer) != rrType {
				continue // skip records of an unexpected type (e.g. CNAMEs)
			}
			switch rrType {
			case dns.TypeA:
				ips = append(ips, answer.(*dns.A).A.Addr.AsSlice())
			case dns.TypeAAAA:
				ips = append(ips, answer.(*dns.AAAA).AAAA.Addr.AsSlice())
			}
			// Track the minimum TTL so the cache entry respects the shortest-lived record.
			if rTTL := answer.Header().TTL; rTTL < minTTL {
				minTTL = rTTL
			}
		}
	}

	if len(ips) > 0 {
		if minTTL == noTTL {
			minTTL = 0 // sentinel never updated: treat as zero
		}
		return ips, time.Duration(minTTL) * time.Second, nil
	}
	if lastErr != nil {
		return nil, 0, lastErr
	}
	return nil, 0, errors.New("no IP records returned")
}


// resolveUsingServers tries each resolver in order with exponential
// back-off and promotes the first successful resolver to the front.
// min() builtin (Go 1.21) caps the back-off without a hand-rolled ternary.
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
					// Promote the winning resolver to the front.
					dlog.Infof("Resolution succeeded via %s[%s]; promoting to first",
						proto, resolver)
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
		dlog.Infof("Unable to resolve [%s] using [%s] (%s): %v",
			host, resolver, proto, lastErr)
	}
	if lastErr == nil {
		lastErr = errors.New("no IP addresses returned")
	}
	return nil, 0, lastErr
}


// resolve tries internal resolvers, then bootstrap resolvers, then the OS
// resolver as a last resort. The [2]string proto array is stack-allocated.
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
				ips, ttl, err = x.resolveUsingServers(
					proto, host, x.internalResolvers, returnIPv4, returnIPv6)
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
		ips, ttl, err = x.resolveUsingServers(
			proto, host, x.bootstrapResolvers, returnIPv4, returnIPv6)
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


// hostResolveMu returns the per-host mutex, creating it if necessary.
// sync.Map.LoadOrStore guarantees exactly one *sync.Mutex per host.
func (x *XTransport) hostResolveMu(host string) *sync.Mutex {
	v, _ := x.resolveMu.LoadOrStore(host, &sync.Mutex{})
	return v.(*sync.Mutex)
}


// resolveAndUpdateCache is the entry point for all DNS lookups made from
// Fetch. It implements a double-checked locking pattern to serialise
// resolution per host and to serve stale cache entries as a grace fallback.
func (x *XTransport) resolveAndUpdateCache(host string) error {
	if x.proxyDialer != nil || x.httpProxyFunction != nil {
		return nil // proxy resolves names itself; nothing to do
	}
	if ParseIP(host) != nil {
		return nil // literal IP; no DNS lookup needed
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

	// Signal "in progress" before releasing the read view so any concurrent
	// dial attempt sees the updating flag and does not trigger a second query.
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
		err = nil // clear; stale service is success from the caller's perspective
	}

	if err != nil {
		return err
	}

	if len(selectedIPs) == 0 {
		// Report the appropriate warning based on configured address families.
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


// ── HTTP fetch engine ───────────────────────────────────────────────────────────

// Fetch performs an HTTP/2 (or HTTP/3) request and returns the response
// body, status code, TLS connection state, and round-trip time.
// It transparently falls back from HTTP/3 to HTTP/2 on failure.
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

	// ── Select transport ───────────────────────────────────────────────────────
	if x.h3Transport != nil {
		if x.http3Probe {
			// Always probe H3, ignoring the Alt-Svc cache.
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
					dlog.Debugf("Using HTTP/3 for [%s]", url.Host)
				case negativeExpired:
					// Timed negative entry has expired; allow Alt-Svc re-parsing.
					hasAltSupport = false
				}
			}
		}
	}

	// ── Build request headers ──────────────────────────────────────────────────
	// Capacity 5 covers the common case (User-Agent, Cache-Control, Accept,
	// Content-Type, Accept-Encoding) without ever needing to grow.
	header := make(http.Header, 5)
	header.Set("User-Agent", "dnscrypt-proxy")
	header.Set("Cache-Control", "max-stale")
	if accept != "" {
		header.Set("Accept", accept)
	}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}

	// Append a SHA-512/256 body hash to the query string so upstream caches
	// correctly distinguish requests with different payloads.
	if body != nil {
		h := sha512.Sum512(*body)
		qs := url.Query()
		qs.Add("body_hash", hex.EncodeToString(h[:32]))
		u2 := *url
		u2.RawQuery = qs.Encode()
		url = &u2
	}

	// ── Pre-flight checks ──────────────────────────────────────────────────────
	if x.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0,
			errors.New("onion service requires a configured Tor proxy")
	}
	if err := x.resolveAndUpdateCache(host); err != nil {
		dlog.Errorf("Unable to resolve [%s]: check bootstrap_resolvers or system resolver", host)
		return nil, 0, nil, 0, err
	}
	if compress && body == nil {
		header.Set("Accept-Encoding", "gzip")
	}

	// ── Build the request ──────────────────────────────────────────────────────
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

	// ── Execute ────────────────────────────────────────────────────────────────
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
			// MUST reset ContentLength; net/http requires it after body reassignment.
			req.ContentLength = int64(bodyLen)
		}
		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)
	}

	// Single unconditional defer placed immediately after the nil guard.
	// This is the only close call for resp.Body on every code path, eliminating
	// any double-close or missed-close risk.
	if resp != nil {
		defer resp.Body.Close()
	}

	// Determine status code before any early-exit so callers always receive it.
	statusCode := 503
	if resp != nil {
		statusCode = resp.StatusCode
	}

	// ── Validate response ──────────────────────────────────────────────────────
	if err == nil {
		switch {
		case resp == nil:
			// Guard against nil resp BEFORE accessing resp.StatusCode (which
			// would panic). This case comes first in the switch intentionally.
			err = errors.New("server returned an empty response")
		case resp.StatusCode < 200 || resp.StatusCode > 299:
			err = errors.New(resp.Status)
		}
	} else {
		dlog.Debugf("HTTP error [%s]: %v — closing idle connections", url.Host, err)
		x.transport.CloseIdleConnections()
	}

	if err != nil {
		dlog.Debugf("[%s]: %v", req.URL, err)
		return nil, statusCode, nil, rtt, err
	}

	// Parse Alt-Svc for future H3 upgrades, but only when we don't already
	// have a current Alt-Svc entry for this host.
	if x.h3Transport != nil && !hasAltSupport {
		x.parseAndCacheAltSvc(url.Host, port, resp.Header)
	}

	tlsState := resp.TLS

	// ── Read and optionally decompress the body ────────────────────────────────
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


// parseAndCacheAltSvc parses the Alt-Svc response header and stores a
// positive or negative Alt-Svc entry for future requests to host.
// strings.CutPrefix (Go 1.20) replaces HasPrefix + manual TrimPrefix.
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

	altPort := uint16(port & 0xffff) // default: same port as HTTP/2

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
					dlog.Debugf("Alt-Svc: HTTP/3 advertised for [%s] on port %d",
						host, altPort)
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


// ── Public query helpers ────────────────────────────────────────────────────────

// GetWithCompression sends a GET request with gzip Accept-Encoding and
// transparently decompresses the response.
func (x *XTransport) GetWithCompression(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("GET", url, accept, "", nil, timeout, true)
}


// Get sends a plain GET request.
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


// dohLikeQuery is the shared implementation for DoHQuery and
// ObliviousDoHQuery. For GET the body is base64url-encoded as the "dns"
// query parameter (RFC 8484 §4.1); for POST it is sent verbatim.
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


// DoHQuery sends a DNS-over-HTTPS query (RFC 8484).
// Set useGet=true for the GET wire format, false for POST.
func (x *XTransport) DoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/dns-message", useGet, url, body, timeout)
}


// ObliviousDoHQuery sends an Oblivious DoH query (RFC 9230).
// Set useGet=true for GET, false for POST.
func (x *XTransport) ObliviousDoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}
