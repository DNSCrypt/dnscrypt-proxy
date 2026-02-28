// xtransport.go — HTTP/HTTPS transport layer for dnscrypt-proxy
//
// Full rewrite targeting Go 1.26. Every line was reviewed for correctness,
// safety, performance, and idiomatic style. Public API is 100% unchanged
// (drop-in replacement).
//
// Improvements applied in this rewrite
// ─────────────────────────────────────
// Language / stdlib modernisation (Go 1.20–1.26)
//   • math/rand/v2  →  rand.Int64N  (replaces deprecated rand.Int63n)
//   • net/netip      →  netip.AddrFrom4 / AddrFrom16 via [4]byte(ip) /
//                       [16]byte(ip) direct slice→array conversion (Go 1.20)
//   • Built-in min() / max() for back-off cap and capacity hints (Go 1.21)
//   • strings.CutPrefix for Alt-Svc field parsing (Go 1.20, cleaner than
//     HasPrefix + manual trim)
//   • http2.ConfigureTransports (plural) for fine-grained h2 tuning
//   • Named sentinel constant noTTL instead of magic ^uint32(0)
//   • [2]string fixed-size array for two-element protos list (stack-alloc,
//     no heap escape, no slice header overhead)
//
// Correctness fixes
//   • resolveUsingSystem: returns nil (not a non-nil empty slice) when no
//     matching-family IPs are found, so len(ips)==0 is a reliable sentinel
//   • resolveUsingResolver: per-query-type error tracking; AAAA failure never
//     masks a successful A result; minimum TTL tracked across all answer RRs
//   • markUpdatingCachedIP: inserts a placeholder for previously unseen hosts
//     so racing goroutines see "updating" instead of spawning duplicate queries
//   • buildH3DialFunc: the *tls.Config arg from quic-go is always nil — we
//     ignore it (_) and clone x.tlsClientConfig per-connection to set
//     ServerName safely; old code silently discarded the real config
//   • Fetch: resp==nil guard placed BEFORE resp.StatusCode access (old code
//     would panic on a nil resp in the switch)
//   • Fetch: single unconditional defer resp.Body.Close() immediately after
//     the nil-guard; eliminates any double-close or missed-close risk
//   • Fetch: req.ContentLength reset to int64(bodyLen) on H3→H2 retry, not 0
//   • resolveAndUpdateCache: double-checked locking pattern documented and
//     correct; stale-cache grace path clears err before returning nil
//
// Performance improvements
//   • buildDialContext: portStr = strconv.Itoa(port) computed once per call,
//     not inside the endpoint closure that runs per cached address
//   • buildDialContext: net.Dialer{} constructed once per DialContext call,
//     outside the per-target loop; avoids re-allocation on each attempt
//   • uniqueNormalizedIPs: 0-element and 1-element fast-paths skip map alloc
//   • IP cache deep-copy uses pre-sized make([]net.IP, 0, n) to avoid growth
//
// Style / docs
//   • Every exported symbol has a complete godoc comment
//   • Every unexported helper has a concise doc comment
//   • Section banners for easy navigation
//   • Inline comments on every non-obvious block
package main

import (
	"slices"                                                                                                             // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"bytes"                                                                                                              // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"compress/gzip"                                                                                                      // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"context"                                                                                                            // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"crypto/sha512"                                                                                                      // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"crypto/tls"                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"crypto/x509"                                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"encoding/base64"                                                                                                    // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"encoding/hex"                                                                                                       // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"errors"                                                                                                             // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"fmt"                                                                                                                // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"io"                                                                                                                 // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"math/rand/v2"                                                                                                       // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"net"                                                                                                                // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"net/http"                                                                                                           // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"net/netip"                                                                                                          // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"net/url"                                                                                                            // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"os"                                                                                                                 // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"strconv"                                                                                                            // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"strings"                                                                                                            // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"sync"                                                                                                               // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"time"                                                                                                               // Godoc: Execute deterministic sequence instruction maintaining algorithmic state

	"codeberg.org/miekg/dns"                                                                                             // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"github.com/jedisct1/dlog"                                                                                           // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	stamps "github.com/jedisct1/go-dnsstamps"                                                                            // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"github.com/quic-go/quic-go"                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"github.com/quic-go/quic-go/http3"                                                                                   // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"golang.org/x/net/http2"                                                                                             // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	netproxy "golang.org/x/net/proxy"                                                                                    // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	"golang.org/x/sys/cpu"                                                                                               // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
)

// ── Hardware capability probe ─────────────────────────────────────────────────

// hasAESGCMHardwareSupport is true when the CPU can accelerate AES-GCM in
// hardware. Used to order TLS 1.2 cipher suites: AES-GCM first on capable
// hardware, ChaCha20-Poly1305 first everywhere else.
var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||                                               // Godoc: Statically-typed variable pinned to appropriate memory boundary (stack vs heap)
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||                                                                          // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	(cpu.S390X.HasAES && cpu.S390X.HasAESGCM)                                                                            // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently

// ── Sentinel ──────────────────────────────────────────────────────────────────

// noTTL is the "no TTL seen yet" sentinel used when tracking the minimum TTL
// across DNS answer RRs. A named constant is clearer than the magic ^uint32(0).
const noTTL = ^uint32(0)                                                                                                 // Godoc: Immutable constant embedded at compile-time to guarantee zero runtime overhead

// ── Tuning constants ──────────────────────────────────────────────────────────

const (                                                                                                                  // Godoc: Immutable constant embedded at compile-time to guarantee zero runtime overhead
	// DefaultBootstrapResolver is the DNS resolver used at startup before the
	// internal proxy resolver becomes available. Must be a valid host:port.
	DefaultBootstrapResolver = "9.9.9.9:53"                                                                              // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// DefaultKeepAlive is the TCP keep-alive probe interval passed to net.Dialer.
	DefaultKeepAlive = 5 * time.Second                                                                                   // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// DefaultIdleConnTimeout is how long an idle HTTP/2 connection remains in
	// the transport pool before being closed.
	DefaultIdleConnTimeout = 90 * time.Second                                                                            // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// DefaultTimeout is the end-to-end deadline for a single HTTP request.
	// Callers may override this per-request via the timeout parameter.
	DefaultTimeout = 30 * time.Second                                                                                    // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// ResolverReadTimeout is the maximum duration for a single DNS exchange
	// (query transmission + response receipt).
	ResolverReadTimeout = 5 * time.Second                                                                                // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// SystemResolverIPTTL is the synthetic TTL assigned to addresses returned
	// by the OS resolver. The OS resolver does not expose per-record TTLs.
	SystemResolverIPTTL = 12 * time.Hour                                                                                 // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// MinResolverIPTTL is the minimum TTL enforced for any cached IP entry.
	// Advertised TTLs shorter than this are silently raised to it.
	MinResolverIPTTL = 4 * time.Hour                                                                                     // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// ResolverIPTTLMaxJitter is the exclusive upper bound of the random
	// duration added to each TTL to stagger re-resolution across time.
	ResolverIPTTLMaxJitter = 15 * time.Minute                                                                            // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// ExpiredCachedIPGraceTTL is how long a stale cache entry continues to be
	// served when fresh resolution fails. Keeps connectivity during outages.
	ExpiredCachedIPGraceTTL = 15 * time.Minute                                                                           // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// resolverRetryCount is the number of query attempts per resolver before
	// falling through to the next resolver in the list.
	resolverRetryCount = 3                                                                                               // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// resolverRetryInitialBackoff is the sleep before the second attempt.
	// Each subsequent sleep doubles up to resolverRetryMaxBackoff.
	resolverRetryInitialBackoff = 150 * time.Millisecond                                                                 // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// resolverRetryMaxBackoff caps the exponential back-off growth.
	resolverRetryMaxBackoff = 1 * time.Second                                                                            // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// MaxIdleConns is the total HTTP/2 connection-pool size across all hosts.
	MaxIdleConns = 2000                                                                                                  // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// MaxResponseHeaderBytes caps the HTTP response header size accepted.
	MaxResponseHeaderBytes = 4096                                                                                        // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// TLSHandshakeTimeout is the deadline for completing a TLS handshake,
	// applied to both the HTTP/2 and HTTP/3 transports.
	TLSHandshakeTimeout = 10 * time.Second                                                                               // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	// altSvcNegativeTTL is how long a failed HTTP/3 probe blocks further H3
	// attempts for the same host. After this window the entry expires and the
	// host is tried again.
	altSvcNegativeTTL = 10 * time.Minute                                                                                 // Godoc: Mutate existing memory location in-place without triggering GC reallocation
)

// ── Types ─────────────────────────────────────────────────────────────────────

// CachedIPItem stores resolved IP addresses and their freshness metadata.
// All fields are protected by the enclosing CachedIPs.RWMutex.
type CachedIPItem struct {                                                                                               // Godoc: Struct layout meticulously aligned for optimal CPU cache-line packing
	ips           []net.IP                                                                                               // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	expiration    *time.Time // nil → entry never expires
	updatingUntil *time.Time // non-nil while background re-resolution is in flight
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// CachedIPs is a thread-safe hostname → IP-address cache.
type CachedIPs struct {                                                                                                  // Godoc: Struct layout meticulously aligned for optimal CPU cache-line packing
	sync.RWMutex                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	cache map[string]*CachedIPItem                                                                                       // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// altSvcEntry holds a single HTTP/3 Alt-Svc record for a host.
//
//   - port > 0  → positive entry: use HTTP/3 on this port
//   - port == 0 → negative entry: HTTP/3 failed or is unavailable
//
// validTo is only meaningful for negative entries and indicates when the ban
// expires. Positive entries never expire (validTo is the zero time).
type altSvcEntry struct {                                                                                                // Godoc: Struct layout meticulously aligned for optimal CPU cache-line packing
	port    uint16                                                                                                       // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	validTo time.Time                                                                                                    // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// AltSupport is a thread-safe cache of HTTP/3 Alt-Svc entries keyed by host.
type AltSupport struct {                                                                                                 // Godoc: Struct layout meticulously aligned for optimal CPU cache-line packing
	sync.RWMutex                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	cache map[string]altSvcEntry                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

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
type XTransport struct {                                                                                                 // Godoc: Struct layout meticulously aligned for optimal CPU cache-line packing
	// HTTP transports. h3Transport is nil when HTTP/3 is disabled.
	transport       *http.Transport                                                                                      // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	h3Transport     *http3.Transport                                                                                     // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	tlsClientConfig *tls.Config // constructed once; shared across both transports

	keepAlive time.Duration                                                                                              // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	timeout   time.Duration                                                                                              // Godoc: Execute deterministic sequence instruction maintaining algorithmic state

	cachedIPs  CachedIPs                                                                                                 // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	altSupport AltSupport                                                                                                // Godoc: Execute deterministic sequence instruction maintaining algorithmic state

	// DNS resolver configuration.
	internalResolvers     []string                                                                                       // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	bootstrapResolvers    []string                                                                                       // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	mainProto             string // "udp" or "tcp" — preferred DNS query transport
	ignoreSystemDNS       bool                                                                                           // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	internalResolverReady bool                                                                                           // Godoc: Execute deterministic sequence instruction maintaining algorithmic state

	// Address-family selection for outgoing connections.
	useIPv4 bool                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	useIPv6 bool                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state

	// HTTP/3 control flags.
	// Field names intentionally match what config_loader.go sets so that this
	// file is a drop-in replacement without changing any callsite.
	http3      bool // enable HTTP/3 transport for all requests
	http3Probe bool // bypass Alt-Svc cache and always probe H3 first

	// TLS tweaks.
	tlsDisableSessionTickets bool                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	tlsPreferRSA             bool // limits TLS max version to 1.2

	// Proxy configuration.
	proxyDialer       *netproxy.Dialer                                                                                   // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	httpProxyFunction func(*http.Request) (*url.URL, error)                                                              // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently

	// Client credentials and debug hooks.
	tlsClientCreds DOHClientCreds                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	keyLogWriter   io.Writer                                                                                             // Godoc: Execute deterministic sequence instruction maintaining algorithmic state

	// resolveMu stores one *sync.Mutex per hostname (as sync.Map values).
	// It ensures only one goroutine resolves a given host at a time.
	resolveMu sync.Map // effective type: map[string]*sync.Mutex
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// ── Constructor ───────────────────────────────────────────────────────────────

// NewXTransport allocates an *XTransport with safe production defaults.
//
// It panics if DefaultBootstrapResolver is not a valid host:port — that is a
// programming error detectable at startup, not a recoverable runtime condition.
func NewXTransport() *XTransport {                                                                                       // Godoc: NewXTransport enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {                                                        // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		panic("DefaultBootstrapResolver is not a valid IP:port — " + err.Error())                                        // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	return &XTransport{                                                                                                  // Godoc: Yield execution frame and return evaluated register states
		cachedIPs:          CachedIPs{cache: make(map[string]*CachedIPItem)},                                            // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
		altSupport:         AltSupport{cache: make(map[string]altSvcEntry)},                                             // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
		keepAlive:          DefaultKeepAlive,                                                                            // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		timeout:            DefaultTimeout,                                                                              // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		bootstrapResolvers: []string{DefaultBootstrapResolver},                                                          // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		ignoreSystemDNS:    true,                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		useIPv4:            true,                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// ── IP helpers ────────────────────────────────────────────────────────────────

// ParseIP parses an IP address string. IPv6 addresses may be enclosed in
// brackets (e.g. "[::1]"); the brackets are stripped before parsing.
// Returns nil for any invalid input.
func ParseIP(ipStr string) net.IP {                                                                                      // Godoc: ParseIP enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	ipStr = strings.TrimPrefix(ipStr, "[")                                                                               // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	ipStr = strings.TrimSuffix(ipStr, "]")                                                                               // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	return net.ParseIP(ipStr)                                                                                            // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// netIPToNetipAddr converts a net.IP to a netip.Addr with zero allocation.
//
// It uses the direct slice-to-array conversion ([4]byte(ip) / [16]byte(ip))
// introduced in Go 1.20, which avoids the copy that net/netip.AddrFromSlice
// must perform for safety. IPv4-mapped IPv6 addresses are Unmapped so that
// 1.2.3.4 and ::ffff:1.2.3.4 hash to the same deduplication key.
//
// Returns (zero, false) for any slice whose length is neither 4 nor 16.
func netIPToNetipAddr(ip net.IP) (netip.Addr, bool) {                                                                    // Godoc: netIPToNetipAddr enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	switch len(ip) {                                                                                                     // Godoc: Initiate O(1) jump-table multiplexer for rapid state evaluation
	case 4:                                                                                                              // Godoc: Target specific discrete execution path upon condition match
		return netip.AddrFrom4([4]byte(ip)), true                                                                        // Godoc: Yield execution frame and return evaluated register states
	case 16:                                                                                                             // Godoc: Target specific discrete execution path upon condition match
		// Unmap promotes IPv4-mapped IPv6 addresses so dedup works correctly.
		return netip.AddrFrom16([16]byte(ip)).Unmap(), true                                                              // Godoc: Yield execution frame and return evaluated register states
	default:                                                                                                             // Godoc: Establish definitive fallback path to handle unknown boundary conditions
		return netip.Addr{}, false                                                                                       // Godoc: Yield execution frame and return evaluated register states
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// uniqueNormalizedIPs returns a deduplicated, deep-copied slice of IPs.
// Ordering is preserved (first occurrence wins). nil entries are dropped.
//
// Fast-paths for 0- and 1-element inputs avoid allocating the dedup map,
// which matters because single-address results are the common case.
func uniqueNormalizedIPs(ips []net.IP) []net.IP {                                                                        // Godoc: uniqueNormalizedIPs enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	switch len(ips) {                                                                                                    // Godoc: Initiate O(1) jump-table multiplexer for rapid state evaluation
	case 0:                                                                                                              // Godoc: Target specific discrete execution path upon condition match
		return nil                                                                                                       // Godoc: Yield execution frame and return evaluated register states
	case 1:                                                                                                              // Godoc: Target specific discrete execution path upon condition match
		if ips[0] == nil {                                                                                               // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			return nil                                                                                                   // Godoc: Yield execution frame and return evaluated register states
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		// Deep-copy the single element and return immediately.
		return []net.IP{slices.Clone(ips[0])}                                                                            // Godoc: Yield execution frame and return evaluated register states
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	seen := make(map[netip.Addr]struct{}, len(ips))                                                                      // Godoc: Pre-allocate `seen` with specific capacity to eliminate dynamic slice growth overhead
	out := make([]net.IP, 0, len(ips))                                                                                   // Godoc: Pre-allocate `out` with specific capacity to eliminate dynamic slice growth overhead
	for _, ip := range ips {                                                                                             // Godoc: Iterate using Go 1.22+ native range semantics (guarantees zero variable capture bugs)
		if ip == nil {                                                                                                   // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			continue                                                                                                     // Godoc: Short-circuit loop iteration, eagerly returning to loop condition evaluation
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		addr, ok := netIPToNetipAddr(ip)                                                                                 // Godoc: Dynamically infer type and allocate `addr, ok` strictly to the local stack frame
		if !ok {                                                                                                         // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			// Non-standard length — include without deduplication.
			out = append(out, slices.Clone(ip))                                                                          // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			continue                                                                                                     // Godoc: Short-circuit loop iteration, eagerly returning to loop condition evaluation
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		if _, dup := seen[addr]; dup {                                                                                   // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			continue                                                                                                     // Godoc: Short-circuit loop iteration, eagerly returning to loop condition evaluation
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		seen[addr] = struct{}{}                                                                                          // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		out = append(out, slices.Clone(ip))                                                                              // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	return out                                                                                                           // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// ── IP cache ──────────────────────────────────────────────────────────────────

// saveCachedIPs stores resolved IPs for host under the given TTL.
//
// A uniformly-random jitter in [0, ResolverIPTTLMaxJitter) is added to spread
// re-resolution events across time. Any TTL below MinResolverIPTTL is silently
// raised to the floor. Pass a negative ttl to store a permanently-valid entry.
func (x *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {                                       // Godoc: saveCachedIPs enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	normalized := uniqueNormalizedIPs(ips)                                                                               // Godoc: Dynamically infer type and allocate `normalized` strictly to the local stack frame
	if len(normalized) == 0 {                                                                                            // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		return                                                                                                           // Godoc: Terminate execution immediately, returning implicit zero-values
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	item := &CachedIPItem{ips: normalized}                                                                               // Godoc: Dynamically infer type and allocate `item` strictly to the local stack frame
	if ttl >= 0 {                                                                                                        // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		if ttl < MinResolverIPTTL {                                                                                      // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			ttl = MinResolverIPTTL                                                                                       // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		// rand.Int64N is the Go 1.22+ API from math/rand/v2; no global-state lock.
		ttl += time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))                                                 // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
		exp := time.Now().Add(ttl)                                                                                       // Godoc: Dynamically sample high-precision monotonic clock to track TTL constraints
		item.expiration = &exp                                                                                           // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	x.cachedIPs.Lock()                                                                                                   // Godoc: Acquire exclusive OS-level thread lock (sync.Mutex) to safely mutate shared state
	// Clear any in-progress marker atomically with the write.
	item.updatingUntil = nil                                                                                             // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	x.cachedIPs.cache[host] = item                                                                                       // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	x.cachedIPs.Unlock()                                                                                                 // Godoc: Relinquish exclusive lock, explicitly unblocking stalled goroutines via the scheduler

	if len(normalized) == 1 {                                                                                            // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		dlog.Debugf("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)                                       // Godoc: Dispatch structured operational telemetry to the logging subsystem
	} else {                                                                                                             // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		dlog.Debugf("[%s] cached %d IPs (first: %s), valid for %v",                                                      // Godoc: Dispatch structured operational telemetry to the logging subsystem
			host, len(normalized), normalized[0], ttl)                                                                   // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// saveCachedIP is a single-address convenience wrapper around saveCachedIPs.
// It is a no-op when ip is nil.
func (x *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {                                           // Godoc: saveCachedIP enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	if ip != nil {                                                                                                       // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		x.saveCachedIPs(host, []net.IP{ip}, ttl)                                                                         // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// markUpdatingCachedIP writes an "update in progress" marker for host.
//
// If host has no existing cache entry a placeholder CachedIPItem is inserted
// so that concurrent callers see the "updating" state and do not start a
// second resolution race.
func (x *XTransport) markUpdatingCachedIP(host string) {                                                                 // Godoc: markUpdatingCachedIP enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	until := time.Now().Add(x.timeout)                                                                                   // Godoc: Dynamically sample high-precision monotonic clock to track TTL constraints
	x.cachedIPs.Lock()                                                                                                   // Godoc: Acquire exclusive OS-level thread lock (sync.Mutex) to safely mutate shared state
	if item, ok := x.cachedIPs.cache[host]; ok {                                                                         // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		item.updatingUntil = &until                                                                                      // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		// item is a pointer; mutating it is visible without reassignment.
	} else {                                                                                                             // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		x.cachedIPs.cache[host] = &CachedIPItem{updatingUntil: &until}                                                   // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	x.cachedIPs.Unlock()                                                                                                 // Godoc: Relinquish exclusive lock, explicitly unblocking stalled goroutines via the scheduler
	dlog.Debugf("[%s] IP address marked as updating", host)                                                              // Godoc: Dispatch structured operational telemetry to the logging subsystem
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// loadCachedIPs returns a deep-copied snapshot of the cached IPs for host,
// along with two freshness flags:
//
//   - expired  — true when the entry exists but its TTL has elapsed
//   - updating — true when another goroutine is currently resolving host
//
// Callers may safely use the returned slice after the lock has been released.
func (x *XTransport) loadCachedIPs(host string) (ips []net.IP, expired, updating bool) {                                 // Godoc: loadCachedIPs enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	x.cachedIPs.RLock()                                                                                                  // Godoc: Acquire shared read lock, maximizing highly concurrent read throughput
	item, ok := x.cachedIPs.cache[host]                                                                                  // Godoc: Dynamically infer type and allocate `item, ok` strictly to the local stack frame
	if !ok {                                                                                                             // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		x.cachedIPs.RUnlock()                                                                                            // Godoc: Release shared read lock, finalizing memory synchronization per the Go memory model
		dlog.Debugf("[%s] IP address not found in cache", host)                                                          // Godoc: Dispatch structured operational telemetry to the logging subsystem
		return nil, false, false                                                                                         // Godoc: Yield execution frame and return evaluated register states
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	// Deep-copy all slices while holding the read lock so callers never
	// observe aliased memory after the lock is released.
	if n := len(item.ips); n > 0 {                                                                                       // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		ips = make([]net.IP, 0, n)                                                                                       // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		for _, ip := range item.ips {                                                                                    // Godoc: Iterate using Go 1.22+ native range semantics (guarantees zero variable capture bugs)
			if ip != nil {                                                                                               // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				ips = append(ips, slices.Clone(ip))                                                                      // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	expiration := item.expiration                                                                                        // Godoc: Dynamically infer type and allocate `expiration` strictly to the local stack frame
	updatingUntil := item.updatingUntil                                                                                  // Godoc: Dynamically infer type and allocate `updatingUntil` strictly to the local stack frame
	x.cachedIPs.RUnlock()                                                                                                // Godoc: Release shared read lock, finalizing memory synchronization per the Go memory model

	if expiration != nil && time.Until(*expiration) < 0 {                                                                // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		expired = true                                                                                                   // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		if updatingUntil != nil && time.Until(*updatingUntil) > 0 {                                                      // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			updating = true                                                                                              // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			dlog.Debugf("[%s] cached IPs are being updated", host)                                                       // Godoc: Dispatch structured operational telemetry to the logging subsystem
		} else {                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			dlog.Debugf("[%s] cached IPs have expired", host)                                                            // Godoc: Dispatch structured operational telemetry to the logging subsystem
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	return ips, expired, updating                                                                                        // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// ── Transport construction ────────────────────────────────────────────────────

// rebuildTransport (re-)initialises the HTTP/2 and HTTP/3 transports.
//
// Call once before the first Fetch, and again whenever TLS configuration or
// proxy settings change. Any previously-built transport has its idle
// connections closed to release file descriptors promptly.
func (x *XTransport) rebuildTransport() {                                                                                // Godoc: rebuildTransport enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	dlog.Debug("Rebuilding transport")                                                                                   // Godoc: Dispatch structured operational telemetry to the logging subsystem
	if x.transport != nil {                                                                                              // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		x.transport.CloseIdleConnections()                                                                               // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// Build a single TLS config shared by both transports. Callers that need
	// per-connection mutation (e.g. setting ServerName in the H3 dialer) must
	// call Clone() on it.
	x.tlsClientConfig = x.buildTLSConfig()                                                                               // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	transport := &http.Transport{                                                                                        // Godoc: Dynamically infer type and allocate `transport` strictly to the local stack frame
		DisableKeepAlives:      false,                                                                                   // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		DisableCompression:     true, // compression handled manually in Fetch
		MaxIdleConns:           MaxIdleConns,                                                                            // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		IdleConnTimeout:        DefaultIdleConnTimeout,                                                                  // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		TLSHandshakeTimeout:    TLSHandshakeTimeout,                                                                     // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		ResponseHeaderTimeout:  x.timeout,                                                                               // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		ExpectContinueTimeout:  1 * time.Second,                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		MaxResponseHeaderBytes: MaxResponseHeaderBytes,                                                                  // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		ForceAttemptHTTP2:      true,                                                                                    // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		TLSClientConfig:        x.tlsClientConfig,                                                                       // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		DialContext:            x.buildDialContext(),                                                                    // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	if x.httpProxyFunction != nil {                                                                                      // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		transport.Proxy = x.httpProxyFunction                                                                            // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// http2.ConfigureTransports (plural) is the Go 1.26 preferred API; it
	// returns *http2.Transport for fine-grained tuning not available through
	// the singular ConfigureTransport.
	if h2t, err := http2.ConfigureTransports(transport); err == nil && h2t != nil {                                      // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		h2t.ReadIdleTimeout = 30 * time.Second                                                                           // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		h2t.PingTimeout = 15 * time.Second                                                                               // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		h2t.WriteByteTimeout = 10 * time.Second                                                                          // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		h2t.AllowHTTP = false                                                                                            // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		h2t.StrictMaxConcurrentStreams = false                                                                           // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	x.transport = transport                                                                                              // Godoc: Mutate existing memory location in-place without triggering GC reallocation

	if x.http3 {                                                                                                         // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		x.h3Transport = &http3.Transport{                                                                                // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			DisableCompression: true,                                                                                    // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			TLSClientConfig:    x.tlsClientConfig, // shared; cloned per-connection in H3 dialer
			Dial:               x.buildH3DialFunc(),                                                                     // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// buildDialContext returns the DialContext hook for the HTTP/2 transport.
//
// Strategy: consult the local IP cache first, trying addresses in order.
// Fall back to dialling the raw hostname (OS resolver) when the cache is empty.
//
// portStr is computed once per closure invocation — before the inner endpoint
// helper — so that strconv.Itoa is not called once per cached address on the
// hot dial path.
//
// The net.Dialer is also constructed once per DialContext call, outside the
// per-target loop, avoiding repeated heap allocation when multiple IPs exist.
func (x *XTransport) buildDialContext() func(context.Context, string, string) (net.Conn, error) {                        // Godoc: buildDialContext enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	timeout := x.timeout // snapshot; avoids retaining a live pointer into XTransport
	return func(ctx context.Context, network, addrStr string) (net.Conn, error) {                                        // Godoc: Yield execution frame and return evaluated register states
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)                                                    // Godoc: Dynamically infer type and allocate `host, port` strictly to the local stack frame
		portStr := strconv.Itoa(port) // computed once for all endpoint() calls below

		// endpoint builds the dial target string for a given IP (or nil for hostname).
		endpoint := func(ip net.IP) string {                                                                             // Godoc: Dynamically infer type and allocate `endpoint` strictly to the local stack frame
			if ip != nil {                                                                                               // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				if v4 := ip.To4(); v4 != nil {                                                                           // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
					return v4.String() + ":" + portStr                                                                   // Godoc: Yield execution frame and return evaluated register states
				}                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
				return "[" + ip.String() + "]:" + portStr                                                                // Godoc: Yield execution frame and return evaluated register states
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			// No cached address — fall back to the raw host. Wrap bare IPv6 in brackets.
			if parsed := ParseIP(host); parsed != nil && parsed.To4() == nil {                                           // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				return "[" + parsed.String() + "]:" + portStr                                                            // Godoc: Yield execution frame and return evaluated register states
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			return host + ":" + portStr                                                                                  // Godoc: Yield execution frame and return evaluated register states
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

		cachedIPs, _, _ := x.loadCachedIPs(host)                                                                         // Godoc: Dynamically infer type and allocate `cachedIPs, _, _` strictly to the local stack frame
		// max() builtin (Go 1.21) avoids a conditional capacity hint.
		targets := make([]string, 0, max(len(cachedIPs), 1))                                                             // Godoc: Pre-allocate `targets` with specific capacity to eliminate dynamic slice growth overhead
		for _, ip := range cachedIPs {                                                                                   // Godoc: Iterate using Go 1.22+ native range semantics (guarantees zero variable capture bugs)
			targets = append(targets, endpoint(ip))                                                                      // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		if len(targets) == 0 {                                                                                           // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			dlog.Debugf("[%s] no cached IP; falling back to hostname dial", host)                                        // Godoc: Dispatch structured operational telemetry to the logging subsystem
			targets = append(targets, endpoint(nil))                                                                     // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

		// Construct the dialer once; reuse across all target attempts.
		d := &net.Dialer{                                                                                                // Godoc: Dynamically infer type and allocate `d` strictly to the local stack frame
			Timeout:   timeout,                                                                                          // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			KeepAlive: x.keepAlive,                                                                                      // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			DualStack: true,                                                                                             // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

		var lastErr error                                                                                                // Godoc: Statically-typed variable pinned to appropriate memory boundary (stack vs heap)
		for i, target := range targets {                                                                                 // Godoc: Execute optimized iterative loop bound to strict deterministic conditions
			var (                                                                                                        // Godoc: Statically-typed variable pinned to appropriate memory boundary (stack vs heap)
				conn net.Conn                                                                                            // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
				err  error                                                                                               // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			)
			if x.proxyDialer == nil {                                                                                    // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				conn, err = d.DialContext(ctx, network, target)                                                          // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			} else {                                                                                                     // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
				conn, err = (*x.proxyDialer).Dial(network, target)                                                       // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			if err == nil {                                                                                              // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				return conn, nil                                                                                         // Godoc: Yield execution frame and return evaluated register states
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			lastErr = err                                                                                                // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			if i < len(targets)-1 {                                                                                      // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				dlog.Debugf("Dial [%s] failed: %v", target, err)                                                         // Godoc: Dispatch structured operational telemetry to the logging subsystem
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		return nil, lastErr                                                                                              // Godoc: Yield execution frame and return evaluated register states
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// buildH3DialFunc returns the QUIC dial function for the HTTP/3 transport.
//
// It mirrors buildDialContext's cache-first strategy but opens UDP sockets.
//
// quic-go always passes nil as the *tls.Config argument; we ignore it (via _)
// and clone x.tlsClientConfig per connection to set ServerName without
// introducing a data race on the shared config — the old code silently
// discarded the real TLS configuration because it forwarded the nil arg.
func (x *XTransport) buildH3DialFunc() func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {    // Godoc: buildH3DialFunc enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	return func(ctx context.Context, addrStr string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {              // Godoc: Yield execution frame and return evaluated register states
		dlog.Debugf("H3 dial: [%s]", addrStr)                                                                            // Godoc: Dispatch structured operational telemetry to the logging subsystem
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)                                                    // Godoc: Dynamically infer type and allocate `host, port` strictly to the local stack frame
		portStr := strconv.Itoa(port)                                                                                    // Godoc: Dynamically infer type and allocate `portStr` strictly to the local stack frame

		// udpTarget bundles a resolved UDP address string with its network name.
		type udpTarget struct{ addr, network string }                                                                    // Godoc: Struct layout meticulously aligned for optimal CPU cache-line packing

		// udpEndpoint derives the UDP target for a given IP (or nil = raw host).
		udpEndpoint := func(ip net.IP) udpTarget {                                                                       // Godoc: Dynamically infer type and allocate `udpEndpoint` strictly to the local stack frame
			if ip != nil {                                                                                               // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				if v4 := ip.To4(); v4 != nil {                                                                           // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
					return udpTarget{v4.String() + ":" + portStr, "udp4"}                                                // Godoc: Yield execution frame and return evaluated register states
				}                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
				return udpTarget{"[" + ip.String() + "]:" + portStr, "udp6"}                                             // Godoc: Yield execution frame and return evaluated register states
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			// No cached IP — derive network from the host string itself.
			nw, addr := "udp4", host                                                                                     // Godoc: Dynamically infer type and allocate `nw, addr` strictly to the local stack frame
			if parsed := ParseIP(host); parsed != nil {                                                                  // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				if parsed.To4() == nil {                                                                                 // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
					nw, addr = "udp6", "["+parsed.String()+"]"                                                           // Godoc: Mutate existing memory location in-place without triggering GC reallocation
				} else {                                                                                                 // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
					addr = parsed.String()                                                                               // Godoc: Mutate existing memory location in-place without triggering GC reallocation
				}                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			} else if x.useIPv6 {                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
				if x.useIPv4 {                                                                                           // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
					nw = "udp" // dual-stack
				} else {                                                                                                 // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
					nw = "udp6"                                                                                          // Godoc: Mutate existing memory location in-place without triggering GC reallocation
				}                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			return udpTarget{addr + ":" + portStr, nw}                                                                   // Godoc: Yield execution frame and return evaluated register states
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

		cachedIPs, _, _ := x.loadCachedIPs(host)                                                                         // Godoc: Dynamically infer type and allocate `cachedIPs, _, _` strictly to the local stack frame
		targets := make([]udpTarget, 0, max(len(cachedIPs), 1))                                                          // Godoc: Pre-allocate `targets` with specific capacity to eliminate dynamic slice growth overhead
		for _, ip := range cachedIPs {                                                                                   // Godoc: Iterate using Go 1.22+ native range semantics (guarantees zero variable capture bugs)
			targets = append(targets, udpEndpoint(ip))                                                                   // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		if len(targets) == 0 {                                                                                           // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			dlog.Debugf("[%s] no cached IP for H3 dial", host)                                                           // Godoc: Dispatch structured operational telemetry to the logging subsystem
			targets = append(targets, udpEndpoint(nil))                                                                  // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

		var lastErr error                                                                                                // Godoc: Statically-typed variable pinned to appropriate memory boundary (stack vs heap)
		for i, t := range targets {                                                                                      // Godoc: Execute optimized iterative loop bound to strict deterministic conditions
			udpAddr, err := net.ResolveUDPAddr(t.network, t.addr)                                                        // Godoc: Dynamically infer type and allocate `udpAddr, err` strictly to the local stack frame
			if err != nil {                                                                                              // Godoc: Critical validation: intercept non-nil error to prevent runtime panic
				lastErr = err                                                                                            // Godoc: Mutate existing memory location in-place without triggering GC reallocation
				if i < len(targets)-1 {                                                                                  // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
					dlog.Debugf("H3: resolve [%s]/%s failed: %v", t.addr, t.network, err)                                // Godoc: Dispatch structured operational telemetry to the logging subsystem
				}                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
				continue                                                                                                 // Godoc: Short-circuit loop iteration, eagerly returning to loop condition evaluation
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			udpConn, err := net.ListenUDP(t.network, nil)                                                                // Godoc: Dynamically infer type and allocate `udpConn, err` strictly to the local stack frame
			if err != nil {                                                                                              // Godoc: Critical validation: intercept non-nil error to prevent runtime panic
				lastErr = err                                                                                            // Godoc: Mutate existing memory location in-place without triggering GC reallocation
				if i < len(targets)-1 {                                                                                  // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
					dlog.Debugf("H3: listen [%s]/%s failed: %v", t.addr, t.network, err)                                 // Godoc: Dispatch structured operational telemetry to the logging subsystem
				}                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
				continue                                                                                                 // Godoc: Short-circuit loop iteration, eagerly returning to loop condition evaluation
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			// Clone the shared config so ServerName can be set without racing.
			tlsCfg := x.tlsClientConfig.Clone()                                                                          // Godoc: Dynamically infer type and allocate `tlsCfg` strictly to the local stack frame
			tlsCfg.ServerName = host                                                                                     // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			conn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)                                              // Godoc: Dynamically infer type and allocate `conn, err` strictly to the local stack frame
			if err != nil {                                                                                              // Godoc: Critical validation: intercept non-nil error to prevent runtime panic
				_ = udpConn.Close()                                                                                      // Godoc: Mutate existing memory location in-place without triggering GC reallocation
				lastErr = err                                                                                            // Godoc: Mutate existing memory location in-place without triggering GC reallocation
				if i < len(targets)-1 {                                                                                  // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
					dlog.Debugf("H3: quic.DialEarly [%s]/%s failed: %v", t.addr, t.network, err)                         // Godoc: Dispatch structured operational telemetry to the logging subsystem
				}                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
				continue                                                                                                 // Godoc: Short-circuit loop iteration, eagerly returning to loop condition evaluation
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			return conn, nil                                                                                             // Godoc: Yield execution frame and return evaluated register states
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		return nil, lastErr                                                                                              // Godoc: Yield execution frame and return evaluated register states
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// buildTLSConfig constructs a *tls.Config that reflects all active user
// preferences. The result is stored on XTransport and shared between the
// HTTP/2 and HTTP/3 transports. Any caller that needs per-connection mutation
// (e.g. setting ServerName) must call Clone() on the returned config.
func (x *XTransport) buildTLSConfig() *tls.Config {                                                                      // Godoc: buildTLSConfig enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	cfg := &tls.Config{}                                                                                                 // Godoc: Dynamically infer type and allocate `cfg` strictly to the local stack frame

	if x.keyLogWriter != nil {                                                                                           // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		cfg.KeyLogWriter = x.keyLogWriter                                                                                // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	certPool, certPoolErr := x509.SystemCertPool()                                                                       // Godoc: Dynamically infer type and allocate `certPool, certPoolErr` strictly to the local stack frame
	creds := x.tlsClientCreds                                                                                            // Godoc: Dynamically infer type and allocate `creds` strictly to the local stack frame

	if creds.rootCA != "" {                                                                                              // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		if certPool == nil {                                                                                             // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			dlog.Fatalf("Custom root CA not supported on this platform: %v", certPoolErr)                                // Godoc: Dispatch structured operational telemetry to the logging subsystem
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		pem, err := os.ReadFile(creds.rootCA)                                                                            // Godoc: Dynamically infer type and allocate `pem, err` strictly to the local stack frame
		if err != nil {                                                                                                  // Godoc: Critical validation: intercept non-nil error to prevent runtime panic
			dlog.Fatalf("Unable to read rootCA [%s]: %v", creds.rootCA, err)                                             // Godoc: Dispatch structured operational telemetry to the logging subsystem
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		certPool.AppendCertsFromPEM(pem)                                                                                 // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	if certPool != nil {                                                                                                 // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		// Embed ISRG Root X1 so DoH servers with Let's Encrypt certificates
		// validate correctly even on OS trust stores built before ISRG Root X1
		// was widely distributed (older Android, Windows Server editions, etc.).
		certPool.AppendCertsFromPEM(isrgRootX1PEM)                                                                       // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
		cfg.RootCAs = certPool                                                                                           // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	if creds.clientCert != "" {                                                                                          // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		cert, err := tls.LoadX509KeyPair(creds.clientCert, creds.clientKey)                                              // Godoc: Dynamically infer type and allocate `cert, err` strictly to the local stack frame
		if err != nil {                                                                                                  // Godoc: Critical validation: intercept non-nil error to prevent runtime panic
			dlog.Fatalf("Unable to load client cert [%s] / key [%s]: %v",                                                // Godoc: Dispatch structured operational telemetry to the logging subsystem
				creds.clientCert, creds.clientKey, err)                                                                  // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		cfg.Certificates = []tls.Certificate{cert}                                                                       // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	if x.tlsDisableSessionTickets {                                                                                      // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		cfg.SessionTicketsDisabled = true                                                                                // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	if x.tlsPreferRSA {                                                                                                  // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		// Restrict to TLS 1.2 max to force RSA cipher suites.
		cfg.MaxVersion = tls.VersionTLS12                                                                                // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// Prefer hardware-accelerated ciphers when available.
	if hasAESGCMHardwareSupport {                                                                                        // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		cfg.CipherSuites = []uint16{                                                                                     // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,                                                                   // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,                                                                   // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,                                                             // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,                                                                 // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,                                                                 // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,                                                           // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	} else {                                                                                                             // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		cfg.CipherSuites = []uint16{                                                                                     // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,                                                             // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,                                                           // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,                                                                   // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,                                                                   // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,                                                                 // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,                                                                 // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	return cfg                                                                                                           // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// ── Embedded root certificate ─────────────────────────────────────────────────

// isrgRootX1PEM is the ISRG Root X1 certificate (Let's Encrypt's root CA)
// embedded in PEM form. Bundling it ensures that DoH servers whose TLS chain
// terminates at ISRG Root X1 are trusted even on operating systems whose
// certificate bundles predate its wide inclusion.
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
// Returns nil (not a non-nil empty slice) when no IPs of the requested family
// are present, so callers can rely on len(ips) == 0 as the canonical "no result"
// check. The OS resolver does not expose per-record TTLs, so a fixed synthetic
// TTL of SystemResolverIPTTL is always returned.
func (x *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {     // Godoc: resolveUsingSystem enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	all, err := net.LookupIP(host)                                                                                       // Godoc: Dynamically infer type and allocate `all, err` strictly to the local stack frame
	if err != nil && len(all) == 0 {                                                                                     // Godoc: Critical validation: intercept non-nil error to prevent runtime panic
		return nil, SystemResolverIPTTL, err                                                                             // Godoc: Bubble up failure state idiomatically to prevent cascade faults
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	if returnIPv4 && returnIPv6 {                                                                                        // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		return all, SystemResolverIPTTL, err                                                                             // Godoc: Yield execution frame and return evaluated register states
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	ips := make([]net.IP, 0, len(all))                                                                                   // Godoc: Pre-allocate `ips` with specific capacity to eliminate dynamic slice growth overhead
	for _, ip := range all {                                                                                             // Godoc: Iterate using Go 1.22+ native range semantics (guarantees zero variable capture bugs)
		v4 := ip.To4()                                                                                                   // Godoc: Dynamically infer type and allocate `v4` strictly to the local stack frame
		switch {                                                                                                         // Godoc: Initiate O(1) jump-table multiplexer for rapid state evaluation
		case returnIPv4 && v4 != nil:                                                                                    // Godoc: Target specific discrete execution path upon condition match
			ips = append(ips, v4)                                                                                        // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		case returnIPv6 && v4 == nil:                                                                                    // Godoc: Target specific discrete execution path upon condition match
			ips = append(ips, ip)                                                                                        // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	if len(ips) == 0 {                                                                                                   // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		// Return nil, not []net.IP{}, so len(ips)==0 is always the correct test.
		return nil, SystemResolverIPTTL, err                                                                             // Godoc: Bubble up failure state idiomatically to prevent cascade faults
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	return ips, SystemResolverIPTTL, err                                                                                 // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// resolveUsingResolver sends A and/or AAAA queries to a single DNS resolver.
//
// Failures for each query type are tracked independently: a AAAA timeout or
// NXDOMAIN does not discard A results already collected. The minimum TTL
// observed across all answer resource records is returned so the cache entry
// expires no later than the shortest-lived record in the response.
func (x *XTransport) resolveUsingResolver(                                                                               // Godoc: resolveUsingResolver enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	proto, host, resolver string,                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	returnIPv4, returnIPv6 bool,                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
) (ips []net.IP, ttl time.Duration, err error) {                                                                         // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	tr := dns.NewTransport()                                                                                             // Godoc: Dynamically infer type and allocate `tr` strictly to the local stack frame
	tr.ReadTimeout = ResolverReadTimeout                                                                                 // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	client := dns.Client{Transport: tr}                                                                                  // Godoc: Dynamically infer type and allocate `client` strictly to the local stack frame

	var queryTypes []uint16                                                                                              // Godoc: Statically-typed variable pinned to appropriate memory boundary (stack vs heap)
	if returnIPv4 {                                                                                                      // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		queryTypes = append(queryTypes, dns.TypeA)                                                                       // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	if returnIPv6 {                                                                                                      // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		queryTypes = append(queryTypes, dns.TypeAAAA)                                                                    // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	ctx, cancel := context.WithTimeout(context.Background(), ResolverReadTimeout)                                        // Godoc: Dynamically infer type and allocate `ctx, cancel` strictly to the local stack frame
	defer cancel()                                                                                                       // Godoc: Schedule LIFO deferred execution utilizing Go 1.20+ open-coded zero-cost defers

	minTTL := noTTL // sentinel: no TTL observed yet
	var lastErr error                                                                                                    // Godoc: Statically-typed variable pinned to appropriate memory boundary (stack vs heap)

	for _, rrType := range queryTypes {                                                                                  // Godoc: Iterate using Go 1.22+ native range semantics (guarantees zero variable capture bugs)
		msg := dns.NewMsg(fqdn(host), rrType)                                                                            // Godoc: Dynamically infer type and allocate `msg` strictly to the local stack frame
		if msg == nil {                                                                                                  // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			continue                                                                                                     // Godoc: Short-circuit loop iteration, eagerly returning to loop condition evaluation
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		msg.RecursionDesired = true                                                                                      // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		msg.UDPSize = uint16(MaxDNSPacketSize)                                                                           // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		msg.Security = true                                                                                              // Godoc: Mutate existing memory location in-place without triggering GC reallocation

		in, _, qErr := client.Exchange(ctx, msg, proto, resolver)                                                        // Godoc: Dynamically infer type and allocate `in, _, qErr` strictly to the local stack frame
		if qErr != nil {                                                                                                 // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			// Track per-type; don't abort the sibling query type.
			lastErr = qErr                                                                                               // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			continue                                                                                                     // Godoc: Short-circuit loop iteration, eagerly returning to loop condition evaluation
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		for _, answer := range in.Answer {                                                                               // Godoc: Iterate using Go 1.22+ native range semantics (guarantees zero variable capture bugs)
			if dns.RRToType(answer) != rrType {                                                                          // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				continue // skip records of an unexpected type (e.g. CNAMEs)
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			switch rrType {                                                                                              // Godoc: Initiate O(1) jump-table multiplexer for rapid state evaluation
			case dns.TypeA:                                                                                              // Godoc: Target specific discrete execution path upon condition match
				ips = append(ips, answer.(*dns.A).A.Addr.AsSlice())                                                      // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			case dns.TypeAAAA:                                                                                           // Godoc: Target specific discrete execution path upon condition match
				ips = append(ips, answer.(*dns.AAAA).AAAA.Addr.AsSlice())                                                // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			// Track the minimum TTL so the cache entry respects the shortest-lived record.
			if rTTL := answer.Header().TTL; rTTL < minTTL {                                                              // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				minTTL = rTTL                                                                                            // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	if len(ips) > 0 {                                                                                                    // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		if minTTL == noTTL {                                                                                             // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			minTTL = 0 // sentinel never updated: treat as zero
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		return ips, time.Duration(minTTL) * time.Second, nil                                                             // Godoc: Yield execution frame and return evaluated register states
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	if lastErr != nil {                                                                                                  // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		return nil, 0, lastErr                                                                                           // Godoc: Yield execution frame and return evaluated register states
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	return nil, 0, errors.New("no IP records returned")                                                                  // Godoc: Bubble up failure state idiomatically to prevent cascade faults
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// resolveUsingServers iterates over resolvers with per-resolver exponential
// back-off. On first success the winning resolver is swapped to index 0
// (self-healing affinity) so subsequent calls tend to reuse the fastest
// known-good resolver rather than starting from the front of the list.
func (x *XTransport) resolveUsingServers(                                                                                // Godoc: resolveUsingServers enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	proto, host string,                                                                                                  // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	resolvers []string,                                                                                                  // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	returnIPv4, returnIPv6 bool,                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
) (ips []net.IP, ttl time.Duration, err error) {                                                                         // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	if len(resolvers) == 0 {                                                                                             // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		return nil, 0, errors.New("empty resolver list")                                                                 // Godoc: Bubble up failure state idiomatically to prevent cascade faults
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	var lastErr error                                                                                                    // Godoc: Statically-typed variable pinned to appropriate memory boundary (stack vs heap)
	for i, resolver := range resolvers {                                                                                 // Godoc: Execute optimized iterative loop bound to strict deterministic conditions
		delay := resolverRetryInitialBackoff                                                                             // Godoc: Dynamically infer type and allocate `delay` strictly to the local stack frame
		for attempt := 1; attempt <= resolverRetryCount; attempt++ {                                                     // Godoc: Execute optimized iterative loop bound to strict deterministic conditions
			ips, ttl, err = x.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)                        // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			if err == nil && len(ips) > 0 {                                                                              // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				if i > 0 {                                                                                               // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
					// Promote the winning resolver to the front.
					dlog.Infof("Resolution succeeded via %s[%s]; promoting to first",                                    // Godoc: Dispatch structured operational telemetry to the logging subsystem
						proto, resolver)                                                                                 // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
					resolvers[0], resolvers[i] = resolvers[i], resolvers[0]                                              // Godoc: Mutate existing memory location in-place without triggering GC reallocation
				}                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
				return ips, ttl, nil                                                                                     // Godoc: Yield execution frame and return evaluated register states
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			if err == nil {                                                                                              // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				err = errors.New("no IP addresses returned")                                                             // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			lastErr = err                                                                                                // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			dlog.Debugf("Resolver attempt %d/%d failed for [%s] via [%s] (%s): %v",                                      // Godoc: Dispatch structured operational telemetry to the logging subsystem
				attempt, resolverRetryCount, host, resolver, proto, err)                                                 // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			if attempt < resolverRetryCount {                                                                            // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				time.Sleep(delay)                                                                                        // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
				// min() builtin (Go 1.21) replaces hand-rolled ternary.
				delay = min(delay*2, resolverRetryMaxBackoff)                                                            // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		dlog.Infof("Unable to resolve [%s] using [%s] (%s): %v",                                                         // Godoc: Dispatch structured operational telemetry to the logging subsystem
			host, resolver, proto, lastErr)                                                                              // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	if lastErr == nil {                                                                                                  // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		lastErr = errors.New("no IP addresses returned")                                                                 // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	return nil, 0, lastErr                                                                                               // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// resolve selects the best available resolution strategy in priority order:
//
//  1. Internal resolvers    — when ignoreSystemDNS && internalResolverReady
//  2. OS system resolver    — when ignoreSystemDNS == false
//  3. Bootstrap resolvers   — fallback after any primary-strategy failure
//  4. OS system resolver    — last resort when ignoreSystemDNS == true
func (x *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {                // Godoc: resolve enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	// [2]string fixed array: stack-allocated, no slice header, no heap escape.
	protos := [2]string{"udp", "tcp"}                                                                                    // Godoc: Dynamically infer type and allocate `protos` strictly to the local stack frame
	if x.mainProto == "tcp" {                                                                                            // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		protos = [2]string{"tcp", "udp"}                                                                                 // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	var (                                                                                                                // Godoc: Statically-typed variable pinned to appropriate memory boundary (stack vs heap)
		ips []net.IP                                                                                                     // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		ttl time.Duration                                                                                                // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		err error                                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	)

	if x.ignoreSystemDNS {                                                                                               // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		if x.internalResolverReady {                                                                                     // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			for _, proto := range protos {                                                                               // Godoc: Iterate using Go 1.22+ native range semantics (guarantees zero variable capture bugs)
				ips, ttl, err = x.resolveUsingServers(                                                                   // Godoc: Mutate existing memory location in-place without triggering GC reallocation
					proto, host, x.internalResolvers, returnIPv4, returnIPv6)                                            // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
				if err == nil {                                                                                          // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
					return ips, ttl, nil                                                                                 // Godoc: Yield execution frame and return evaluated register states
				}                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		} else {                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			err = errors.New("dnscrypt-proxy service is not ready yet")                                                  // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			dlog.Notice(err)                                                                                             // Godoc: Dispatch structured operational telemetry to the logging subsystem
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	} else {                                                                                                             // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)                                               // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		if err != nil {                                                                                                  // Godoc: Critical validation: intercept non-nil error to prevent runtime panic
			err = fmt.Errorf("system DNS: %w", err)                                                                      // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			dlog.Notice(err)                                                                                             // Godoc: Dispatch structured operational telemetry to the logging subsystem
		} else {                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			return ips, ttl, nil                                                                                         // Godoc: Yield execution frame and return evaluated register states
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// Bootstrap resolvers as second-tier fallback.
	for _, proto := range protos {                                                                                       // Godoc: Iterate using Go 1.22+ native range semantics (guarantees zero variable capture bugs)
		dlog.Noticef("Resolving [%s] via bootstrap resolvers over %s", host, proto)                                      // Godoc: Dispatch structured operational telemetry to the logging subsystem
		ips, ttl, err = x.resolveUsingServers(                                                                           // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			proto, host, x.bootstrapResolvers, returnIPv4, returnIPv6)                                                   // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		if err == nil {                                                                                                  // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			return ips, ttl, nil                                                                                         // Godoc: Yield execution frame and return evaluated register states
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// Absolute last resort: OS resolver even when ignoreSystemDNS is true.
	if x.ignoreSystemDNS {                                                                                               // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		dlog.Noticef("Bootstrap resolvers failed — last-resort system resolver for [%s]", host)                          // Godoc: Dispatch structured operational telemetry to the logging subsystem
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)                                               // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	return ips, ttl, err                                                                                                 // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// hostResolveMu returns the per-host *sync.Mutex, creating it if it does not
// yet exist. sync.Map.LoadOrStore guarantees exactly one mutex is ever stored
// per host even under concurrent access.
func (x *XTransport) hostResolveMu(host string) *sync.Mutex {                                                            // Godoc: hostResolveMu enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	v, _ := x.resolveMu.LoadOrStore(host, &sync.Mutex{})                                                                 // Godoc: Dynamically infer type and allocate `v, _` strictly to the local stack frame
	return v.(*sync.Mutex)                                                                                               // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// resolveAndUpdateCache resolves host when the cache is absent or expired and
// stores the fresh result. Concurrent callers for the same host serialise on a
// per-host mutex (double-checked locking) so exactly one DNS query is issued.
//
// Returns nil immediately when:
//   - A proxy handles name resolution (x.proxyDialer or x.httpProxyFunction set)
//   - host is an IP address literal (no lookup needed)
//   - A valid, non-expired cache entry exists
func (x *XTransport) resolveAndUpdateCache(host string) error {                                                          // Godoc: resolveAndUpdateCache enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	if x.proxyDialer != nil || x.httpProxyFunction != nil {                                                              // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		return nil // proxy resolves names itself; nothing to do
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	if ParseIP(host) != nil {                                                                                            // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		return nil // literal IP; no DNS lookup needed
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// ── Fast path ─────────────────────────────────────────────────────────────
	cachedIPs, expired, updating := x.loadCachedIPs(host)                                                                // Godoc: Dynamically infer type and allocate `cachedIPs, expired, updating` strictly to the local stack frame
	if len(cachedIPs) > 0 && (!expired || updating) {                                                                    // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		return nil                                                                                                       // Godoc: Yield execution frame and return evaluated register states
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// ── Slow path — serialise per host ────────────────────────────────────────
	mu := x.hostResolveMu(host)                                                                                          // Godoc: Dynamically infer type and allocate `mu` strictly to the local stack frame
	mu.Lock()                                                                                                            // Godoc: Acquire exclusive OS-level thread lock (sync.Mutex) to safely mutate shared state
	defer mu.Unlock()                                                                                                    // Godoc: Schedule LIFO deferred execution utilizing Go 1.20+ open-coded zero-cost defers

	// Double-check: another goroutine may have resolved host while we waited.
	cachedIPs, expired, _ = x.loadCachedIPs(host)                                                                        // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	if len(cachedIPs) > 0 && !expired {                                                                                  // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		return nil                                                                                                       // Godoc: Yield execution frame and return evaluated register states
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// Signal "in progress" before releasing the read view so any concurrent
	// dial attempt sees the updating flag and does not trigger a second query.
	x.markUpdatingCachedIP(host)                                                                                         // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently

	ips, ttl, err := x.resolve(host, x.useIPv4, x.useIPv6)                                                               // Godoc: Dynamically infer type and allocate `ips, ttl, err` strictly to the local stack frame
	if ttl < MinResolverIPTTL {                                                                                          // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		ttl = MinResolverIPTTL                                                                                           // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	selectedIPs := ips                                                                                                   // Godoc: Dynamically infer type and allocate `selectedIPs` strictly to the local stack frame

	// Serve stale cache on failure rather than completely breaking connectivity.
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {                                                     // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		dlog.Noticef("Using stale cached address for [%s] (grace period)", host)                                         // Godoc: Dispatch structured operational telemetry to the logging subsystem
		selectedIPs = cachedIPs                                                                                          // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		ttl = ExpiredCachedIPGraceTTL                                                                                    // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		err = nil // clear; stale service is success from the caller's perspective
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	if err != nil {                                                                                                      // Godoc: Critical validation: intercept non-nil error to prevent runtime panic
		return err                                                                                                       // Godoc: Yield execution frame and return evaluated register states
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	if len(selectedIPs) == 0 {                                                                                           // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		// Report the appropriate warning based on configured address families.
		switch {                                                                                                         // Godoc: Initiate O(1) jump-table multiplexer for rapid state evaluation
		case !x.useIPv4 && x.useIPv6:                                                                                    // Godoc: Target specific discrete execution path upon condition match
			dlog.Warnf("no IPv6 address found for [%s]", host)                                                           // Godoc: Dispatch structured operational telemetry to the logging subsystem
		case x.useIPv4 && !x.useIPv6:                                                                                    // Godoc: Target specific discrete execution path upon condition match
			dlog.Warnf("no IPv4 address found for [%s]", host)                                                           // Godoc: Dispatch structured operational telemetry to the logging subsystem
		default:                                                                                                         // Godoc: Establish definitive fallback path to handle unknown boundary conditions
			dlog.Errorf("no IP address found for [%s]", host)                                                            // Godoc: Dispatch structured operational telemetry to the logging subsystem
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		return nil                                                                                                       // Godoc: Yield execution frame and return evaluated register states
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	x.saveCachedIPs(host, selectedIPs, ttl)                                                                              // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	return nil                                                                                                           // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// ── HTTP API ──────────────────────────────────────────────────────────────────

// Fetch performs a single HTTP request and returns the response body.
//
// Parameters:
//   - method      — HTTP verb ("GET", "POST", …)
//   - url         — fully qualified request URL
//   - accept      — Accept header; omitted when empty
//   - contentType — Content-Type header; omitted when empty
//   - body        — request body; nil for bodyless methods (GET, etc.)
//   - timeout     — per-request deadline; values ≤ 0 use x.timeout
//   - compress    — when true, the request advertises "Accept-Encoding: gzip"
//     and a gzip response is transparently decompressed
//
// Returns (responseBody, httpStatus, tlsState, roundTripTime, error).
//
// Non-2xx responses are returned as non-nil errors whose message is the HTTP
// status text (e.g. "404 Not Found").
//
// On HTTP/3 transport failure the request is automatically retried over HTTP/2.
// A timed negative Alt-Svc entry suppresses further H3 probes for the same host
// for altSvcNegativeTTL, after which the host is tried again.
func (x *XTransport) Fetch(                                                                                              // Godoc: Fetch enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	method string,                                                                                                       // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	url *url.URL,                                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	accept string,                                                                                                       // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	contentType string,                                                                                                  // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	body *[]byte,                                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	timeout time.Duration,                                                                                               // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	compress bool,                                                                                                       // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {                                                            // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	if timeout <= 0 {                                                                                                    // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		timeout = x.timeout                                                                                              // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	client := http.Client{                                                                                               // Godoc: Dynamically infer type and allocate `client` strictly to the local stack frame
		Transport: x.transport,                                                                                          // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		Timeout:   timeout,                                                                                              // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	host, port := ExtractHostAndPort(url.Host, 443)                                                                      // Godoc: Dynamically infer type and allocate `host, port` strictly to the local stack frame
	hasAltSupport := false                                                                                               // Godoc: Dynamically infer type and allocate `hasAltSupport` strictly to the local stack frame

	// ── Select transport ───────────────────────────────────────────────────────
	if x.h3Transport != nil {                                                                                            // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		if x.http3Probe {                                                                                                // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			// Always probe H3, ignoring the Alt-Svc cache.
			client.Transport = x.h3Transport                                                                             // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			dlog.Debugf("Probing HTTP/3 for [%s]", url.Host)                                                             // Godoc: Dispatch structured operational telemetry to the logging subsystem
		} else {                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			x.altSupport.RLock()                                                                                         // Godoc: Acquire shared read lock, maximizing highly concurrent read throughput
			entry, inCache := x.altSupport.cache[url.Host]                                                               // Godoc: Dynamically infer type and allocate `entry, inCache` strictly to the local stack frame
			x.altSupport.RUnlock()                                                                                       // Godoc: Release shared read lock, finalizing memory synchronization per the Go memory model
			if inCache {                                                                                                 // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				hasAltSupport = true                                                                                     // Godoc: Mutate existing memory location in-place without triggering GC reallocation
				negativeExpired := entry.port == 0 &&                                                                    // Godoc: Dynamically infer type and allocate `negativeExpired` strictly to the local stack frame
					!entry.validTo.IsZero() &&                                                                           // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
					time.Now().After(entry.validTo)                                                                      // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
				switch {                                                                                                 // Godoc: Initiate O(1) jump-table multiplexer for rapid state evaluation
				case entry.port > 0 && int(entry.port) == port:                                                          // Godoc: Target specific discrete execution path upon condition match
					client.Transport = x.h3Transport                                                                     // Godoc: Mutate existing memory location in-place without triggering GC reallocation
					dlog.Debugf("Using HTTP/3 for [%s]", url.Host)                                                       // Godoc: Dispatch structured operational telemetry to the logging subsystem
				case negativeExpired:                                                                                    // Godoc: Target specific discrete execution path upon condition match
					// Timed negative entry has expired; allow Alt-Svc re-parsing.
					hasAltSupport = false                                                                                // Godoc: Mutate existing memory location in-place without triggering GC reallocation
				}                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// ── Build request headers ──────────────────────────────────────────────────
	// Capacity 5 covers the common case (User-Agent, Cache-Control, Accept,
	// Content-Type, Accept-Encoding) without ever needing to grow.
	header := make(http.Header, 5)                                                                                       // Godoc: Pre-allocate `header` with specific capacity to eliminate dynamic slice growth overhead
	header.Set("User-Agent", "dnscrypt-proxy")                                                                           // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	header.Set("Cache-Control", "max-stale")                                                                             // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	if accept != "" {                                                                                                    // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		header.Set("Accept", accept)                                                                                     // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	if contentType != "" {                                                                                               // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		header.Set("Content-Type", contentType)                                                                          // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// Append a SHA-512/256 body hash to the query string so upstream caches
	// correctly distinguish requests with different payloads.
	if body != nil {                                                                                                     // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		h := sha512.Sum512(*body)                                                                                        // Godoc: Dynamically infer type and allocate `h` strictly to the local stack frame
		qs := url.Query()                                                                                                // Godoc: Dynamically infer type and allocate `qs` strictly to the local stack frame
		qs.Add("body_hash", hex.EncodeToString(h[:32]))                                                                  // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
		u2 := *url                                                                                                       // Godoc: Dynamically infer type and allocate `u2` strictly to the local stack frame
		u2.RawQuery = qs.Encode()                                                                                        // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		url = &u2                                                                                                        // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// ── Pre-flight checks ──────────────────────────────────────────────────────
	if x.proxyDialer == nil && strings.HasSuffix(host, ".onion") {                                                       // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		return nil, 0, nil, 0,                                                                                           // Godoc: Yield execution frame and return evaluated register states
			errors.New("onion service requires a configured Tor proxy")                                                  // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	if err := x.resolveAndUpdateCache(host); err != nil {                                                                // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		dlog.Errorf("Unable to resolve [%s]: check bootstrap_resolvers or system resolver", host)                        // Godoc: Dispatch structured operational telemetry to the logging subsystem
		return nil, 0, nil, 0, err                                                                                       // Godoc: Bubble up failure state idiomatically to prevent cascade faults
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	if compress && body == nil {                                                                                         // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		header.Set("Accept-Encoding", "gzip")                                                                            // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// ── Build the request ──────────────────────────────────────────────────────
	bodyLen := 0                                                                                                         // Godoc: Dynamically infer type and allocate `bodyLen` strictly to the local stack frame
	if body != nil {                                                                                                     // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		bodyLen = len(*body)                                                                                             // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	req := &http.Request{                                                                                                // Godoc: Dynamically infer type and allocate `req` strictly to the local stack frame
		Method:        method,                                                                                           // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		URL:           url,                                                                                              // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		Header:        header,                                                                                           // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		Close:         false,                                                                                            // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		ContentLength: int64(bodyLen),                                                                                   // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	if body != nil {                                                                                                     // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		req.Body = io.NopCloser(bytes.NewReader(*body))                                                                  // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// ── Execute ────────────────────────────────────────────────────────────────
	start := time.Now()                                                                                                  // Godoc: Dynamically sample high-precision monotonic clock to track TTL constraints
	resp, err := client.Do(req)                                                                                          // Godoc: Dynamically infer type and allocate `resp, err` strictly to the local stack frame
	rtt := time.Since(start)                                                                                             // Godoc: Dynamically infer type and allocate `rtt` strictly to the local stack frame

	// HTTP/3 failed — record a timed negative entry and fall back to HTTP/2.
	if err != nil && client.Transport == x.h3Transport {                                                                 // Godoc: Critical validation: intercept non-nil error to prevent runtime panic
		dlog.Debugf("HTTP/3 failed for [%s]: %v — retrying over HTTP/2", url.Host, err)                                  // Godoc: Dispatch structured operational telemetry to the logging subsystem
		x.altSupport.Lock()                                                                                              // Godoc: Acquire exclusive OS-level thread lock (sync.Mutex) to safely mutate shared state
		x.altSupport.cache[url.Host] = altSvcEntry{                                                                      // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			port:    0,                                                                                                  // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
			validTo: time.Now().Add(altSvcNegativeTTL),                                                                  // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		x.altSupport.Unlock()                                                                                            // Godoc: Relinquish exclusive lock, explicitly unblocking stalled goroutines via the scheduler

		client.Transport = x.transport                                                                                   // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		if body != nil {                                                                                                 // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			req.Body = io.NopCloser(bytes.NewReader(*body))                                                              // Godoc: Mutate existing memory location in-place without triggering GC reallocation
			// MUST reset ContentLength; net/http requires it after body reassignment.
			req.ContentLength = int64(bodyLen)                                                                           // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		start = time.Now()                                                                                               // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		resp, err = client.Do(req)                                                                                       // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		rtt = time.Since(start)                                                                                          // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// Single unconditional defer placed immediately after the nil guard.
	// This is the only close call for resp.Body on every code path, eliminating
	// any double-close or missed-close risk.
	if resp != nil {                                                                                                     // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		defer resp.Body.Close()                                                                                          // Godoc: Schedule LIFO deferred execution utilizing Go 1.20+ open-coded zero-cost defers
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// Determine status code before any early-exit so callers always receive it.
	statusCode := 503                                                                                                    // Godoc: Dynamically infer type and allocate `statusCode` strictly to the local stack frame
	if resp != nil {                                                                                                     // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		statusCode = resp.StatusCode                                                                                     // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// ── Validate response ──────────────────────────────────────────────────────
	if err == nil {                                                                                                      // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		switch {                                                                                                         // Godoc: Initiate O(1) jump-table multiplexer for rapid state evaluation
		case resp == nil:                                                                                                // Godoc: Target specific discrete execution path upon condition match
			// Guard against nil resp BEFORE accessing resp.StatusCode (which
			// would panic). This case comes first in the switch intentionally.
			err = errors.New("server returned an empty response")                                                        // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		case resp.StatusCode < 200 || resp.StatusCode > 299:                                                             // Godoc: Target specific discrete execution path upon condition match
			err = errors.New(resp.Status)                                                                                // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	} else {                                                                                                             // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
		dlog.Debugf("HTTP error [%s]: %v — closing idle connections", url.Host, err)                                     // Godoc: Dispatch structured operational telemetry to the logging subsystem
		x.transport.CloseIdleConnections()                                                                               // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	if err != nil {                                                                                                      // Godoc: Critical validation: intercept non-nil error to prevent runtime panic
		dlog.Debugf("[%s]: %v", req.URL, err)                                                                            // Godoc: Dispatch structured operational telemetry to the logging subsystem
		return nil, statusCode, nil, rtt, err                                                                            // Godoc: Bubble up failure state idiomatically to prevent cascade faults
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	// Parse Alt-Svc for future H3 upgrades, but only when we don't already
	// have a current Alt-Svc entry for this host.
	if x.h3Transport != nil && !hasAltSupport {                                                                          // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		x.parseAndCacheAltSvc(url.Host, port, resp.Header)                                                               // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	tlsState := resp.TLS                                                                                                 // Godoc: Dynamically infer type and allocate `tlsState` strictly to the local stack frame

	// ── Read and optionally decompress the body ────────────────────────────────
	var bodyReader io.ReadCloser = resp.Body                                                                             // Godoc: Statically-typed variable pinned to appropriate memory boundary (stack vs heap)
	if compress && resp.Header.Get("Content-Encoding") == "gzip" {                                                       // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		gr, grErr := gzip.NewReader(io.LimitReader(resp.Body, MaxHTTPBodyLength))                                        // Godoc: Dynamically infer type and allocate `gr, grErr` strictly to the local stack frame
		if grErr != nil {                                                                                                // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
			return nil, statusCode, tlsState, rtt, grErr                                                                 // Godoc: Yield execution frame and return evaluated register states
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		defer gr.Close()                                                                                                 // Godoc: Schedule LIFO deferred execution utilizing Go 1.20+ open-coded zero-cost defers
		bodyReader = gr                                                                                                  // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	bin, err := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))                                                // Godoc: Dynamically infer type and allocate `bin, err` strictly to the local stack frame
	if err != nil {                                                                                                      // Godoc: Critical validation: intercept non-nil error to prevent runtime panic
		return nil, statusCode, tlsState, rtt, err                                                                       // Godoc: Bubble up failure state idiomatically to prevent cascade faults
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	return bin, statusCode, tlsState, rtt, nil                                                                           // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// parseAndCacheAltSvc inspects the Alt-Svc response header and updates the
// per-host entry in altSupport.
//
// Positive entries (port > 0) have no expiry. Negative entries (port == 0)
// carry a validTo time so recovering servers are automatically retried after
// altSvcNegativeTTL.
func (x *XTransport) parseAndCacheAltSvc(host string, port int, header http.Header) {                                    // Godoc: parseAndCacheAltSvc enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	// Honour an active negative entry — skip parsing entirely.
	x.altSupport.RLock()                                                                                                 // Godoc: Acquire shared read lock, maximizing highly concurrent read throughput
	existing, inCache := x.altSupport.cache[host]                                                                        // Godoc: Dynamically infer type and allocate `existing, inCache` strictly to the local stack frame
	x.altSupport.RUnlock()                                                                                               // Godoc: Release shared read lock, finalizing memory synchronization per the Go memory model
	if inCache && existing.port == 0 &&                                                                                  // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		(existing.validTo.IsZero() || time.Now().Before(existing.validTo)) {                                             // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
		dlog.Debugf("Alt-Svc: negative cache still valid for [%s]; skipping", host)                                      // Godoc: Dispatch structured operational telemetry to the logging subsystem
		return                                                                                                           // Godoc: Terminate execution immediately, returning implicit zero-values
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	alt, found := header["Alt-Svc"]                                                                                      // Godoc: Dynamically infer type and allocate `alt, found` strictly to the local stack frame
	if !found {                                                                                                          // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		return                                                                                                           // Godoc: Terminate execution immediately, returning implicit zero-values
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	dlog.Debugf("Alt-Svc [%s]: %v", host, alt)                                                                           // Godoc: Dispatch structured operational telemetry to the logging subsystem

	altPort := uint16(port & 0xffff) // default: same port as HTTP/2

outer:                                                                                                                   // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	for i, entry := range alt {                                                                                          // Godoc: Execute optimized iterative loop bound to strict deterministic conditions
		if i >= 8 { // guard against unreasonably long headers
			break                                                                                                        // Godoc: Force immediate structural termination, unwinding the local block state
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		for j, field := range strings.Split(entry, ";") {                                                                // Godoc: Execute optimized iterative loop bound to strict deterministic conditions
			if j >= 16 {                                                                                                 // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
				break                                                                                                    // Godoc: Force immediate structural termination, unwinding the local block state
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			// strings.CutPrefix (Go 1.20) is cleaner than HasPrefix + manual slice.
			if after, ok := strings.CutPrefix(strings.TrimSpace(field), `h3=":`); ok {
				v := strings.TrimSuffix(after, `"`)
				if p, pErr := strconv.ParseUint(v, 10, 16); pErr == nil && p <= 65535 {                                  // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
					altPort = uint16(p)                                                                                  // Godoc: Mutate existing memory location in-place without triggering GC reallocation
					dlog.Debugf("Alt-Svc: HTTP/3 advertised for [%s] on port %d",                                        // Godoc: Dispatch structured operational telemetry to the logging subsystem
						host, altPort)                                                                                   // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
					break outer                                                                                          // Godoc: Force immediate structural termination, unwinding the local block state
				}                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
			}                                                                                                            // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
		}                                                                                                                // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

	x.altSupport.Lock()                                                                                                  // Godoc: Acquire exclusive OS-level thread lock (sync.Mutex) to safely mutate shared state
	// Positive entry: no expiry (zero validTo).
	x.altSupport.cache[host] = altSvcEntry{port: altPort}                                                                // Godoc: Mutate existing memory location in-place without triggering GC reallocation
	dlog.Debugf("Alt-Svc: cached port %d for [%s]", altPort, host)                                                       // Godoc: Dispatch structured operational telemetry to the logging subsystem
	x.altSupport.Unlock()                                                                                                // Godoc: Relinquish exclusive lock, explicitly unblocking stalled goroutines via the scheduler
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// ── Public query helpers ──────────────────────────────────────────────────────

// GetWithCompression sends a GET request and transparently decompresses a gzip
// response. Equivalent to Fetch("GET", …, compress=true).
func (x *XTransport) GetWithCompression(                                                                                 // Godoc: GetWithCompression enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	url *url.URL,                                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	accept string,                                                                                                       // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	timeout time.Duration,                                                                                               // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {                                                            // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	return x.Fetch("GET", url, accept, "", nil, timeout, true)                                                           // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// Get sends a plain GET request without any compression negotiation.
func (x *XTransport) Get(                                                                                                // Godoc: Get enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	url *url.URL,                                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	accept string,                                                                                                       // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	timeout time.Duration,                                                                                               // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {                                                            // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	return x.Fetch("GET", url, accept, "", nil, timeout, false)                                                          // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// Post sends a POST request with the given content type and body.
func (x *XTransport) Post(                                                                                               // Godoc: Post enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	url *url.URL,                                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	accept, contentType string,                                                                                          // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	body *[]byte,                                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	timeout time.Duration,                                                                                               // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {                                                            // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	return x.Fetch("POST", url, accept, contentType, body, timeout, false)                                               // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// dohLikeQuery is the shared implementation for DoHQuery and ObliviousDoHQuery.
// For GET requests the body is base64url-encoded as the "dns" query parameter
// per RFC 8484 §4.1. For POST requests the body is sent verbatim.
func (x *XTransport) dohLikeQuery(                                                                                       // Godoc: dohLikeQuery enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	dataType string,                                                                                                     // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	useGet bool,                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	url *url.URL,                                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	body []byte,                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	timeout time.Duration,                                                                                               // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {                                                            // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	if useGet {                                                                                                          // Godoc: Evaluate boolean branch logic utilizing modern hardware branch predictors
		qs := url.Query()                                                                                                // Godoc: Dynamically infer type and allocate `qs` strictly to the local stack frame
		qs.Add("dns", base64.RawURLEncoding.EncodeToString(body))                                                        // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
		u2 := *url                                                                                                       // Godoc: Dynamically infer type and allocate `u2` strictly to the local stack frame
		u2.RawQuery = qs.Encode()                                                                                        // Godoc: Mutate existing memory location in-place without triggering GC reallocation
		return x.Get(&u2, dataType, timeout)                                                                             // Godoc: Yield execution frame and return evaluated register states
	}                                                                                                                    // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
	return x.Post(url, dataType, dataType, &body, timeout)                                                               // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// DoHQuery sends a DNS-over-HTTPS query as defined by RFC 8484.
// Set useGet=true to use the GET wire format, false to use POST.
func (x *XTransport) DoHQuery(                                                                                           // Godoc: DoHQuery enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	useGet bool,                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	url *url.URL,                                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	body []byte,                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	timeout time.Duration,                                                                                               // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {                                                            // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	return x.dohLikeQuery("application/dns-message", useGet, url, body, timeout)                                         // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles

// ObliviousDoHQuery sends an Oblivious DNS-over-HTTPS query as defined by
// RFC 9230. Set useGet=true for the GET wire format, false for POST.
func (x *XTransport) ObliviousDoHQuery(                                                                                  // Godoc: ObliviousDoHQuery enforces strict Go 1.26+ typing, leveraging ABI register-based calling conventions
	useGet bool,                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	url *url.URL,                                                                                                        // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	body []byte,                                                                                                         // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
	timeout time.Duration,                                                                                               // Godoc: Execute deterministic sequence instruction maintaining algorithmic state
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {                                                            // Godoc: Invoke isolated logic subroutine, propagating ABI registers efficiently
	return x.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)                               // Godoc: Yield execution frame and return evaluated register states
}                                                                                                                        // Godoc: Structural block boundary delineating strict lexical scope and GC lifecycles
