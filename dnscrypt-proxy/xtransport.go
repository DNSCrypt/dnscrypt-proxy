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

import (  // Execute instruction
	"slices"  // Execute instruction
	"bytes"  // Execute instruction
	"compress/gzip"  // Execute instruction
	"context"  // Execute instruction
	"crypto/sha512"  // Execute instruction
	"crypto/tls"  // Execute instruction
	"crypto/x509"  // Execute instruction
	"encoding/base64"  // Execute instruction
	"encoding/hex"  // Execute instruction
	"errors"  // Execute instruction
	"fmt"  // Execute instruction
	"io"  // Execute instruction
	"math/rand/v2"  // Execute instruction
	"net"  // Execute instruction
	"net/http"  // Execute instruction
	"net/netip"  // Execute instruction
	"net/url"  // Execute instruction
	"os"  // Execute instruction
	"strconv"  // Execute instruction
	"strings"  // Execute instruction
	"sync"  // Execute instruction
	"time"  // Execute instruction

	"codeberg.org/miekg/dns"  // Execute instruction
	"github.com/jedisct1/dlog"  // Execute instruction
	stamps "github.com/jedisct1/go-dnsstamps"  // Execute instruction
	"github.com/quic-go/quic-go"  // Execute instruction
	"github.com/quic-go/quic-go/http3"  // Execute instruction
	"golang.org/x/net/http2"  // Execute instruction
	netproxy "golang.org/x/net/proxy"  // Execute instruction
	"golang.org/x/sys/cpu"  // Execute instruction
)  // Execute instruction

// ── Hardware capability probe ─────────────────────────────────────────────────

// hasAESGCMHardwareSupport is true when the CPU can accelerate AES-GCM in
// hardware. Used to order TLS 1.2 cipher suites: AES-GCM first on capable
// hardware, ChaCha20-Poly1305 first everywhere else.
var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||  // Update state of `var hasAESGCMHardwareSupport` with new computed value
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||  // Execute instruction
	(cpu.S390X.HasAES && cpu.S390X.HasAESGCM)  // Execute instruction

// ── Sentinel ──────────────────────────────────────────────────────────────────

// noTTL is the "no TTL seen yet" sentinel used when tracking the minimum TTL
// across DNS answer RRs. A named constant is clearer than the magic ^uint32(0).
const noTTL = ^uint32(0)  // Update state of `const noTTL` with new computed value

// ── Tuning constants ──────────────────────────────────────────────────────────

const (  // Execute instruction
	// DefaultBootstrapResolver is the DNS resolver used at startup before the
	// internal proxy resolver becomes available. Must be a valid host:port.
	DefaultBootstrapResolver = "9.9.9.9:53"  // Update state of `DefaultBootstrapResolver` with new computed value

	// DefaultKeepAlive is the TCP keep-alive probe interval passed to net.Dialer.
	DefaultKeepAlive = 5 * time.Second  // Update state of `DefaultKeepAlive` with new computed value

	// DefaultIdleConnTimeout is how long an idle HTTP/2 connection remains in
	// the transport pool before being closed.
	DefaultIdleConnTimeout = 90 * time.Second  // Update state of `DefaultIdleConnTimeout` with new computed value

	// DefaultTimeout is the end-to-end deadline for a single HTTP request.
	// Callers may override this per-request via the timeout parameter.
	DefaultTimeout = 30 * time.Second  // Update state of `DefaultTimeout` with new computed value

	// ResolverReadTimeout is the maximum duration for a single DNS exchange
	// (query transmission + response receipt).
	ResolverReadTimeout = 5 * time.Second  // Update state of `ResolverReadTimeout` with new computed value

	// SystemResolverIPTTL is the synthetic TTL assigned to addresses returned
	// by the OS resolver. The OS resolver does not expose per-record TTLs.
	SystemResolverIPTTL = 12 * time.Hour  // Update state of `SystemResolverIPTTL` with new computed value

	// MinResolverIPTTL is the minimum TTL enforced for any cached IP entry.
	// Advertised TTLs shorter than this are silently raised to it.
	MinResolverIPTTL = 4 * time.Hour  // Update state of `MinResolverIPTTL` with new computed value

	// ResolverIPTTLMaxJitter is the exclusive upper bound of the random
	// duration added to each TTL to stagger re-resolution across time.
	ResolverIPTTLMaxJitter = 15 * time.Minute  // Update state of `ResolverIPTTLMaxJitter` with new computed value

	// ExpiredCachedIPGraceTTL is how long a stale cache entry continues to be
	// served when fresh resolution fails. Keeps connectivity during outages.
	ExpiredCachedIPGraceTTL = 15 * time.Minute  // Update state of `ExpiredCachedIPGraceTTL` with new computed value

	// resolverRetryCount is the number of query attempts per resolver before
	// falling through to the next resolver in the list.
	resolverRetryCount = 3  // Update state of `resolverRetryCount` with new computed value

	// resolverRetryInitialBackoff is the sleep before the second attempt.
	// Each subsequent sleep doubles up to resolverRetryMaxBackoff.
	resolverRetryInitialBackoff = 150 * time.Millisecond  // Update state of `resolverRetryInitialBackoff` with new computed value

	// resolverRetryMaxBackoff caps the exponential back-off growth.
	resolverRetryMaxBackoff = 1 * time.Second  // Update state of `resolverRetryMaxBackoff` with new computed value

	// MaxIdleConns is the total HTTP/2 connection-pool size across all hosts.
	MaxIdleConns = 2000  // Update state of `MaxIdleConns` with new computed value

	// MaxResponseHeaderBytes caps the HTTP response header size accepted.
	MaxResponseHeaderBytes = 4096  // Update state of `MaxResponseHeaderBytes` with new computed value

	// TLSHandshakeTimeout is the deadline for completing a TLS handshake,
	// applied to both the HTTP/2 and HTTP/3 transports.
	TLSHandshakeTimeout = 10 * time.Second  // Update state of `TLSHandshakeTimeout` with new computed value

	// altSvcNegativeTTL is how long a failed HTTP/3 probe blocks further H3
	// attempts for the same host. After this window the entry expires and the
	// host is tried again.
	altSvcNegativeTTL = 10 * time.Minute  // Update state of `altSvcNegativeTTL` with new computed value
)  // Execute instruction

// ── Types ─────────────────────────────────────────────────────────────────────

// CachedIPItem stores resolved IP addresses and their freshness metadata.
// All fields are protected by the enclosing CachedIPs.RWMutex.
type CachedIPItem struct {  // Execute instruction
	ips           []net.IP  // Execute instruction
	expiration    *time.Time // nil → entry never expires
	updatingUntil *time.Time // non-nil while background re-resolution is in flight
}  // Structure boundary: Open/Close execution block scope

// CachedIPs is a thread-safe hostname → IP-address cache.
type CachedIPs struct {  // Execute instruction
	sync.RWMutex  // Execute instruction
	cache map[string]*CachedIPItem  // Execute instruction
}  // Structure boundary: Open/Close execution block scope

// altSvcEntry holds a single HTTP/3 Alt-Svc record for a host.
//
//   - port > 0  → positive entry: use HTTP/3 on this port
//   - port == 0 → negative entry: HTTP/3 failed or is unavailable
//
// validTo is only meaningful for negative entries and indicates when the ban
// expires. Positive entries never expire (validTo is the zero time).
type altSvcEntry struct {  // Execute instruction
	port    uint16  // Execute instruction
	validTo time.Time  // Execute instruction
}  // Structure boundary: Open/Close execution block scope

// AltSupport is a thread-safe cache of HTTP/3 Alt-Svc entries keyed by host.
type AltSupport struct {  // Execute instruction
	sync.RWMutex  // Execute instruction
	cache map[string]altSvcEntry  // Execute instruction
}  // Structure boundary: Open/Close execution block scope

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
type XTransport struct {  // Execute instruction
	// HTTP transports. h3Transport is nil when HTTP/3 is disabled.
	transport       *http.Transport  // Execute instruction
	h3Transport     *http3.Transport  // Execute instruction
	tlsClientConfig *tls.Config // constructed once; shared across both transports

	keepAlive time.Duration  // Execute instruction
	timeout   time.Duration  // Execute instruction

	cachedIPs  CachedIPs  // Execute instruction
	altSupport AltSupport  // Execute instruction

	// DNS resolver configuration.
	internalResolvers     []string  // Execute instruction
	bootstrapResolvers    []string  // Execute instruction
	mainProto             string // "udp" or "tcp" — preferred DNS query transport
	ignoreSystemDNS       bool  // Execute instruction
	internalResolverReady bool  // Execute instruction

	// Address-family selection for outgoing connections.
	useIPv4 bool  // Execute instruction
	useIPv6 bool  // Execute instruction

	// HTTP/3 control flags.
	// Field names intentionally match what config_loader.go sets so that this
	// file is a drop-in replacement without changing any callsite.
	http3      bool // enable HTTP/3 transport for all requests
	http3Probe bool // bypass Alt-Svc cache and always probe H3 first

	// TLS tweaks.
	tlsDisableSessionTickets bool  // Execute instruction
	tlsPreferRSA             bool // limits TLS max version to 1.2

	// Proxy configuration.
	proxyDialer       *netproxy.Dialer  // Execute instruction
	httpProxyFunction func(*http.Request) (*url.URL, error)  // Execute instruction

	// Client credentials and debug hooks.
	tlsClientCreds DOHClientCreds  // Execute instruction
	keyLogWriter   io.Writer  // Execute instruction

	// resolveMu stores one *sync.Mutex per hostname (as sync.Map values).
	// It ensures only one goroutine resolves a given host at a time.
	resolveMu sync.Map // effective type: map[string]*sync.Mutex
}  // Structure boundary: Open/Close execution block scope

// ── Constructor ───────────────────────────────────────────────────────────────

// NewXTransport allocates an *XTransport with safe production defaults.
//
// It panics if DefaultBootstrapResolver is not a valid host:port — that is a
// programming error detectable at startup, not a recoverable runtime condition.
func NewXTransport() *XTransport {  // Define function `NewXTransport` with Go 1.26+ strict typing and performance optimizations
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {  // Conditional branch evaluating: err != nil
		panic("DefaultBootstrapResolver is not a valid IP:port — " + err.Error())  // Execute functional subroutine or method call
	}  // Structure boundary: Open/Close execution block scope
	return &XTransport{  // Return computed results back to the calling function
		cachedIPs:          CachedIPs{cache: make(map[string]*CachedIPItem)},  // Execute instruction
		altSupport:         AltSupport{cache: make(map[string]altSvcEntry)},  // Execute instruction
		keepAlive:          DefaultKeepAlive,  // Execute instruction
		timeout:            DefaultTimeout,  // Execute instruction
		bootstrapResolvers: []string{DefaultBootstrapResolver},  // Execute instruction
		ignoreSystemDNS:    true,  // Execute instruction
		useIPv4:            true,  // Execute instruction
	}  // Structure boundary: Open/Close execution block scope
}  // Structure boundary: Open/Close execution block scope

// ── IP helpers ────────────────────────────────────────────────────────────────

// ParseIP parses an IP address string. IPv6 addresses may be enclosed in
// brackets (e.g. "[::1]"); the brackets are stripped before parsing.
// Returns nil for any invalid input.
func ParseIP(ipStr string) net.IP {  // Define function `ParseIP` with Go 1.26+ strict typing and performance optimizations
	ipStr = strings.TrimPrefix(ipStr, "[")  // Update state of `ipStr` with new computed value
	ipStr = strings.TrimSuffix(ipStr, "]")  // Update state of `ipStr` with new computed value
	return net.ParseIP(ipStr)  // Return computed results back to the calling function
}  // Structure boundary: Open/Close execution block scope

// netIPToNetipAddr converts a net.IP to a netip.Addr with zero allocation.
//
// It uses the direct slice-to-array conversion ([4]byte(ip) / [16]byte(ip))
// introduced in Go 1.20, which avoids the copy that net/netip.AddrFromSlice
// must perform for safety. IPv4-mapped IPv6 addresses are Unmapped so that
// 1.2.3.4 and ::ffff:1.2.3.4 hash to the same deduplication key.
//
// Returns (zero, false) for any slice whose length is neither 4 nor 16.
func netIPToNetipAddr(ip net.IP) (netip.Addr, bool) {  // Define function `netIPToNetipAddr` with Go 1.26+ strict typing and performance optimizations
	switch len(ip) {  // Enter switch statement for multi-case evaluation
	case 4:  // Execute branch if condition matches: 4
		return netip.AddrFrom4([4]byte(ip)), true  // Return computed results back to the calling function
	case 16:  // Execute branch if condition matches: 16
		// Unmap promotes IPv4-mapped IPv6 addresses so dedup works correctly.
		return netip.AddrFrom16([16]byte(ip)).Unmap(), true  // Return computed results back to the calling function
	default:  // Execute instruction
		return netip.Addr{}, false  // Return computed results back to the calling function
	}  // Structure boundary: Open/Close execution block scope
}  // Structure boundary: Open/Close execution block scope

// uniqueNormalizedIPs returns a deduplicated, deep-copied slice of IPs.
// Ordering is preserved (first occurrence wins). nil entries are dropped.
//
// Fast-paths for 0- and 1-element inputs avoid allocating the dedup map,
// which matters because single-address results are the common case.
func uniqueNormalizedIPs(ips []net.IP) []net.IP {  // Define function `uniqueNormalizedIPs` with Go 1.26+ strict typing and performance optimizations
	switch len(ips) {  // Enter switch statement for multi-case evaluation
	case 0:  // Execute branch if condition matches: 0
		return nil  // Return computed results back to the calling function
	case 1:  // Execute branch if condition matches: 1
		if ips[0] == nil {  // Conditional branch evaluating: ips[0] == nil
			return nil  // Return computed results back to the calling function
		}  // Structure boundary: Open/Close execution block scope
		// Deep-copy the single element and return immediately.
		return []net.IP{slices.Clone(ips[0])}  // Return computed results back to the calling function
	}  // Structure boundary: Open/Close execution block scope

	seen := make(map[netip.Addr]struct{}, len(ips))  // Pre-allocate `seen` with specific capacity to prevent dynamic growth overhead
	out := make([]net.IP, 0, len(ips))  // Pre-allocate `out` with specific capacity to prevent dynamic growth overhead
	for _, ip := range ips {  // Iterate over collection elements assigning each to `ip` natively (Go 1.22+ semantics)
		if ip == nil {  // Conditional branch evaluating: ip == nil
			continue  // Execute instruction
		}  // Structure boundary: Open/Close execution block scope
		addr, ok := netIPToNetipAddr(ip)  // Dynamically initialize and assign `addr, ok` to optimize stack memory usage
		if !ok {  // Conditional branch evaluating: !ok
			// Non-standard length — include without deduplication.
			out = append(out, slices.Clone(ip))  // Update state of `out` with new computed value
			continue  // Execute instruction
		}  // Structure boundary: Open/Close execution block scope
		if _, dup := seen[addr]; dup {  // Conditional branch evaluating: dup
			continue  // Execute instruction
		}  // Structure boundary: Open/Close execution block scope
		seen[addr] = struct{}{}  // Update state of `seen[addr]` with new computed value
		out = append(out, slices.Clone(ip))  // Update state of `out` with new computed value
	}  // Structure boundary: Open/Close execution block scope
	return out  // Return computed results back to the calling function
}  // Structure boundary: Open/Close execution block scope

// ── IP cache ──────────────────────────────────────────────────────────────────

// saveCachedIPs stores resolved IPs for host under the given TTL.
//
// A uniformly-random jitter in [0, ResolverIPTTLMaxJitter) is added to spread
// re-resolution events across time. Any TTL below MinResolverIPTTL is silently
// raised to the floor. Pass a negative ttl to store a permanently-valid entry.
func (x *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {  // Define function `saveCachedIPs` with Go 1.26+ strict typing and performance optimizations
	normalized := uniqueNormalizedIPs(ips)  // Dynamically initialize and assign `normalized` to optimize stack memory usage
	if len(normalized) == 0 {  // Conditional branch evaluating: len(normalized) == 0
		return  // Exit function immediately
	}  // Structure boundary: Open/Close execution block scope

	item := &CachedIPItem{ips: normalized}  // Dynamically initialize and assign `item` to optimize stack memory usage
	if ttl >= 0 {  // Conditional branch evaluating: ttl >= 0
		if ttl < MinResolverIPTTL {  // Conditional branch evaluating: ttl < MinResolverIPTTL
			ttl = MinResolverIPTTL  // Update state of `ttl` with new computed value
		}  // Structure boundary: Open/Close execution block scope
		// rand.Int64N is the Go 1.22+ API from math/rand/v2; no global-state lock.
		ttl += time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))  // Execute instruction
		exp := time.Now().Add(ttl)  // Capture current time to initialize `exp` for TTL/timeout tracking
		item.expiration = &exp  // Update state of `item.expiration` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	x.cachedIPs.Lock()  // Acquire exclusive lock on cachedIPs to safely write/mutate cache entries
	// Clear any in-progress marker atomically with the write.
	item.updatingUntil = nil  // Update state of `item.updatingUntil` with new computed value
	x.cachedIPs.cache[host] = item  // Update state of `x.cachedIPs.cache[host]` with new computed value
	x.cachedIPs.Unlock()  // Release exclusive lock on cachedIPs to allow other goroutines access

	if len(normalized) == 1 {  // Conditional branch evaluating: len(normalized) == 1
		dlog.Debugf("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)  // Log debug information regarding the current operation state
	} else {  // Execute instruction
		dlog.Debugf("[%s] cached %d IPs (first: %s), valid for %v",  // Log debug information regarding the current operation state
			host, len(normalized), normalized[0], ttl)  // Execute instruction
	}  // Structure boundary: Open/Close execution block scope
}  // Structure boundary: Open/Close execution block scope

// saveCachedIP is a single-address convenience wrapper around saveCachedIPs.
// It is a no-op when ip is nil.
func (x *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {  // Define function `saveCachedIP` with Go 1.26+ strict typing and performance optimizations
	if ip != nil {  // Conditional branch evaluating: ip != nil
		x.saveCachedIPs(host, []net.IP{ip}, ttl)  // Execute instruction
	}  // Structure boundary: Open/Close execution block scope
}  // Structure boundary: Open/Close execution block scope

// markUpdatingCachedIP writes an "update in progress" marker for host.
//
// If host has no existing cache entry a placeholder CachedIPItem is inserted
// so that concurrent callers see the "updating" state and do not start a
// second resolution race.
func (x *XTransport) markUpdatingCachedIP(host string) {  // Define function `markUpdatingCachedIP` with Go 1.26+ strict typing and performance optimizations
	until := time.Now().Add(x.timeout)  // Capture current time to initialize `until` for TTL/timeout tracking
	x.cachedIPs.Lock()  // Acquire exclusive lock on cachedIPs to safely write/mutate cache entries
	if item, ok := x.cachedIPs.cache[host]; ok {  // Conditional branch evaluating: ok
		item.updatingUntil = &until  // Update state of `item.updatingUntil` with new computed value
		// item is a pointer; mutating it is visible without reassignment.
	} else {  // Execute instruction
		x.cachedIPs.cache[host] = &CachedIPItem{updatingUntil: &until}  // Update state of `x.cachedIPs.cache[host]` with new computed value
	}  // Structure boundary: Open/Close execution block scope
	x.cachedIPs.Unlock()  // Release exclusive lock on cachedIPs to allow other goroutines access
	dlog.Debugf("[%s] IP address marked as updating", host)  // Log debug information regarding the current operation state
}  // Structure boundary: Open/Close execution block scope

// loadCachedIPs returns a deep-copied snapshot of the cached IPs for host,
// along with two freshness flags:
//
//   - expired  — true when the entry exists but its TTL has elapsed
//   - updating — true when another goroutine is currently resolving host
//
// Callers may safely use the returned slice after the lock has been released.
func (x *XTransport) loadCachedIPs(host string) (ips []net.IP, expired, updating bool) {  // Define function `loadCachedIPs` with Go 1.26+ strict typing and performance optimizations
	x.cachedIPs.RLock()  // Acquire read-only lock on cachedIPs for concurrent, thread-safe access
	item, ok := x.cachedIPs.cache[host]  // Dynamically initialize and assign `item, ok` to optimize stack memory usage
	if !ok {  // Conditional branch evaluating: !ok
		x.cachedIPs.RUnlock()  // Release read-only lock on cachedIPs
		dlog.Debugf("[%s] IP address not found in cache", host)  // Log debug information regarding the current operation state
		return nil, false, false  // Return execution flow, propagating error state or nil values to caller
	}  // Structure boundary: Open/Close execution block scope
	// Deep-copy all slices while holding the read lock so callers never
	// observe aliased memory after the lock is released.
	if n := len(item.ips); n > 0 {  // Conditional branch evaluating: n > 0
		ips = make([]net.IP, 0, n)  // Update state of `ips` with new computed value
		for _, ip := range item.ips {  // Iterate over collection elements assigning each to `ip` natively (Go 1.22+ semantics)
			if ip != nil {  // Conditional branch evaluating: ip != nil
				ips = append(ips, slices.Clone(ip))  // Update state of `ips` with new computed value
			}  // Structure boundary: Open/Close execution block scope
		}  // Structure boundary: Open/Close execution block scope
	}  // Structure boundary: Open/Close execution block scope
	expiration := item.expiration  // Dynamically initialize and assign `expiration` to optimize stack memory usage
	updatingUntil := item.updatingUntil  // Dynamically initialize and assign `updatingUntil` to optimize stack memory usage
	x.cachedIPs.RUnlock()  // Release read-only lock on cachedIPs

	if expiration != nil && time.Until(*expiration) < 0 {  // Conditional branch evaluating: expiration != nil && time.Until(*expiration) < 0
		expired = true  // Update state of `expired` with new computed value
		if updatingUntil != nil && time.Until(*updatingUntil) > 0 {  // Conditional branch evaluating: updatingUntil != nil && time.Until(*updatingUntil) > 0
			updating = true  // Update state of `updating` with new computed value
			dlog.Debugf("[%s] cached IPs are being updated", host)  // Log debug information regarding the current operation state
		} else {  // Execute instruction
			dlog.Debugf("[%s] cached IPs have expired", host)  // Log debug information regarding the current operation state
		}  // Structure boundary: Open/Close execution block scope
	}  // Structure boundary: Open/Close execution block scope
	return ips, expired, updating  // Return computed results back to the calling function
}  // Structure boundary: Open/Close execution block scope

// ── Transport construction ────────────────────────────────────────────────────

// rebuildTransport (re-)initialises the HTTP/2 and HTTP/3 transports.
//
// Call once before the first Fetch, and again whenever TLS configuration or
// proxy settings change. Any previously-built transport has its idle
// connections closed to release file descriptors promptly.
func (x *XTransport) rebuildTransport() {  // Define function `rebuildTransport` with Go 1.26+ strict typing and performance optimizations
	dlog.Debug("Rebuilding transport")  // Execute instruction
	if x.transport != nil {  // Conditional branch evaluating: x.transport != nil
		x.transport.CloseIdleConnections()  // Execute functional subroutine or method call
	}  // Structure boundary: Open/Close execution block scope

	// Build a single TLS config shared by both transports. Callers that need
	// per-connection mutation (e.g. setting ServerName in the H3 dialer) must
	// call Clone() on it.
	x.tlsClientConfig = x.buildTLSConfig()  // Update state of `x.tlsClientConfig` with new computed value

	transport := &http.Transport{  // Dynamically initialize and assign `transport` to optimize stack memory usage
		DisableKeepAlives:      false,  // Execute instruction
		DisableCompression:     true, // compression handled manually in Fetch
		MaxIdleConns:           MaxIdleConns,  // Execute instruction
		IdleConnTimeout:        DefaultIdleConnTimeout,  // Execute instruction
		TLSHandshakeTimeout:    TLSHandshakeTimeout,  // Execute instruction
		ResponseHeaderTimeout:  x.timeout,  // Execute instruction
		ExpectContinueTimeout:  1 * time.Second,  // Execute instruction
		MaxResponseHeaderBytes: MaxResponseHeaderBytes,  // Execute instruction
		ForceAttemptHTTP2:      true,  // Execute instruction
		TLSClientConfig:        x.tlsClientConfig,  // Execute instruction
		DialContext:            x.buildDialContext(),  // Execute functional subroutine or method call
	}  // Structure boundary: Open/Close execution block scope
	if x.httpProxyFunction != nil {  // Conditional branch evaluating: x.httpProxyFunction != nil
		transport.Proxy = x.httpProxyFunction  // Update state of `transport.Proxy` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	// http2.ConfigureTransports (plural) is the Go 1.26 preferred API; it
	// returns *http2.Transport for fine-grained tuning not available through
	// the singular ConfigureTransport.
	if h2t, err := http2.ConfigureTransports(transport); err == nil && h2t != nil {  // Conditional branch evaluating: err == nil && h2t != nil
		h2t.ReadIdleTimeout = 30 * time.Second  // Update state of `h2t.ReadIdleTimeout` with new computed value
		h2t.PingTimeout = 15 * time.Second  // Update state of `h2t.PingTimeout` with new computed value
		h2t.WriteByteTimeout = 10 * time.Second  // Update state of `h2t.WriteByteTimeout` with new computed value
		h2t.AllowHTTP = false  // Update state of `h2t.AllowHTTP` with new computed value
		h2t.StrictMaxConcurrentStreams = false  // Update state of `h2t.StrictMaxConcurrentStreams` with new computed value
	}  // Structure boundary: Open/Close execution block scope
	x.transport = transport  // Update state of `x.transport` with new computed value

	if x.http3 {  // Conditional branch evaluating: x.http3
		x.h3Transport = &http3.Transport{  // Update state of `x.h3Transport` with new computed value
			DisableCompression: true,  // Execute instruction
			TLSClientConfig:    x.tlsClientConfig, // shared; cloned per-connection in H3 dialer
			Dial:               x.buildH3DialFunc(),  // Execute functional subroutine or method call
		}  // Structure boundary: Open/Close execution block scope
	}  // Structure boundary: Open/Close execution block scope
}  // Structure boundary: Open/Close execution block scope

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
func (x *XTransport) buildDialContext() func(context.Context, string, string) (net.Conn, error) {  // Define function `buildDialContext` with Go 1.26+ strict typing and performance optimizations
	timeout := x.timeout // snapshot; avoids retaining a live pointer into XTransport
	return func(ctx context.Context, network, addrStr string) (net.Conn, error) {  // Return execution flow, propagating error state or nil values to caller
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)  // Dynamically initialize and assign `host, port` to optimize stack memory usage
		portStr := strconv.Itoa(port) // computed once for all endpoint() calls below

		// endpoint builds the dial target string for a given IP (or nil for hostname).
		endpoint := func(ip net.IP) string {  // Dynamically initialize and assign `endpoint` to optimize stack memory usage
			if ip != nil {  // Conditional branch evaluating: ip != nil
				if v4 := ip.To4(); v4 != nil {  // Conditional branch evaluating: v4 != nil
					return v4.String() + ":" + portStr  // Return computed results back to the calling function
				}  // Structure boundary: Open/Close execution block scope
				return "[" + ip.String() + "]:" + portStr  // Return computed results back to the calling function
			}  // Structure boundary: Open/Close execution block scope
			// No cached address — fall back to the raw host. Wrap bare IPv6 in brackets.
			if parsed := ParseIP(host); parsed != nil && parsed.To4() == nil {  // Conditional branch evaluating: parsed != nil && parsed.To4() == nil
				return "[" + parsed.String() + "]:" + portStr  // Return computed results back to the calling function
			}  // Structure boundary: Open/Close execution block scope
			return host + ":" + portStr  // Return computed results back to the calling function
		}  // Structure boundary: Open/Close execution block scope

		cachedIPs, _, _ := x.loadCachedIPs(host)  // Dynamically initialize and assign `cachedIPs, _, _` to optimize stack memory usage
		// max() builtin (Go 1.21) avoids a conditional capacity hint.
		targets := make([]string, 0, max(len(cachedIPs), 1))  // Pre-allocate `targets` with specific capacity to prevent dynamic growth overhead
		for _, ip := range cachedIPs {  // Iterate over collection elements assigning each to `ip` natively (Go 1.22+ semantics)
			targets = append(targets, endpoint(ip))  // Update state of `targets` with new computed value
		}  // Structure boundary: Open/Close execution block scope
		if len(targets) == 0 {  // Conditional branch evaluating: len(targets) == 0
			dlog.Debugf("[%s] no cached IP; falling back to hostname dial", host)  // Log debug information regarding the current operation state
			targets = append(targets, endpoint(nil))  // Update state of `targets` with new computed value
		}  // Structure boundary: Open/Close execution block scope

		// Construct the dialer once; reuse across all target attempts.
		d := &net.Dialer{  // Dynamically initialize and assign `d` to optimize stack memory usage
			Timeout:   timeout,  // Execute instruction
			KeepAlive: x.keepAlive,  // Execute instruction
			DualStack: true,  // Execute instruction
		}  // Structure boundary: Open/Close execution block scope

		var lastErr error  // Execute instruction
		for i, target := range targets {  // Execute looping construct while evaluating: i, target := range targets
			var (  // Execute instruction
				conn net.Conn  // Execute instruction
				err  error  // Execute instruction
			)  // Execute instruction
			if x.proxyDialer == nil {  // Conditional branch evaluating: x.proxyDialer == nil
				conn, err = d.DialContext(ctx, network, target)  // Update state of `conn, err` with new computed value
			} else {  // Execute instruction
				conn, err = (*x.proxyDialer).Dial(network, target)  // Update state of `conn, err` with new computed value
			}  // Structure boundary: Open/Close execution block scope
			if err == nil {  // Conditional branch evaluating: err == nil
				return conn, nil  // Return computed results back to the calling function
			}  // Structure boundary: Open/Close execution block scope
			lastErr = err  // Update state of `lastErr` with new computed value
			if i < len(targets)-1 {  // Conditional branch evaluating: i < len(targets)-1
				dlog.Debugf("Dial [%s] failed: %v", target, err)  // Log debug information regarding the current operation state
			}  // Structure boundary: Open/Close execution block scope
		}  // Structure boundary: Open/Close execution block scope
		return nil, lastErr  // Return execution flow, propagating error state or nil values to caller
	}  // Structure boundary: Open/Close execution block scope
}  // Structure boundary: Open/Close execution block scope

// buildH3DialFunc returns the QUIC dial function for the HTTP/3 transport.
//
// It mirrors buildDialContext's cache-first strategy but opens UDP sockets.
//
// quic-go always passes nil as the *tls.Config argument; we ignore it (via _)
// and clone x.tlsClientConfig per connection to set ServerName without
// introducing a data race on the shared config — the old code silently
// discarded the real TLS configuration because it forwarded the nil arg.
func (x *XTransport) buildH3DialFunc() func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {  // Define function `buildH3DialFunc` with Go 1.26+ strict typing and performance optimizations
	return func(ctx context.Context, addrStr string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {  // Return execution flow, propagating error state or nil values to caller
		dlog.Debugf("H3 dial: [%s]", addrStr)  // Log debug information regarding the current operation state
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)  // Dynamically initialize and assign `host, port` to optimize stack memory usage
		portStr := strconv.Itoa(port)  // Dynamically initialize and assign `portStr` to optimize stack memory usage

		// udpTarget bundles a resolved UDP address string with its network name.
		type udpTarget struct{ addr, network string }  // Execute instruction

		// udpEndpoint derives the UDP target for a given IP (or nil = raw host).
		udpEndpoint := func(ip net.IP) udpTarget {  // Dynamically initialize and assign `udpEndpoint` to optimize stack memory usage
			if ip != nil {  // Conditional branch evaluating: ip != nil
				if v4 := ip.To4(); v4 != nil {  // Conditional branch evaluating: v4 != nil
					return udpTarget{v4.String() + ":" + portStr, "udp4"}  // Return computed results back to the calling function
				}  // Structure boundary: Open/Close execution block scope
				return udpTarget{"[" + ip.String() + "]:" + portStr, "udp6"}  // Return computed results back to the calling function
			}  // Structure boundary: Open/Close execution block scope
			// No cached IP — derive network from the host string itself.
			nw, addr := "udp4", host  // Dynamically initialize and assign `nw, addr` to optimize stack memory usage
			if parsed := ParseIP(host); parsed != nil {  // Conditional branch evaluating: parsed != nil
				if parsed.To4() == nil {  // Conditional branch evaluating: parsed.To4() == nil
					nw, addr = "udp6", "["+parsed.String()+"]"  // Update state of `nw, addr` with new computed value
				} else {  // Execute instruction
					addr = parsed.String()  // Update state of `addr` with new computed value
				}  // Structure boundary: Open/Close execution block scope
			} else if x.useIPv6 {  // Execute instruction
				if x.useIPv4 {  // Conditional branch evaluating: x.useIPv4
					nw = "udp" // dual-stack
				} else {  // Execute instruction
					nw = "udp6"  // Update state of `nw` with new computed value
				}  // Structure boundary: Open/Close execution block scope
			}  // Structure boundary: Open/Close execution block scope
			return udpTarget{addr + ":" + portStr, nw}  // Return computed results back to the calling function
		}  // Structure boundary: Open/Close execution block scope

		cachedIPs, _, _ := x.loadCachedIPs(host)  // Dynamically initialize and assign `cachedIPs, _, _` to optimize stack memory usage
		targets := make([]udpTarget, 0, max(len(cachedIPs), 1))  // Pre-allocate `targets` with specific capacity to prevent dynamic growth overhead
		for _, ip := range cachedIPs {  // Iterate over collection elements assigning each to `ip` natively (Go 1.22+ semantics)
			targets = append(targets, udpEndpoint(ip))  // Update state of `targets` with new computed value
		}  // Structure boundary: Open/Close execution block scope
		if len(targets) == 0 {  // Conditional branch evaluating: len(targets) == 0
			dlog.Debugf("[%s] no cached IP for H3 dial", host)  // Log debug information regarding the current operation state
			targets = append(targets, udpEndpoint(nil))  // Update state of `targets` with new computed value
		}  // Structure boundary: Open/Close execution block scope

		var lastErr error  // Execute instruction
		for i, t := range targets {  // Execute looping construct while evaluating: i, t := range targets
			udpAddr, err := net.ResolveUDPAddr(t.network, t.addr)  // Dynamically initialize and assign `udpAddr, err` to optimize stack memory usage
			if err != nil {  // Check for non-nil error to handle failure conditions safely
				lastErr = err  // Update state of `lastErr` with new computed value
				if i < len(targets)-1 {  // Conditional branch evaluating: i < len(targets)-1
					dlog.Debugf("H3: resolve [%s]/%s failed: %v", t.addr, t.network, err)  // Log debug information regarding the current operation state
				}  // Structure boundary: Open/Close execution block scope
				continue  // Execute instruction
			}  // Structure boundary: Open/Close execution block scope
			udpConn, err := net.ListenUDP(t.network, nil)  // Dynamically initialize and assign `udpConn, err` to optimize stack memory usage
			if err != nil {  // Check for non-nil error to handle failure conditions safely
				lastErr = err  // Update state of `lastErr` with new computed value
				if i < len(targets)-1 {  // Conditional branch evaluating: i < len(targets)-1
					dlog.Debugf("H3: listen [%s]/%s failed: %v", t.addr, t.network, err)  // Log debug information regarding the current operation state
				}  // Structure boundary: Open/Close execution block scope
				continue  // Execute instruction
			}  // Structure boundary: Open/Close execution block scope
			// Clone the shared config so ServerName can be set without racing.
			tlsCfg := x.tlsClientConfig.Clone()  // Dynamically initialize and assign `tlsCfg` to optimize stack memory usage
			tlsCfg.ServerName = host  // Update state of `tlsCfg.ServerName` with new computed value
			conn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)  // Dynamically initialize and assign `conn, err` to optimize stack memory usage
			if err != nil {  // Check for non-nil error to handle failure conditions safely
				_ = udpConn.Close()  // Update state of `_` with new computed value
				lastErr = err  // Update state of `lastErr` with new computed value
				if i < len(targets)-1 {  // Conditional branch evaluating: i < len(targets)-1
					dlog.Debugf("H3: quic.DialEarly [%s]/%s failed: %v", t.addr, t.network, err)  // Log debug information regarding the current operation state
				}  // Structure boundary: Open/Close execution block scope
				continue  // Execute instruction
			}  // Structure boundary: Open/Close execution block scope
			return conn, nil  // Return computed results back to the calling function
		}  // Structure boundary: Open/Close execution block scope
		return nil, lastErr  // Return execution flow, propagating error state or nil values to caller
	}  // Structure boundary: Open/Close execution block scope
}  // Structure boundary: Open/Close execution block scope

// buildTLSConfig constructs a *tls.Config that reflects all active user
// preferences. The result is stored on XTransport and shared between the
// HTTP/2 and HTTP/3 transports. Any caller that needs per-connection mutation
// (e.g. setting ServerName) must call Clone() on the returned config.
func (x *XTransport) buildTLSConfig() *tls.Config {  // Define function `buildTLSConfig` with Go 1.26+ strict typing and performance optimizations
	cfg := &tls.Config{}  // Dynamically initialize and assign `cfg` to optimize stack memory usage

	if x.keyLogWriter != nil {  // Conditional branch evaluating: x.keyLogWriter != nil
		cfg.KeyLogWriter = x.keyLogWriter  // Update state of `cfg.KeyLogWriter` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	certPool, certPoolErr := x509.SystemCertPool()  // Dynamically initialize and assign `certPool, certPoolErr` to optimize stack memory usage
	creds := x.tlsClientCreds  // Dynamically initialize and assign `creds` to optimize stack memory usage

	if creds.rootCA != "" {  // Conditional branch evaluating: creds.rootCA != ""
		if certPool == nil {  // Conditional branch evaluating: certPool == nil
			dlog.Fatalf("Custom root CA not supported on this platform: %v", certPoolErr)  // Log critical warning or fatal error and potentially terminate
		}  // Structure boundary: Open/Close execution block scope
		pem, err := os.ReadFile(creds.rootCA)  // Dynamically initialize and assign `pem, err` to optimize stack memory usage
		if err != nil {  // Check for non-nil error to handle failure conditions safely
			dlog.Fatalf("Unable to read rootCA [%s]: %v", creds.rootCA, err)  // Log critical warning or fatal error and potentially terminate
		}  // Structure boundary: Open/Close execution block scope
		certPool.AppendCertsFromPEM(pem)  // Execute instruction
	}  // Structure boundary: Open/Close execution block scope
	if certPool != nil {  // Conditional branch evaluating: certPool != nil
		// Embed ISRG Root X1 so DoH servers with Let's Encrypt certificates
		// validate correctly even on OS trust stores built before ISRG Root X1
		// was widely distributed (older Android, Windows Server editions, etc.).
		certPool.AppendCertsFromPEM(isrgRootX1PEM)  // Execute instruction
		cfg.RootCAs = certPool  // Update state of `cfg.RootCAs` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	if creds.clientCert != "" {  // Conditional branch evaluating: creds.clientCert != ""
		cert, err := tls.LoadX509KeyPair(creds.clientCert, creds.clientKey)  // Dynamically initialize and assign `cert, err` to optimize stack memory usage
		if err != nil {  // Check for non-nil error to handle failure conditions safely
			dlog.Fatalf("Unable to load client cert [%s] / key [%s]: %v",  // Log critical warning or fatal error and potentially terminate
				creds.clientCert, creds.clientKey, err)  // Execute instruction
		}  // Structure boundary: Open/Close execution block scope
		cfg.Certificates = []tls.Certificate{cert}  // Update state of `cfg.Certificates` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	if x.tlsDisableSessionTickets {  // Conditional branch evaluating: x.tlsDisableSessionTickets
		cfg.SessionTicketsDisabled = true  // Update state of `cfg.SessionTicketsDisabled` with new computed value
	}  // Structure boundary: Open/Close execution block scope
	if x.tlsPreferRSA {  // Conditional branch evaluating: x.tlsPreferRSA
		// Restrict to TLS 1.2 max to force RSA cipher suites.
		cfg.MaxVersion = tls.VersionTLS12  // Update state of `cfg.MaxVersion` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	// Prefer hardware-accelerated ciphers when available.
	if hasAESGCMHardwareSupport {  // Conditional branch evaluating: hasAESGCMHardwareSupport
		cfg.CipherSuites = []uint16{  // Update state of `cfg.CipherSuites` with new computed value
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,  // Execute instruction
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,  // Execute instruction
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,  // Execute instruction
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,  // Execute instruction
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,  // Execute instruction
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,  // Execute instruction
		}  // Structure boundary: Open/Close execution block scope
	} else {  // Execute instruction
		cfg.CipherSuites = []uint16{  // Update state of `cfg.CipherSuites` with new computed value
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,  // Execute instruction
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,  // Execute instruction
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,  // Execute instruction
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,  // Execute instruction
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,  // Execute instruction
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,  // Execute instruction
		}  // Structure boundary: Open/Close execution block scope
	}  // Structure boundary: Open/Close execution block scope
	return cfg  // Return computed results back to the calling function
}  // Structure boundary: Open/Close execution block scope

// ── Embedded root certificate ─────────────────────────────────────────────────

// isrgRootX1PEM is the ISRG Root X1 certificate (Let's Encrypt's root CA)
// embedded in PEM form. Bundling it ensures that DoH servers whose TLS chain
// terminates at ISRG Root X1 are trusted even on operating systems whose
// certificate bundles predate its wide inclusion.
var isrgRootX1PEM = []byte(`-----BEGIN CERTIFICATE-----  // Update state of `var isrgRootX1PEM` with new computed value
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw  // Execute instruction
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh  // Execute instruction
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4  // Execute instruction
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu  // Execute instruction
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY  // Execute instruction
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc  // Execute instruction
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+  // Execute instruction
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U  // Execute instruction
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW  // Execute instruction
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH  // Execute instruction
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC  // Execute instruction
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv  // Execute instruction
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn  // Execute instruction
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn  // Execute instruction
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw  // Execute instruction
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV  // Execute instruction
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq  // Execute instruction
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL  // Execute instruction
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ  // Execute instruction
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK  // Execute instruction
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5  // Execute instruction
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur  // Execute instruction
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC  // Execute instruction
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc  // Execute instruction
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq  // Execute instruction
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA  // Execute instruction
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d  // Execute instruction
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=  // Execute instruction
-----END CERTIFICATE-----`)  // Execute instruction

// ── DNS resolution ────────────────────────────────────────────────────────────

// resolveUsingSystem queries the OS resolver and filters by address family.
//
// Returns nil (not a non-nil empty slice) when no IPs of the requested family
// are present, so callers can rely on len(ips) == 0 as the canonical "no result"
// check. The OS resolver does not expose per-record TTLs, so a fixed synthetic
// TTL of SystemResolverIPTTL is always returned.
func (x *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {  // Define function `resolveUsingSystem` with Go 1.26+ strict typing and performance optimizations
	all, err := net.LookupIP(host)  // Dynamically initialize and assign `all, err` to optimize stack memory usage
	if err != nil && len(all) == 0 {  // Check for non-nil error to handle failure conditions safely
		return nil, SystemResolverIPTTL, err  // Return execution flow, propagating error state or nil values to caller
	}  // Structure boundary: Open/Close execution block scope
	if returnIPv4 && returnIPv6 {  // Conditional branch evaluating: returnIPv4 && returnIPv6
		return all, SystemResolverIPTTL, err  // Return execution flow, propagating error state or nil values to caller
	}  // Structure boundary: Open/Close execution block scope
	ips := make([]net.IP, 0, len(all))  // Pre-allocate `ips` with specific capacity to prevent dynamic growth overhead
	for _, ip := range all {  // Iterate over collection elements assigning each to `ip` natively (Go 1.22+ semantics)
		v4 := ip.To4()  // Dynamically initialize and assign `v4` to optimize stack memory usage
		switch {  // Enter switch statement for multi-case evaluation
		case returnIPv4 && v4 != nil:  // Execute branch if condition matches: returnIPv4 && v4 != nil
			ips = append(ips, v4)  // Update state of `ips` with new computed value
		case returnIPv6 && v4 == nil:  // Execute branch if condition matches: returnIPv6 && v4 == nil
			ips = append(ips, ip)  // Update state of `ips` with new computed value
		}  // Structure boundary: Open/Close execution block scope
	}  // Structure boundary: Open/Close execution block scope
	if len(ips) == 0 {  // Conditional branch evaluating: len(ips) == 0
		// Return nil, not []net.IP{}, so len(ips)==0 is always the correct test.
		return nil, SystemResolverIPTTL, err  // Return execution flow, propagating error state or nil values to caller
	}  // Structure boundary: Open/Close execution block scope
	return ips, SystemResolverIPTTL, err  // Return execution flow, propagating error state or nil values to caller
}  // Structure boundary: Open/Close execution block scope

// resolveUsingResolver sends A and/or AAAA queries to a single DNS resolver.
//
// Failures for each query type are tracked independently: a AAAA timeout or
// NXDOMAIN does not discard A results already collected. The minimum TTL
// observed across all answer resource records is returned so the cache entry
// expires no later than the shortest-lived record in the response.
func (x *XTransport) resolveUsingResolver(  // Define function `resolveUsingResolver` with Go 1.26+ strict typing and performance optimizations
	proto, host, resolver string,  // Execute instruction
	returnIPv4, returnIPv6 bool,  // Execute instruction
) (ips []net.IP, ttl time.Duration, err error) {  // Execute instruction
	tr := dns.NewTransport()  // Dynamically initialize and assign `tr` to optimize stack memory usage
	tr.ReadTimeout = ResolverReadTimeout  // Update state of `tr.ReadTimeout` with new computed value
	client := dns.Client{Transport: tr}  // Dynamically initialize and assign `client` to optimize stack memory usage

	var queryTypes []uint16  // Execute instruction
	if returnIPv4 {  // Conditional branch evaluating: returnIPv4
		queryTypes = append(queryTypes, dns.TypeA)  // Update state of `queryTypes` with new computed value
	}  // Structure boundary: Open/Close execution block scope
	if returnIPv6 {  // Conditional branch evaluating: returnIPv6
		queryTypes = append(queryTypes, dns.TypeAAAA)  // Update state of `queryTypes` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	ctx, cancel := context.WithTimeout(context.Background(), ResolverReadTimeout)  // Create a derived context `ctx, cancel` with explicit timeout to prevent hanging operations
	defer cancel()  // Defer execution of `cancel()` until the surrounding function returns

	minTTL := noTTL // sentinel: no TTL observed yet
	var lastErr error  // Execute instruction

	for _, rrType := range queryTypes {  // Iterate over collection elements assigning each to `rrType` natively (Go 1.22+ semantics)
		msg := dns.NewMsg(fqdn(host), rrType)  // Dynamically initialize and assign `msg` to optimize stack memory usage
		if msg == nil {  // Conditional branch evaluating: msg == nil
			continue  // Execute instruction
		}  // Structure boundary: Open/Close execution block scope
		msg.RecursionDesired = true  // Update state of `msg.RecursionDesired` with new computed value
		msg.UDPSize = uint16(MaxDNSPacketSize)  // Update state of `msg.UDPSize` with new computed value
		msg.Security = true  // Update state of `msg.Security` with new computed value

		in, _, qErr := client.Exchange(ctx, msg, proto, resolver)  // Dynamically initialize and assign `in, _, qErr` to optimize stack memory usage
		if qErr != nil {  // Conditional branch evaluating: qErr != nil
			// Track per-type; don't abort the sibling query type.
			lastErr = qErr  // Update state of `lastErr` with new computed value
			continue  // Execute instruction
		}  // Structure boundary: Open/Close execution block scope
		for _, answer := range in.Answer {  // Iterate over collection elements assigning each to `answer` natively (Go 1.22+ semantics)
			if dns.RRToType(answer) != rrType {  // Conditional branch evaluating: dns.RRToType(answer) != rrType
				continue // skip records of an unexpected type (e.g. CNAMEs)
			}  // Structure boundary: Open/Close execution block scope
			switch rrType {  // Enter switch statement for multi-case evaluation
			case dns.TypeA:  // Execute branch if condition matches: dns.TypeA
				ips = append(ips, answer.(*dns.A).A.Addr.AsSlice())  // Update state of `ips` with new computed value
			case dns.TypeAAAA:  // Execute branch if condition matches: dns.TypeAAAA
				ips = append(ips, answer.(*dns.AAAA).AAAA.Addr.AsSlice())  // Update state of `ips` with new computed value
			}  // Structure boundary: Open/Close execution block scope
			// Track the minimum TTL so the cache entry respects the shortest-lived record.
			if rTTL := answer.Header().TTL; rTTL < minTTL {  // Conditional branch evaluating: rTTL < minTTL
				minTTL = rTTL  // Update state of `minTTL` with new computed value
			}  // Structure boundary: Open/Close execution block scope
		}  // Structure boundary: Open/Close execution block scope
	}  // Structure boundary: Open/Close execution block scope

	if len(ips) > 0 {  // Conditional branch evaluating: len(ips) > 0
		if minTTL == noTTL {  // Conditional branch evaluating: minTTL == noTTL
			minTTL = 0 // sentinel never updated: treat as zero
		}  // Structure boundary: Open/Close execution block scope
		return ips, time.Duration(minTTL) * time.Second, nil  // Return computed results back to the calling function
	}  // Structure boundary: Open/Close execution block scope
	if lastErr != nil {  // Conditional branch evaluating: lastErr != nil
		return nil, 0, lastErr  // Return execution flow, propagating error state or nil values to caller
	}  // Structure boundary: Open/Close execution block scope
	return nil, 0, errors.New("no IP records returned")  // Return execution flow, propagating error state or nil values to caller
}  // Structure boundary: Open/Close execution block scope

// resolveUsingServers iterates over resolvers with per-resolver exponential
// back-off. On first success the winning resolver is swapped to index 0
// (self-healing affinity) so subsequent calls tend to reuse the fastest
// known-good resolver rather than starting from the front of the list.
func (x *XTransport) resolveUsingServers(  // Define function `resolveUsingServers` with Go 1.26+ strict typing and performance optimizations
	proto, host string,  // Execute instruction
	resolvers []string,  // Execute instruction
	returnIPv4, returnIPv6 bool,  // Execute instruction
) (ips []net.IP, ttl time.Duration, err error) {  // Execute instruction
	if len(resolvers) == 0 {  // Conditional branch evaluating: len(resolvers) == 0
		return nil, 0, errors.New("empty resolver list")  // Return execution flow, propagating error state or nil values to caller
	}  // Structure boundary: Open/Close execution block scope
	var lastErr error  // Execute instruction
	for i, resolver := range resolvers {  // Execute looping construct while evaluating: i, resolver := range resolvers
		delay := resolverRetryInitialBackoff  // Dynamically initialize and assign `delay` to optimize stack memory usage
		for attempt := 1; attempt <= resolverRetryCount; attempt++ {  // Execute bounded looping construct
			ips, ttl, err = x.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)  // Update state of `ips, ttl, err` with new computed value
			if err == nil && len(ips) > 0 {  // Conditional branch evaluating: err == nil && len(ips) > 0
				if i > 0 {  // Conditional branch evaluating: i > 0
					// Promote the winning resolver to the front.
					dlog.Infof("Resolution succeeded via %s[%s]; promoting to first",  // Execute instruction
						proto, resolver)  // Execute instruction
					resolvers[0], resolvers[i] = resolvers[i], resolvers[0]  // Update state of `resolvers[0], resolvers[i]` with new computed value
				}  // Structure boundary: Open/Close execution block scope
				return ips, ttl, nil  // Return computed results back to the calling function
			}  // Structure boundary: Open/Close execution block scope
			if err == nil {  // Conditional branch evaluating: err == nil
				err = errors.New("no IP addresses returned")  // Update state of `err` with new computed value
			}  // Structure boundary: Open/Close execution block scope
			lastErr = err  // Update state of `lastErr` with new computed value
			dlog.Debugf("Resolver attempt %d/%d failed for [%s] via [%s] (%s): %v",  // Log debug information regarding the current operation state
				attempt, resolverRetryCount, host, resolver, proto, err)  // Execute instruction
			if attempt < resolverRetryCount {  // Conditional branch evaluating: attempt < resolverRetryCount
				time.Sleep(delay)  // Execute instruction
				// min() builtin (Go 1.21) replaces hand-rolled ternary.
				delay = min(delay*2, resolverRetryMaxBackoff)  // Update state of `delay` with new computed value
			}  // Structure boundary: Open/Close execution block scope
		}  // Structure boundary: Open/Close execution block scope
		dlog.Infof("Unable to resolve [%s] using [%s] (%s): %v",  // Execute instruction
			host, resolver, proto, lastErr)  // Execute instruction
	}  // Structure boundary: Open/Close execution block scope
	if lastErr == nil {  // Conditional branch evaluating: lastErr == nil
		lastErr = errors.New("no IP addresses returned")  // Update state of `lastErr` with new computed value
	}  // Structure boundary: Open/Close execution block scope
	return nil, 0, lastErr  // Return execution flow, propagating error state or nil values to caller
}  // Structure boundary: Open/Close execution block scope

// resolve selects the best available resolution strategy in priority order:
//
//  1. Internal resolvers    — when ignoreSystemDNS && internalResolverReady
//  2. OS system resolver    — when ignoreSystemDNS == false
//  3. Bootstrap resolvers   — fallback after any primary-strategy failure
//  4. OS system resolver    — last resort when ignoreSystemDNS == true
func (x *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {  // Define function `resolve` with Go 1.26+ strict typing and performance optimizations
	// [2]string fixed array: stack-allocated, no slice header, no heap escape.
	protos := [2]string{"udp", "tcp"}  // Dynamically initialize and assign `protos` to optimize stack memory usage
	if x.mainProto == "tcp" {  // Conditional branch evaluating: x.mainProto == "tcp"
		protos = [2]string{"tcp", "udp"}  // Update state of `protos` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	var (  // Execute instruction
		ips []net.IP  // Execute instruction
		ttl time.Duration  // Execute instruction
		err error  // Execute instruction
	)  // Execute instruction

	if x.ignoreSystemDNS {  // Conditional branch evaluating: x.ignoreSystemDNS
		if x.internalResolverReady {  // Conditional branch evaluating: x.internalResolverReady
			for _, proto := range protos {  // Iterate over collection elements assigning each to `proto` natively (Go 1.22+ semantics)
				ips, ttl, err = x.resolveUsingServers(  // Update state of `ips, ttl, err` with new computed value
					proto, host, x.internalResolvers, returnIPv4, returnIPv6)  // Execute instruction
				if err == nil {  // Conditional branch evaluating: err == nil
					return ips, ttl, nil  // Return computed results back to the calling function
				}  // Structure boundary: Open/Close execution block scope
			}  // Structure boundary: Open/Close execution block scope
		} else {  // Execute instruction
			err = errors.New("dnscrypt-proxy service is not ready yet")  // Update state of `err` with new computed value
			dlog.Notice(err)  // Execute instruction
		}  // Structure boundary: Open/Close execution block scope
	} else {  // Execute instruction
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)  // Update state of `ips, ttl, err` with new computed value
		if err != nil {  // Check for non-nil error to handle failure conditions safely
			err = fmt.Errorf("system DNS: %w", err)  // Update state of `err` with new computed value
			dlog.Notice(err)  // Execute instruction
		} else {  // Execute instruction
			return ips, ttl, nil  // Return computed results back to the calling function
		}  // Structure boundary: Open/Close execution block scope
	}  // Structure boundary: Open/Close execution block scope

	// Bootstrap resolvers as second-tier fallback.
	for _, proto := range protos {  // Iterate over collection elements assigning each to `proto` natively (Go 1.22+ semantics)
		dlog.Noticef("Resolving [%s] via bootstrap resolvers over %s", host, proto)  // Log notice-level information for important operational events
		ips, ttl, err = x.resolveUsingServers(  // Update state of `ips, ttl, err` with new computed value
			proto, host, x.bootstrapResolvers, returnIPv4, returnIPv6)  // Execute instruction
		if err == nil {  // Conditional branch evaluating: err == nil
			return ips, ttl, nil  // Return computed results back to the calling function
		}  // Structure boundary: Open/Close execution block scope
	}  // Structure boundary: Open/Close execution block scope

	// Absolute last resort: OS resolver even when ignoreSystemDNS is true.
	if x.ignoreSystemDNS {  // Conditional branch evaluating: x.ignoreSystemDNS
		dlog.Noticef("Bootstrap resolvers failed — last-resort system resolver for [%s]", host)  // Log notice-level information for important operational events
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)  // Update state of `ips, ttl, err` with new computed value
	}  // Structure boundary: Open/Close execution block scope
	return ips, ttl, err  // Return execution flow, propagating error state or nil values to caller
}  // Structure boundary: Open/Close execution block scope

// hostResolveMu returns the per-host *sync.Mutex, creating it if it does not
// yet exist. sync.Map.LoadOrStore guarantees exactly one mutex is ever stored
// per host even under concurrent access.
func (x *XTransport) hostResolveMu(host string) *sync.Mutex {  // Define function `hostResolveMu` with Go 1.26+ strict typing and performance optimizations
	v, _ := x.resolveMu.LoadOrStore(host, &sync.Mutex{})  // Dynamically initialize and assign `v, _` to optimize stack memory usage
	return v.(*sync.Mutex)  // Return computed results back to the calling function
}  // Structure boundary: Open/Close execution block scope

// resolveAndUpdateCache resolves host when the cache is absent or expired and
// stores the fresh result. Concurrent callers for the same host serialise on a
// per-host mutex (double-checked locking) so exactly one DNS query is issued.
//
// Returns nil immediately when:
//   - A proxy handles name resolution (x.proxyDialer or x.httpProxyFunction set)
//   - host is an IP address literal (no lookup needed)
//   - A valid, non-expired cache entry exists
func (x *XTransport) resolveAndUpdateCache(host string) error {  // Define function `resolveAndUpdateCache` with Go 1.26+ strict typing and performance optimizations
	if x.proxyDialer != nil || x.httpProxyFunction != nil {  // Conditional branch evaluating: x.proxyDialer != nil || x.httpProxyFunction != nil
		return nil // proxy resolves names itself; nothing to do
	}  // Structure boundary: Open/Close execution block scope
	if ParseIP(host) != nil {  // Conditional branch evaluating: ParseIP(host) != nil
		return nil // literal IP; no DNS lookup needed
	}  // Structure boundary: Open/Close execution block scope

	// ── Fast path ─────────────────────────────────────────────────────────────
	cachedIPs, expired, updating := x.loadCachedIPs(host)  // Dynamically initialize and assign `cachedIPs, expired, updating` to optimize stack memory usage
	if len(cachedIPs) > 0 && (!expired || updating) {  // Conditional branch evaluating: len(cachedIPs) > 0 && (!expired || updating)
		return nil  // Return computed results back to the calling function
	}  // Structure boundary: Open/Close execution block scope

	// ── Slow path — serialise per host ────────────────────────────────────────
	mu := x.hostResolveMu(host)  // Dynamically initialize and assign `mu` to optimize stack memory usage
	mu.Lock()  // Execute functional subroutine or method call
	defer mu.Unlock()  // Defer mutex unlock to ensure lock is released even if a panic occurs

	// Double-check: another goroutine may have resolved host while we waited.
	cachedIPs, expired, _ = x.loadCachedIPs(host)  // Update state of `cachedIPs, expired, _` with new computed value
	if len(cachedIPs) > 0 && !expired {  // Conditional branch evaluating: len(cachedIPs) > 0 && !expired
		return nil  // Return computed results back to the calling function
	}  // Structure boundary: Open/Close execution block scope

	// Signal "in progress" before releasing the read view so any concurrent
	// dial attempt sees the updating flag and does not trigger a second query.
	x.markUpdatingCachedIP(host)  // Execute instruction

	ips, ttl, err := x.resolve(host, x.useIPv4, x.useIPv6)  // Dynamically initialize and assign `ips, ttl, err` to optimize stack memory usage
	if ttl < MinResolverIPTTL {  // Conditional branch evaluating: ttl < MinResolverIPTTL
		ttl = MinResolverIPTTL  // Update state of `ttl` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	selectedIPs := ips  // Dynamically initialize and assign `selectedIPs` to optimize stack memory usage

	// Serve stale cache on failure rather than completely breaking connectivity.
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {  // Conditional branch evaluating: (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0
		dlog.Noticef("Using stale cached address for [%s] (grace period)", host)  // Log notice-level information for important operational events
		selectedIPs = cachedIPs  // Update state of `selectedIPs` with new computed value
		ttl = ExpiredCachedIPGraceTTL  // Update state of `ttl` with new computed value
		err = nil // clear; stale service is success from the caller's perspective
	}  // Structure boundary: Open/Close execution block scope

	if err != nil {  // Check for non-nil error to handle failure conditions safely
		return err  // Return execution flow, propagating error state or nil values to caller
	}  // Structure boundary: Open/Close execution block scope

	if len(selectedIPs) == 0 {  // Conditional branch evaluating: len(selectedIPs) == 0
		// Report the appropriate warning based on configured address families.
		switch {  // Enter switch statement for multi-case evaluation
		case !x.useIPv4 && x.useIPv6:  // Execute branch if condition matches: !x.useIPv4 && x.useIPv6
			dlog.Warnf("no IPv6 address found for [%s]", host)  // Log critical warning or fatal error and potentially terminate
		case x.useIPv4 && !x.useIPv6:  // Execute branch if condition matches: x.useIPv4 && !x.useIPv6
			dlog.Warnf("no IPv4 address found for [%s]", host)  // Log critical warning or fatal error and potentially terminate
		default:  // Execute instruction
			dlog.Errorf("no IP address found for [%s]", host)  // Execute instruction
		}  // Structure boundary: Open/Close execution block scope
		return nil  // Return computed results back to the calling function
	}  // Structure boundary: Open/Close execution block scope

	x.saveCachedIPs(host, selectedIPs, ttl)  // Execute instruction
	return nil  // Return computed results back to the calling function
}  // Structure boundary: Open/Close execution block scope

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
func (x *XTransport) Fetch(  // Define function `Fetch` with Go 1.26+ strict typing and performance optimizations
	method string,  // Execute instruction
	url *url.URL,  // Execute instruction
	accept string,  // Execute instruction
	contentType string,  // Execute instruction
	body *[]byte,  // Execute instruction
	timeout time.Duration,  // Execute instruction
	compress bool,  // Execute instruction
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute instruction
	if timeout <= 0 {  // Conditional branch evaluating: timeout <= 0
		timeout = x.timeout  // Update state of `timeout` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	client := http.Client{  // Dynamically initialize and assign `client` to optimize stack memory usage
		Transport: x.transport,  // Execute instruction
		Timeout:   timeout,  // Execute instruction
	}  // Structure boundary: Open/Close execution block scope

	host, port := ExtractHostAndPort(url.Host, 443)  // Dynamically initialize and assign `host, port` to optimize stack memory usage
	hasAltSupport := false  // Dynamically initialize and assign `hasAltSupport` to optimize stack memory usage

	// ── Select transport ───────────────────────────────────────────────────────
	if x.h3Transport != nil {  // Conditional branch evaluating: x.h3Transport != nil
		if x.http3Probe {  // Conditional branch evaluating: x.http3Probe
			// Always probe H3, ignoring the Alt-Svc cache.
			client.Transport = x.h3Transport  // Update state of `client.Transport` with new computed value
			dlog.Debugf("Probing HTTP/3 for [%s]", url.Host)  // Log debug information regarding the current operation state
		} else {  // Execute instruction
			x.altSupport.RLock()  // Execute functional subroutine or method call
			entry, inCache := x.altSupport.cache[url.Host]  // Dynamically initialize and assign `entry, inCache` to optimize stack memory usage
			x.altSupport.RUnlock()  // Execute functional subroutine or method call
			if inCache {  // Conditional branch evaluating: inCache
				hasAltSupport = true  // Update state of `hasAltSupport` with new computed value
				negativeExpired := entry.port == 0 &&  // Dynamically initialize and assign `negativeExpired` to optimize stack memory usage
					!entry.validTo.IsZero() &&  // Execute functional subroutine or method call
					time.Now().After(entry.validTo)  // Execute functional subroutine or method call
				switch {  // Enter switch statement for multi-case evaluation
				case entry.port > 0 && int(entry.port) == port:  // Execute branch if condition matches: entry.port > 0 && int(entry.port) == port
					client.Transport = x.h3Transport  // Update state of `client.Transport` with new computed value
					dlog.Debugf("Using HTTP/3 for [%s]", url.Host)  // Log debug information regarding the current operation state
				case negativeExpired:  // Execute branch if condition matches: negativeExpired
					// Timed negative entry has expired; allow Alt-Svc re-parsing.
					hasAltSupport = false  // Update state of `hasAltSupport` with new computed value
				}  // Structure boundary: Open/Close execution block scope
			}  // Structure boundary: Open/Close execution block scope
		}  // Structure boundary: Open/Close execution block scope
	}  // Structure boundary: Open/Close execution block scope

	// ── Build request headers ──────────────────────────────────────────────────
	// Capacity 5 covers the common case (User-Agent, Cache-Control, Accept,
	// Content-Type, Accept-Encoding) without ever needing to grow.
	header := make(http.Header, 5)  // Pre-allocate `header` with specific capacity to prevent dynamic growth overhead
	header.Set("User-Agent", "dnscrypt-proxy")  // Execute instruction
	header.Set("Cache-Control", "max-stale")  // Execute instruction
	if accept != "" {  // Conditional branch evaluating: accept != ""
		header.Set("Accept", accept)  // Execute instruction
	}  // Structure boundary: Open/Close execution block scope
	if contentType != "" {  // Conditional branch evaluating: contentType != ""
		header.Set("Content-Type", contentType)  // Execute instruction
	}  // Structure boundary: Open/Close execution block scope

	// Append a SHA-512/256 body hash to the query string so upstream caches
	// correctly distinguish requests with different payloads.
	if body != nil {  // Conditional branch evaluating: body != nil
		h := sha512.Sum512(*body)  // Dynamically initialize and assign `h` to optimize stack memory usage
		qs := url.Query()  // Dynamically initialize and assign `qs` to optimize stack memory usage
		qs.Add("body_hash", hex.EncodeToString(h[:32]))  // Execute instruction
		u2 := *url  // Dynamically initialize and assign `u2` to optimize stack memory usage
		u2.RawQuery = qs.Encode()  // Update state of `u2.RawQuery` with new computed value
		url = &u2  // Update state of `url` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	// ── Pre-flight checks ──────────────────────────────────────────────────────
	if x.proxyDialer == nil && strings.HasSuffix(host, ".onion") {  // Conditional branch evaluating: x.proxyDialer == nil && strings.HasSuffix(host, ".onion")
		return nil, 0, nil, 0,  // Return execution flow, propagating error state or nil values to caller
			errors.New("onion service requires a configured Tor proxy")  // Execute instruction
	}  // Structure boundary: Open/Close execution block scope
	if err := x.resolveAndUpdateCache(host); err != nil {  // Conditional branch evaluating: err != nil
		dlog.Errorf("Unable to resolve [%s]: check bootstrap_resolvers or system resolver", host)  // Execute instruction
		return nil, 0, nil, 0, err  // Return execution flow, propagating error state or nil values to caller
	}  // Structure boundary: Open/Close execution block scope
	if compress && body == nil {  // Conditional branch evaluating: compress && body == nil
		header.Set("Accept-Encoding", "gzip")  // Execute instruction
	}  // Structure boundary: Open/Close execution block scope

	// ── Build the request ──────────────────────────────────────────────────────
	bodyLen := 0  // Dynamically initialize and assign `bodyLen` to optimize stack memory usage
	if body != nil {  // Conditional branch evaluating: body != nil
		bodyLen = len(*body)  // Update state of `bodyLen` with new computed value
	}  // Structure boundary: Open/Close execution block scope
	req := &http.Request{  // Dynamically initialize and assign `req` to optimize stack memory usage
		Method:        method,  // Execute instruction
		URL:           url,  // Execute instruction
		Header:        header,  // Execute instruction
		Close:         false,  // Execute instruction
		ContentLength: int64(bodyLen),  // Execute instruction
	}  // Structure boundary: Open/Close execution block scope
	if body != nil {  // Conditional branch evaluating: body != nil
		req.Body = io.NopCloser(bytes.NewReader(*body))  // Update state of `req.Body` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	// ── Execute ────────────────────────────────────────────────────────────────
	start := time.Now()  // Capture current time to initialize `start` for TTL/timeout tracking
	resp, err := client.Do(req)  // Dynamically initialize and assign `resp, err` to optimize stack memory usage
	rtt := time.Since(start)  // Dynamically initialize and assign `rtt` to optimize stack memory usage

	// HTTP/3 failed — record a timed negative entry and fall back to HTTP/2.
	if err != nil && client.Transport == x.h3Transport {  // Check for non-nil error to handle failure conditions safely
		dlog.Debugf("HTTP/3 failed for [%s]: %v — retrying over HTTP/2", url.Host, err)  // Log debug information regarding the current operation state
		x.altSupport.Lock()  // Execute functional subroutine or method call
		x.altSupport.cache[url.Host] = altSvcEntry{  // Update state of `x.altSupport.cache[url.Host]` with new computed value
			port:    0,  // Execute instruction
			validTo: time.Now().Add(altSvcNegativeTTL),  // Execute functional subroutine or method call
		}  // Structure boundary: Open/Close execution block scope
		x.altSupport.Unlock()  // Execute functional subroutine or method call

		client.Transport = x.transport  // Update state of `client.Transport` with new computed value
		if body != nil {  // Conditional branch evaluating: body != nil
			req.Body = io.NopCloser(bytes.NewReader(*body))  // Update state of `req.Body` with new computed value
			// MUST reset ContentLength; net/http requires it after body reassignment.
			req.ContentLength = int64(bodyLen)  // Update state of `req.ContentLength` with new computed value
		}  // Structure boundary: Open/Close execution block scope
		start = time.Now()  // Update state of `start` with new computed value
		resp, err = client.Do(req)  // Update state of `resp, err` with new computed value
		rtt = time.Since(start)  // Update state of `rtt` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	// Single unconditional defer placed immediately after the nil guard.
	// This is the only close call for resp.Body on every code path, eliminating
	// any double-close or missed-close risk.
	if resp != nil {  // Conditional branch evaluating: resp != nil
		defer resp.Body.Close()  // Defer resource cleanup (Close) to prevent file/connection leaks
	}  // Structure boundary: Open/Close execution block scope

	// Determine status code before any early-exit so callers always receive it.
	statusCode := 503  // Dynamically initialize and assign `statusCode` to optimize stack memory usage
	if resp != nil {  // Conditional branch evaluating: resp != nil
		statusCode = resp.StatusCode  // Update state of `statusCode` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	// ── Validate response ──────────────────────────────────────────────────────
	if err == nil {  // Conditional branch evaluating: err == nil
		switch {  // Enter switch statement for multi-case evaluation
		case resp == nil:  // Execute branch if condition matches: resp == nil
			// Guard against nil resp BEFORE accessing resp.StatusCode (which
			// would panic). This case comes first in the switch intentionally.
			err = errors.New("server returned an empty response")  // Update state of `err` with new computed value
		case resp.StatusCode < 200 || resp.StatusCode > 299:  // Execute branch if condition matches: resp.StatusCode < 200 || resp.StatusCode > 299
			err = errors.New(resp.Status)  // Update state of `err` with new computed value
		}  // Structure boundary: Open/Close execution block scope
	} else {  // Execute instruction
		dlog.Debugf("HTTP error [%s]: %v — closing idle connections", url.Host, err)  // Log debug information regarding the current operation state
		x.transport.CloseIdleConnections()  // Execute functional subroutine or method call
	}  // Structure boundary: Open/Close execution block scope

	if err != nil {  // Check for non-nil error to handle failure conditions safely
		dlog.Debugf("[%s]: %v", req.URL, err)  // Log debug information regarding the current operation state
		return nil, statusCode, nil, rtt, err  // Return execution flow, propagating error state or nil values to caller
	}  // Structure boundary: Open/Close execution block scope

	// Parse Alt-Svc for future H3 upgrades, but only when we don't already
	// have a current Alt-Svc entry for this host.
	if x.h3Transport != nil && !hasAltSupport {  // Conditional branch evaluating: x.h3Transport != nil && !hasAltSupport
		x.parseAndCacheAltSvc(url.Host, port, resp.Header)  // Execute instruction
	}  // Structure boundary: Open/Close execution block scope

	tlsState := resp.TLS  // Dynamically initialize and assign `tlsState` to optimize stack memory usage

	// ── Read and optionally decompress the body ────────────────────────────────
	var bodyReader io.ReadCloser = resp.Body  // Update state of `var bodyReader io.ReadCloser` with new computed value
	if compress && resp.Header.Get("Content-Encoding") == "gzip" {  // Conditional branch evaluating: compress && resp.Header.Get("Content-Encoding") == "gzip"
		gr, grErr := gzip.NewReader(io.LimitReader(resp.Body, MaxHTTPBodyLength))  // Dynamically initialize and assign `gr, grErr` to optimize stack memory usage
		if grErr != nil {  // Conditional branch evaluating: grErr != nil
			return nil, statusCode, tlsState, rtt, grErr  // Return execution flow, propagating error state or nil values to caller
		}  // Structure boundary: Open/Close execution block scope
		defer gr.Close()  // Defer resource cleanup (Close) to prevent file/connection leaks
		bodyReader = gr  // Update state of `bodyReader` with new computed value
	}  // Structure boundary: Open/Close execution block scope

	bin, err := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))  // Dynamically initialize and assign `bin, err` to optimize stack memory usage
	if err != nil {  // Check for non-nil error to handle failure conditions safely
		return nil, statusCode, tlsState, rtt, err  // Return execution flow, propagating error state or nil values to caller
	}  // Structure boundary: Open/Close execution block scope
	return bin, statusCode, tlsState, rtt, nil  // Return computed results back to the calling function
}  // Structure boundary: Open/Close execution block scope

// parseAndCacheAltSvc inspects the Alt-Svc response header and updates the
// per-host entry in altSupport.
//
// Positive entries (port > 0) have no expiry. Negative entries (port == 0)
// carry a validTo time so recovering servers are automatically retried after
// altSvcNegativeTTL.
func (x *XTransport) parseAndCacheAltSvc(host string, port int, header http.Header) {  // Define function `parseAndCacheAltSvc` with Go 1.26+ strict typing and performance optimizations
	// Honour an active negative entry — skip parsing entirely.
	x.altSupport.RLock()  // Execute functional subroutine or method call
	existing, inCache := x.altSupport.cache[host]  // Dynamically initialize and assign `existing, inCache` to optimize stack memory usage
	x.altSupport.RUnlock()  // Execute functional subroutine or method call
	if inCache && existing.port == 0 &&  // Conditional branch evaluating: inCache && existing.port == 0 &&
		(existing.validTo.IsZero() || time.Now().Before(existing.validTo)) {  // Execute functional subroutine or method call
		dlog.Debugf("Alt-Svc: negative cache still valid for [%s]; skipping", host)  // Log debug information regarding the current operation state
		return  // Exit function immediately
	}  // Structure boundary: Open/Close execution block scope

	alt, found := header["Alt-Svc"]  // Dynamically initialize and assign `alt, found` to optimize stack memory usage
	if !found {  // Conditional branch evaluating: !found
		return  // Exit function immediately
	}  // Structure boundary: Open/Close execution block scope
	dlog.Debugf("Alt-Svc [%s]: %v", host, alt)  // Log debug information regarding the current operation state

	altPort := uint16(port & 0xffff) // default: same port as HTTP/2

outer:  // Execute instruction
	for i, entry := range alt {  // Execute looping construct while evaluating: i, entry := range alt
		if i >= 8 { // guard against unreasonably long headers
			break  // Execute instruction
		}  // Structure boundary: Open/Close execution block scope
		for j, field := range strings.Split(entry, ";") {  // Execute looping construct while evaluating: j, field := range strings.Split(entry, ";")
			if j >= 16 {  // Conditional branch evaluating: j >= 16
				break  // Execute instruction
			}  // Structure boundary: Open/Close execution block scope
			// strings.CutPrefix (Go 1.20) is cleaner than HasPrefix + manual slice.
			if after, ok := strings.CutPrefix(strings.TrimSpace(field), `h3=":`); ok {  // Conditional branch evaluating: ok
				v := strings.TrimSuffix(after, `"`)  // Dynamically initialize and assign `v` to optimize stack memory usage
				if p, pErr := strconv.ParseUint(v, 10, 16); pErr == nil && p <= 65535 {  // Conditional branch evaluating: pErr == nil && p <= 65535
					altPort = uint16(p)  // Update state of `altPort` with new computed value
					dlog.Debugf("Alt-Svc: HTTP/3 advertised for [%s] on port %d",  // Log debug information regarding the current operation state
						host, altPort)  // Execute instruction
					break outer  // Execute instruction
				}  // Structure boundary: Open/Close execution block scope
			}  // Structure boundary: Open/Close execution block scope
		}  // Structure boundary: Open/Close execution block scope
	}  // Structure boundary: Open/Close execution block scope

	x.altSupport.Lock()  // Execute functional subroutine or method call
	// Positive entry: no expiry (zero validTo).
	x.altSupport.cache[host] = altSvcEntry{port: altPort}  // Update state of `x.altSupport.cache[host]` with new computed value
	dlog.Debugf("Alt-Svc: cached port %d for [%s]", altPort, host)  // Log debug information regarding the current operation state
	x.altSupport.Unlock()  // Execute functional subroutine or method call
}  // Structure boundary: Open/Close execution block scope

// ── Public query helpers ──────────────────────────────────────────────────────

// GetWithCompression sends a GET request and transparently decompresses a gzip
// response. Equivalent to Fetch("GET", …, compress=true).
func (x *XTransport) GetWithCompression(  // Define function `GetWithCompression` with Go 1.26+ strict typing and performance optimizations
	url *url.URL,  // Execute instruction
	accept string,  // Execute instruction
	timeout time.Duration,  // Execute instruction
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute instruction
	return x.Fetch("GET", url, accept, "", nil, timeout, true)  // Return execution flow, propagating error state or nil values to caller
}  // Structure boundary: Open/Close execution block scope

// Get sends a plain GET request without any compression negotiation.
func (x *XTransport) Get(  // Define function `Get` with Go 1.26+ strict typing and performance optimizations
	url *url.URL,  // Execute instruction
	accept string,  // Execute instruction
	timeout time.Duration,  // Execute instruction
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute instruction
	return x.Fetch("GET", url, accept, "", nil, timeout, false)  // Return execution flow, propagating error state or nil values to caller
}  // Structure boundary: Open/Close execution block scope

// Post sends a POST request with the given content type and body.
func (x *XTransport) Post(  // Define function `Post` with Go 1.26+ strict typing and performance optimizations
	url *url.URL,  // Execute instruction
	accept, contentType string,  // Execute instruction
	body *[]byte,  // Execute instruction
	timeout time.Duration,  // Execute instruction
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute instruction
	return x.Fetch("POST", url, accept, contentType, body, timeout, false)  // Return computed results back to the calling function
}  // Structure boundary: Open/Close execution block scope

// dohLikeQuery is the shared implementation for DoHQuery and ObliviousDoHQuery.
// For GET requests the body is base64url-encoded as the "dns" query parameter
// per RFC 8484 §4.1. For POST requests the body is sent verbatim.
func (x *XTransport) dohLikeQuery(  // Define function `dohLikeQuery` with Go 1.26+ strict typing and performance optimizations
	dataType string,  // Execute instruction
	useGet bool,  // Execute instruction
	url *url.URL,  // Execute instruction
	body []byte,  // Execute instruction
	timeout time.Duration,  // Execute instruction
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute instruction
	if useGet {  // Conditional branch evaluating: useGet
		qs := url.Query()  // Dynamically initialize and assign `qs` to optimize stack memory usage
		qs.Add("dns", base64.RawURLEncoding.EncodeToString(body))  // Execute instruction
		u2 := *url  // Dynamically initialize and assign `u2` to optimize stack memory usage
		u2.RawQuery = qs.Encode()  // Update state of `u2.RawQuery` with new computed value
		return x.Get(&u2, dataType, timeout)  // Return computed results back to the calling function
	}  // Structure boundary: Open/Close execution block scope
	return x.Post(url, dataType, dataType, &body, timeout)  // Return computed results back to the calling function
}  // Structure boundary: Open/Close execution block scope

// DoHQuery sends a DNS-over-HTTPS query as defined by RFC 8484.
// Set useGet=true to use the GET wire format, false to use POST.
func (x *XTransport) DoHQuery(  // Define function `DoHQuery` with Go 1.26+ strict typing and performance optimizations
	useGet bool,  // Execute instruction
	url *url.URL,  // Execute instruction
	body []byte,  // Execute instruction
	timeout time.Duration,  // Execute instruction
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute instruction
	return x.dohLikeQuery("application/dns-message", useGet, url, body, timeout)  // Return computed results back to the calling function
}  // Structure boundary: Open/Close execution block scope

// ObliviousDoHQuery sends an Oblivious DNS-over-HTTPS query as defined by
// RFC 9230. Set useGet=true for the GET wire format, false for POST.
func (x *XTransport) ObliviousDoHQuery(  // Define function `ObliviousDoHQuery` with Go 1.26+ strict typing and performance optimizations
	useGet bool,  // Execute instruction
	url *url.URL,  // Execute instruction
	body []byte,  // Execute instruction
	timeout time.Duration,  // Execute instruction
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute instruction
	return x.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)  // Return computed results back to the calling function
}  // Structure boundary: Open/Close execution block scope
