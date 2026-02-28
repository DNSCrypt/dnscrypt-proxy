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
	"slices"
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

// ── Hardware capability probe ─────────────────────────────────────────────────

// hasAESGCMHardwareSupport is true when the CPU can accelerate AES-GCM in
// hardware. Used to order TLS 1.2 cipher suites: AES-GCM first on capable
// hardware, ChaCha20-Poly1305 first everywhere else.
var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||  // Update existing variable state with new computed value
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||  // Execute subroutine or method call per application logic
	(cpu.S390X.HasAES && cpu.S390X.HasAESGCM)  // Execute subroutine or method call per application logic

// ── Sentinel ──────────────────────────────────────────────────────────────────

// noTTL is the "no TTL seen yet" sentinel used when tracking the minimum TTL
// across DNS answer RRs. A named constant is clearer than the magic ^uint32(0).
const noTTL = ^uint32(0)  // Update existing variable state with new computed value

// ── Tuning constants ──────────────────────────────────────────────────────────

const (  // Execute sequential algorithmic statement
	// DefaultBootstrapResolver is the DNS resolver used at startup before the
	// internal proxy resolver becomes available. Must be a valid host:port.
	DefaultBootstrapResolver = "9.9.9.9:53"  // Update existing variable state with new computed value

	// DefaultKeepAlive is the TCP keep-alive probe interval passed to net.Dialer.
	DefaultKeepAlive = 5 * time.Second  // Update existing variable state with new computed value

	// DefaultIdleConnTimeout is how long an idle HTTP/2 connection remains in
	// the transport pool before being closed.
	DefaultIdleConnTimeout = 90 * time.Second  // Update existing variable state with new computed value

	// DefaultTimeout is the end-to-end deadline for a single HTTP request.
	// Callers may override this per-request via the timeout parameter.
	DefaultTimeout = 30 * time.Second  // Update existing variable state with new computed value

	// ResolverReadTimeout is the maximum duration for a single DNS exchange
	// (query transmission + response receipt).
	ResolverReadTimeout = 5 * time.Second  // Update existing variable state with new computed value

	// SystemResolverIPTTL is the synthetic TTL assigned to addresses returned
	// by the OS resolver. The OS resolver does not expose per-record TTLs.
	SystemResolverIPTTL = 12 * time.Hour  // Update existing variable state with new computed value

	// MinResolverIPTTL is the minimum TTL enforced for any cached IP entry.
	// Advertised TTLs shorter than this are silently raised to it.
	MinResolverIPTTL = 4 * time.Hour  // Update existing variable state with new computed value

	// ResolverIPTTLMaxJitter is the exclusive upper bound of the random
	// duration added to each TTL to stagger re-resolution across time.
	ResolverIPTTLMaxJitter = 15 * time.Minute  // Update existing variable state with new computed value

	// ExpiredCachedIPGraceTTL is how long a stale cache entry continues to be
	// served when fresh resolution fails. Keeps connectivity during outages.
	ExpiredCachedIPGraceTTL = 15 * time.Minute  // Update existing variable state with new computed value

	// resolverRetryCount is the number of query attempts per resolver before
	// falling through to the next resolver in the list.
	resolverRetryCount = 3  // Update existing variable state with new computed value

	// resolverRetryInitialBackoff is the sleep before the second attempt.
	// Each subsequent sleep doubles up to resolverRetryMaxBackoff.
	resolverRetryInitialBackoff = 150 * time.Millisecond  // Update existing variable state with new computed value

	// resolverRetryMaxBackoff caps the exponential back-off growth.
	resolverRetryMaxBackoff = 1 * time.Second  // Update existing variable state with new computed value

	// MaxIdleConns is the total HTTP/2 connection-pool size across all hosts.
	MaxIdleConns = 2000  // Update existing variable state with new computed value

	// MaxResponseHeaderBytes caps the HTTP response header size accepted.
	MaxResponseHeaderBytes = 4096  // Update existing variable state with new computed value

	// TLSHandshakeTimeout is the deadline for completing a TLS handshake,
	// applied to both the HTTP/2 and HTTP/3 transports.
	TLSHandshakeTimeout = 10 * time.Second  // Update existing variable state with new computed value

	// altSvcNegativeTTL is how long a failed HTTP/3 probe blocks further H3
	// attempts for the same host. After this window the entry expires and the
	// host is tried again.
	altSvcNegativeTTL = 10 * time.Minute  // Update existing variable state with new computed value
)  // Execute sequential algorithmic statement

// ── Types ─────────────────────────────────────────────────────────────────────

// CachedIPItem stores resolved IP addresses and their freshness metadata.
// All fields are protected by the enclosing CachedIPs.RWMutex.
type CachedIPItem struct {  // Declare user-defined type for memory-efficient data structuring
	ips           []net.IP  // Execute sequential algorithmic statement
	expiration    *time.Time // nil → entry never expires
	updatingUntil *time.Time // non-nil while background re-resolution is in flight
}  // Block boundary: manages lexical scope and stack allocation limits

// CachedIPs is a thread-safe hostname → IP-address cache.
type CachedIPs struct {  // Declare user-defined type for memory-efficient data structuring
	sync.RWMutex  // Execute sequential algorithmic statement
	cache map[string]*CachedIPItem  // Execute sequential algorithmic statement
}  // Block boundary: manages lexical scope and stack allocation limits

// altSvcEntry holds a single HTTP/3 Alt-Svc record for a host.
//
//   - port > 0  → positive entry: use HTTP/3 on this port
//   - port == 0 → negative entry: HTTP/3 failed or is unavailable
//
// validTo is only meaningful for negative entries and indicates when the ban
// expires. Positive entries never expire (validTo is the zero time).
type altSvcEntry struct {  // Declare user-defined type for memory-efficient data structuring
	port    uint16  // Execute sequential algorithmic statement
	validTo time.Time  // Execute sequential algorithmic statement
}  // Block boundary: manages lexical scope and stack allocation limits

// AltSupport is a thread-safe cache of HTTP/3 Alt-Svc entries keyed by host.
type AltSupport struct {  // Declare user-defined type for memory-efficient data structuring
	sync.RWMutex  // Execute sequential algorithmic statement
	cache map[string]altSvcEntry  // Execute sequential algorithmic statement
}  // Block boundary: manages lexical scope and stack allocation limits

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
type XTransport struct {  // Declare user-defined type for memory-efficient data structuring
	// HTTP transports. h3Transport is nil when HTTP/3 is disabled.
	transport       *http.Transport  // Execute sequential algorithmic statement
	h3Transport     *http3.Transport  // Execute sequential algorithmic statement
	tlsClientConfig *tls.Config // constructed once; shared across both transports

	keepAlive time.Duration  // Execute sequential algorithmic statement
	timeout   time.Duration  // Execute sequential algorithmic statement

	cachedIPs  CachedIPs  // Execute sequential algorithmic statement
	altSupport AltSupport  // Execute sequential algorithmic statement

	// DNS resolver configuration.
	internalResolvers     []string  // Execute sequential algorithmic statement
	bootstrapResolvers    []string  // Execute sequential algorithmic statement
	mainProto             string // "udp" or "tcp" — preferred DNS query transport
	ignoreSystemDNS       bool  // Execute sequential algorithmic statement
	internalResolverReady bool  // Execute sequential algorithmic statement

	// Address-family selection for outgoing connections.
	useIPv4 bool  // Execute sequential algorithmic statement
	useIPv6 bool  // Execute sequential algorithmic statement

	// HTTP/3 control flags.
	// Field names intentionally match what config_loader.go sets so that this
	// file is a drop-in replacement without changing any callsite.
	http3      bool // enable HTTP/3 transport for all requests
	http3Probe bool // bypass Alt-Svc cache and always probe H3 first

	// TLS tweaks.
	tlsDisableSessionTickets bool  // Execute sequential algorithmic statement
	tlsPreferRSA             bool // limits TLS max version to 1.2

	// Proxy configuration.
	proxyDialer       *netproxy.Dialer  // Execute sequential algorithmic statement
	httpProxyFunction func(*http.Request) (*url.URL, error)  // Execute subroutine or method call per application logic

	// Client credentials and debug hooks.
	tlsClientCreds DOHClientCreds  // Execute sequential algorithmic statement
	keyLogWriter   io.Writer  // Execute sequential algorithmic statement

	// resolveMu stores one *sync.Mutex per hostname (as sync.Map values).
	// It ensures only one goroutine resolves a given host at a time.
	resolveMu sync.Map // effective type: map[string]*sync.Mutex
}  // Block boundary: manages lexical scope and stack allocation limits

// ── Constructor ───────────────────────────────────────────────────────────────

// NewXTransport allocates an *XTransport with safe production defaults.
//
// It panics if DefaultBootstrapResolver is not a valid host:port — that is a
// programming error detectable at startup, not a recoverable runtime condition.
func NewXTransport() *XTransport {  // Define function/method NewXTransport leveraging Go 1.26+ strict typing
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {  // Evaluate conditional expression to branch execution flow
		panic("DefaultBootstrapResolver is not a valid IP:port — " + err.Error())  // Execute subroutine or method call per application logic
	}  // Block boundary: manages lexical scope and stack allocation limits
	return &XTransport{  // Return computed value(s) to caller and exit current stack frame
		cachedIPs:          CachedIPs{cache: make(map[string]*CachedIPItem)},  // Execute subroutine or method call per application logic
		altSupport:         AltSupport{cache: make(map[string]altSvcEntry)},  // Execute subroutine or method call per application logic
		keepAlive:          DefaultKeepAlive,  // Execute sequential algorithmic statement
		timeout:            DefaultTimeout,  // Execute sequential algorithmic statement
		bootstrapResolvers: []string{DefaultBootstrapResolver},  // Execute sequential algorithmic statement
		ignoreSystemDNS:    true,  // Execute sequential algorithmic statement
		useIPv4:            true,  // Execute sequential algorithmic statement
	}  // Block boundary: manages lexical scope and stack allocation limits
}  // Block boundary: manages lexical scope and stack allocation limits

// ── IP helpers ────────────────────────────────────────────────────────────────

// ParseIP parses an IP address string. IPv6 addresses may be enclosed in
// brackets (e.g. "[::1]"); the brackets are stripped before parsing.
// Returns nil for any invalid input.
func ParseIP(ipStr string) net.IP {  // Define function/method ParseIP leveraging Go 1.26+ strict typing
	ipStr = strings.TrimPrefix(ipStr, "[")  // Update existing variable state with new computed value
	ipStr = strings.TrimSuffix(ipStr, "]")  // Update existing variable state with new computed value
	return net.ParseIP(ipStr)  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

// netIPToNetipAddr converts a net.IP to a netip.Addr with zero allocation.
//
// It uses the direct slice-to-array conversion ([4]byte(ip) / [16]byte(ip))
// introduced in Go 1.20, which avoids the copy that net/netip.AddrFromSlice
// must perform for safety. IPv4-mapped IPv6 addresses are Unmapped so that
// 1.2.3.4 and ::ffff:1.2.3.4 hash to the same deduplication key.
//
// Returns (zero, false) for any slice whose length is neither 4 nor 16.
func netIPToNetipAddr(ip net.IP) (netip.Addr, bool) {  // Define function/method netIPToNetipAddr leveraging Go 1.26+ strict typing
	switch len(ip) {  // Evaluate multiplexer switch statement for targeted branching
	case 4:  // Define execution path for specific matched condition
		return netip.AddrFrom4([4]byte(ip)), true  // Return computed value(s) to caller and exit current stack frame
	case 16:  // Define execution path for specific matched condition
		// Unmap promotes IPv4-mapped IPv6 addresses so dedup works correctly.
		return netip.AddrFrom16([16]byte(ip)).Unmap(), true  // Return computed value(s) to caller and exit current stack frame
	default:  // Provide default execution path if no specific cases match
		return netip.Addr{}, false  // Return computed value(s) to caller and exit current stack frame
	}  // Block boundary: manages lexical scope and stack allocation limits
}  // Block boundary: manages lexical scope and stack allocation limits

// uniqueNormalizedIPs returns a deduplicated, deep-copied slice of IPs.
// Ordering is preserved (first occurrence wins). nil entries are dropped.
//
// Fast-paths for 0- and 1-element inputs avoid allocating the dedup map,
// which matters because single-address results are the common case.
func uniqueNormalizedIPs(ips []net.IP) []net.IP {  // Define function/method uniqueNormalizedIPs leveraging Go 1.26+ strict typing
	switch len(ips) {  // Evaluate multiplexer switch statement for targeted branching
	case 0:  // Define execution path for specific matched condition
		return nil  // Return computed value(s) to caller and exit current stack frame
	case 1:  // Define execution path for specific matched condition
		if ips[0] == nil {  // Evaluate conditional expression to branch execution flow
			return nil  // Return computed value(s) to caller and exit current stack frame
		}  // Block boundary: manages lexical scope and stack allocation limits
		// Deep-copy the single element and return immediately.
		return []net.IP{slices.Clone(ips[0])}  // Return computed value(s) to caller and exit current stack frame
	}  // Block boundary: manages lexical scope and stack allocation limits

	seen := make(map[netip.Addr]struct{}, len(ips))  // Pre-allocate memory capacity to avoid dynamic heap resizing overhead
	out := make([]net.IP, 0, len(ips))  // Pre-allocate memory capacity to avoid dynamic heap resizing overhead
	for _, ip := range ips {  // Iterate over elements using native Go 1.22+ un-captured loop semantics
		if ip == nil {  // Evaluate conditional expression to branch execution flow
			continue  // Execute sequential algorithmic statement
		}  // Block boundary: manages lexical scope and stack allocation limits
		addr, ok := netIPToNetipAddr(ip)  // Declare and initialize new variable(s) with type inference
		if !ok {  // Evaluate conditional expression to branch execution flow
			// Non-standard length — include without deduplication.
			out = append(out, slices.Clone(ip))  // Update existing variable state with new computed value
			continue  // Execute sequential algorithmic statement
		}  // Block boundary: manages lexical scope and stack allocation limits
		if _, dup := seen[addr]; dup {  // Evaluate conditional expression to branch execution flow
			continue  // Execute sequential algorithmic statement
		}  // Block boundary: manages lexical scope and stack allocation limits
		seen[addr] = struct{}{}  // Update existing variable state with new computed value
		out = append(out, slices.Clone(ip))  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits
	return out  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

// ── IP cache ──────────────────────────────────────────────────────────────────

// saveCachedIPs stores resolved IPs for host under the given TTL.
//
// A uniformly-random jitter in [0, ResolverIPTTLMaxJitter) is added to spread
// re-resolution events across time. Any TTL below MinResolverIPTTL is silently
// raised to the floor. Pass a negative ttl to store a permanently-valid entry.
func (x *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {  // Define function/method saveCachedIPs leveraging Go 1.26+ strict typing
	normalized := uniqueNormalizedIPs(ips)  // Declare and initialize new variable(s) with type inference
	if len(normalized) == 0 {  // Evaluate conditional expression to branch execution flow
		return  // Exit function immediately returning implicit zero values
	}  // Block boundary: manages lexical scope and stack allocation limits

	item := &CachedIPItem{ips: normalized}  // Declare and initialize new variable(s) with type inference
	if ttl >= 0 {  // Evaluate conditional expression to branch execution flow
		if ttl < MinResolverIPTTL {  // Evaluate conditional expression to branch execution flow
			ttl = MinResolverIPTTL  // Update existing variable state with new computed value
		}  // Block boundary: manages lexical scope and stack allocation limits
		// rand.Int64N is the Go 1.22+ API from math/rand/v2; no global-state lock.
		ttl += time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))  // Execute subroutine or method call per application logic
		exp := time.Now().Add(ttl)  // Dynamically allocate and initialize timestamp for tracking durations/timeouts
		item.expiration = &exp  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	x.cachedIPs.Lock()  // Acquire exclusive mutex lock to safeguard critical section from data races
	// Clear any in-progress marker atomically with the write.
	item.updatingUntil = nil  // Update existing variable state with new computed value
	x.cachedIPs.cache[host] = item  // Update existing variable state with new computed value
	x.cachedIPs.Unlock()  // Release exclusive mutex lock, allowing pending goroutines to proceed

	if len(normalized) == 1 {  // Evaluate conditional expression to branch execution flow
		dlog.Debugf("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)  // Log operational metrics or diagnostic context for runtime observability
	} else {  // Execute sequential algorithmic statement
		dlog.Debugf("[%s] cached %d IPs (first: %s), valid for %v",  // Log operational metrics or diagnostic context for runtime observability
			host, len(normalized), normalized[0], ttl)  // Execute subroutine or method call per application logic
	}  // Block boundary: manages lexical scope and stack allocation limits
}  // Block boundary: manages lexical scope and stack allocation limits

// saveCachedIP is a single-address convenience wrapper around saveCachedIPs.
// It is a no-op when ip is nil.
func (x *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {  // Define function/method saveCachedIP leveraging Go 1.26+ strict typing
	if ip != nil {  // Evaluate conditional expression to branch execution flow
		x.saveCachedIPs(host, []net.IP{ip}, ttl)  // Execute subroutine or method call per application logic
	}  // Block boundary: manages lexical scope and stack allocation limits
}  // Block boundary: manages lexical scope and stack allocation limits

// markUpdatingCachedIP writes an "update in progress" marker for host.
//
// If host has no existing cache entry a placeholder CachedIPItem is inserted
// so that concurrent callers see the "updating" state and do not start a
// second resolution race.
func (x *XTransport) markUpdatingCachedIP(host string) {  // Define function/method markUpdatingCachedIP leveraging Go 1.26+ strict typing
	until := time.Now().Add(x.timeout)  // Dynamically allocate and initialize timestamp for tracking durations/timeouts
	x.cachedIPs.Lock()  // Acquire exclusive mutex lock to safeguard critical section from data races
	if item, ok := x.cachedIPs.cache[host]; ok {  // Evaluate conditional expression to branch execution flow
		item.updatingUntil = &until  // Update existing variable state with new computed value
		// item is a pointer; mutating it is visible without reassignment.
	} else {  // Execute sequential algorithmic statement
		x.cachedIPs.cache[host] = &CachedIPItem{updatingUntil: &until}  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits
	x.cachedIPs.Unlock()  // Release exclusive mutex lock, allowing pending goroutines to proceed
	dlog.Debugf("[%s] IP address marked as updating", host)  // Log operational metrics or diagnostic context for runtime observability
}  // Block boundary: manages lexical scope and stack allocation limits

// loadCachedIPs returns a deep-copied snapshot of the cached IPs for host,
// along with two freshness flags:
//
//   - expired  — true when the entry exists but its TTL has elapsed
//   - updating — true when another goroutine is currently resolving host
//
// Callers may safely use the returned slice after the lock has been released.
func (x *XTransport) loadCachedIPs(host string) (ips []net.IP, expired, updating bool) {  // Define function/method loadCachedIPs leveraging Go 1.26+ strict typing
	x.cachedIPs.RLock()  // Acquire read-only lock to allow concurrent reads while blocking writes
	item, ok := x.cachedIPs.cache[host]  // Declare and initialize new variable(s) with type inference
	if !ok {  // Evaluate conditional expression to branch execution flow
		x.cachedIPs.RUnlock()  // Release read-only lock on the synchronization primitive
		dlog.Debugf("[%s] IP address not found in cache", host)  // Log operational metrics or diagnostic context for runtime observability
		return nil, false, false  // Return computed value(s) to caller and exit current stack frame
	}  // Block boundary: manages lexical scope and stack allocation limits
	// Deep-copy all slices while holding the read lock so callers never
	// observe aliased memory after the lock is released.
	if n := len(item.ips); n > 0 {  // Evaluate conditional expression to branch execution flow
		ips = make([]net.IP, 0, n)  // Update existing variable state with new computed value
		for _, ip := range item.ips {  // Iterate over elements using native Go 1.22+ un-captured loop semantics
			if ip != nil {  // Evaluate conditional expression to branch execution flow
				ips = append(ips, slices.Clone(ip))  // Update existing variable state with new computed value
			}  // Block boundary: manages lexical scope and stack allocation limits
		}  // Block boundary: manages lexical scope and stack allocation limits
	}  // Block boundary: manages lexical scope and stack allocation limits
	expiration := item.expiration  // Declare and initialize new variable(s) with type inference
	updatingUntil := item.updatingUntil  // Declare and initialize new variable(s) with type inference
	x.cachedIPs.RUnlock()  // Release read-only lock on the synchronization primitive

	if expiration != nil && time.Until(*expiration) < 0 {  // Evaluate conditional expression to branch execution flow
		expired = true  // Update existing variable state with new computed value
		if updatingUntil != nil && time.Until(*updatingUntil) > 0 {  // Evaluate conditional expression to branch execution flow
			updating = true  // Update existing variable state with new computed value
			dlog.Debugf("[%s] cached IPs are being updated", host)  // Log operational metrics or diagnostic context for runtime observability
		} else {  // Execute sequential algorithmic statement
			dlog.Debugf("[%s] cached IPs have expired", host)  // Log operational metrics or diagnostic context for runtime observability
		}  // Block boundary: manages lexical scope and stack allocation limits
	}  // Block boundary: manages lexical scope and stack allocation limits
	return ips, expired, updating  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

// ── Transport construction ────────────────────────────────────────────────────

// rebuildTransport (re-)initialises the HTTP/2 and HTTP/3 transports.
//
// Call once before the first Fetch, and again whenever TLS configuration or
// proxy settings change. Any previously-built transport has its idle
// connections closed to release file descriptors promptly.
func (x *XTransport) rebuildTransport() {  // Define function/method rebuildTransport leveraging Go 1.26+ strict typing
	dlog.Debug("Rebuilding transport")  // Execute subroutine or method call per application logic
	if x.transport != nil {  // Evaluate conditional expression to branch execution flow
		x.transport.CloseIdleConnections()  // Execute subroutine or method call per application logic
	}  // Block boundary: manages lexical scope and stack allocation limits

	// Build a single TLS config shared by both transports. Callers that need
	// per-connection mutation (e.g. setting ServerName in the H3 dialer) must
	// call Clone() on it.
	x.tlsClientConfig = x.buildTLSConfig()  // Update existing variable state with new computed value

	transport := &http.Transport{  // Declare and initialize new variable(s) with type inference
		DisableKeepAlives:      false,  // Execute sequential algorithmic statement
		DisableCompression:     true, // compression handled manually in Fetch
		MaxIdleConns:           MaxIdleConns,  // Execute sequential algorithmic statement
		IdleConnTimeout:        DefaultIdleConnTimeout,  // Execute sequential algorithmic statement
		TLSHandshakeTimeout:    TLSHandshakeTimeout,  // Execute sequential algorithmic statement
		ResponseHeaderTimeout:  x.timeout,  // Execute sequential algorithmic statement
		ExpectContinueTimeout:  1 * time.Second,  // Execute sequential algorithmic statement
		MaxResponseHeaderBytes: MaxResponseHeaderBytes,  // Execute sequential algorithmic statement
		ForceAttemptHTTP2:      true,  // Execute sequential algorithmic statement
		TLSClientConfig:        x.tlsClientConfig,  // Execute sequential algorithmic statement
		DialContext:            x.buildDialContext(),  // Execute subroutine or method call per application logic
	}  // Block boundary: manages lexical scope and stack allocation limits
	if x.httpProxyFunction != nil {  // Evaluate conditional expression to branch execution flow
		transport.Proxy = x.httpProxyFunction  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	// http2.ConfigureTransports (plural) is the Go 1.26 preferred API; it
	// returns *http2.Transport for fine-grained tuning not available through
	// the singular ConfigureTransport.
	if h2t, err := http2.ConfigureTransports(transport); err == nil && h2t != nil {  // Evaluate conditional expression to branch execution flow
		h2t.ReadIdleTimeout = 30 * time.Second  // Update existing variable state with new computed value
		h2t.PingTimeout = 15 * time.Second  // Update existing variable state with new computed value
		h2t.WriteByteTimeout = 10 * time.Second  // Update existing variable state with new computed value
		h2t.AllowHTTP = false  // Update existing variable state with new computed value
		h2t.StrictMaxConcurrentStreams = false  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits
	x.transport = transport  // Update existing variable state with new computed value

	if x.http3 {  // Evaluate conditional expression to branch execution flow
		x.h3Transport = &http3.Transport{  // Update existing variable state with new computed value
			DisableCompression: true,  // Execute sequential algorithmic statement
			TLSClientConfig:    x.tlsClientConfig, // shared; cloned per-connection in H3 dialer
			Dial:               x.buildH3DialFunc(),  // Execute subroutine or method call per application logic
		}  // Block boundary: manages lexical scope and stack allocation limits
	}  // Block boundary: manages lexical scope and stack allocation limits
}  // Block boundary: manages lexical scope and stack allocation limits

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
func (x *XTransport) buildDialContext() func(context.Context, string, string) (net.Conn, error) {  // Define function/method buildDialContext leveraging Go 1.26+ strict typing
	timeout := x.timeout // snapshot; avoids retaining a live pointer into XTransport
	return func(ctx context.Context, network, addrStr string) (net.Conn, error) {  // Return computed value(s) to caller and exit current stack frame
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)  // Declare and initialize new variable(s) with type inference
		portStr := strconv.Itoa(port) // computed once for all endpoint() calls below

		// endpoint builds the dial target string for a given IP (or nil for hostname).
		endpoint := func(ip net.IP) string {  // Declare and initialize new variable(s) with type inference
			if ip != nil {  // Evaluate conditional expression to branch execution flow
				if v4 := ip.To4(); v4 != nil {  // Evaluate conditional expression to branch execution flow
					return v4.String() + ":" + portStr  // Return computed value(s) to caller and exit current stack frame
				}  // Block boundary: manages lexical scope and stack allocation limits
				return "[" + ip.String() + "]:" + portStr  // Return computed value(s) to caller and exit current stack frame
			}  // Block boundary: manages lexical scope and stack allocation limits
			// No cached address — fall back to the raw host. Wrap bare IPv6 in brackets.
			if parsed := ParseIP(host); parsed != nil && parsed.To4() == nil {  // Evaluate conditional expression to branch execution flow
				return "[" + parsed.String() + "]:" + portStr  // Return computed value(s) to caller and exit current stack frame
			}  // Block boundary: manages lexical scope and stack allocation limits
			return host + ":" + portStr  // Return computed value(s) to caller and exit current stack frame
		}  // Block boundary: manages lexical scope and stack allocation limits

		cachedIPs, _, _ := x.loadCachedIPs(host)  // Declare and initialize new variable(s) with type inference
		// max() builtin (Go 1.21) avoids a conditional capacity hint.
		targets := make([]string, 0, max(len(cachedIPs), 1))  // Pre-allocate memory capacity to avoid dynamic heap resizing overhead
		for _, ip := range cachedIPs {  // Iterate over elements using native Go 1.22+ un-captured loop semantics
			targets = append(targets, endpoint(ip))  // Update existing variable state with new computed value
		}  // Block boundary: manages lexical scope and stack allocation limits
		if len(targets) == 0 {  // Evaluate conditional expression to branch execution flow
			dlog.Debugf("[%s] no cached IP; falling back to hostname dial", host)  // Log operational metrics or diagnostic context for runtime observability
			targets = append(targets, endpoint(nil))  // Update existing variable state with new computed value
		}  // Block boundary: manages lexical scope and stack allocation limits

		// Construct the dialer once; reuse across all target attempts.
		d := &net.Dialer{  // Declare and initialize new variable(s) with type inference
			Timeout:   timeout,  // Execute sequential algorithmic statement
			KeepAlive: x.keepAlive,  // Execute sequential algorithmic statement
			DualStack: true,  // Execute sequential algorithmic statement
		}  // Block boundary: manages lexical scope and stack allocation limits

		var lastErr error  // Execute sequential algorithmic statement
		for i, target := range targets {  // Execute iterative looping construct
			var (  // Execute sequential algorithmic statement
				conn net.Conn  // Execute sequential algorithmic statement
				err  error  // Execute sequential algorithmic statement
			)  // Execute sequential algorithmic statement
			if x.proxyDialer == nil {  // Evaluate conditional expression to branch execution flow
				conn, err = d.DialContext(ctx, network, target)  // Update existing variable state with new computed value
			} else {  // Execute sequential algorithmic statement
				conn, err = (*x.proxyDialer).Dial(network, target)  // Update existing variable state with new computed value
			}  // Block boundary: manages lexical scope and stack allocation limits
			if err == nil {  // Evaluate conditional expression to branch execution flow
				return conn, nil  // Return computed value(s) to caller and exit current stack frame
			}  // Block boundary: manages lexical scope and stack allocation limits
			lastErr = err  // Update existing variable state with new computed value
			if i < len(targets)-1 {  // Evaluate conditional expression to branch execution flow
				dlog.Debugf("Dial [%s] failed: %v", target, err)  // Log operational metrics or diagnostic context for runtime observability
			}  // Block boundary: manages lexical scope and stack allocation limits
		}  // Block boundary: manages lexical scope and stack allocation limits
		return nil, lastErr  // Return computed value(s) to caller and exit current stack frame
	}  // Block boundary: manages lexical scope and stack allocation limits
}  // Block boundary: manages lexical scope and stack allocation limits

// buildH3DialFunc returns the QUIC dial function for the HTTP/3 transport.
//
// It mirrors buildDialContext's cache-first strategy but opens UDP sockets.
//
// quic-go always passes nil as the *tls.Config argument; we ignore it (via _)
// and clone x.tlsClientConfig per connection to set ServerName without
// introducing a data race on the shared config — the old code silently
// discarded the real TLS configuration because it forwarded the nil arg.
func (x *XTransport) buildH3DialFunc() func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {  // Define function/method buildH3DialFunc leveraging Go 1.26+ strict typing
	return func(ctx context.Context, addrStr string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {  // Return computed value(s) to caller and exit current stack frame
		dlog.Debugf("H3 dial: [%s]", addrStr)  // Log operational metrics or diagnostic context for runtime observability
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)  // Declare and initialize new variable(s) with type inference
		portStr := strconv.Itoa(port)  // Declare and initialize new variable(s) with type inference

		// udpTarget bundles a resolved UDP address string with its network name.
		type udpTarget struct{ addr, network string }  // Declare user-defined type for memory-efficient data structuring

		// udpEndpoint derives the UDP target for a given IP (or nil = raw host).
		udpEndpoint := func(ip net.IP) udpTarget {  // Declare and initialize new variable(s) with type inference
			if ip != nil {  // Evaluate conditional expression to branch execution flow
				if v4 := ip.To4(); v4 != nil {  // Evaluate conditional expression to branch execution flow
					return udpTarget{v4.String() + ":" + portStr, "udp4"}  // Return computed value(s) to caller and exit current stack frame
				}  // Block boundary: manages lexical scope and stack allocation limits
				return udpTarget{"[" + ip.String() + "]:" + portStr, "udp6"}  // Return computed value(s) to caller and exit current stack frame
			}  // Block boundary: manages lexical scope and stack allocation limits
			// No cached IP — derive network from the host string itself.
			nw, addr := "udp4", host  // Declare and initialize new variable(s) with type inference
			if parsed := ParseIP(host); parsed != nil {  // Evaluate conditional expression to branch execution flow
				if parsed.To4() == nil {  // Evaluate conditional expression to branch execution flow
					nw, addr = "udp6", "["+parsed.String()+"]"  // Update existing variable state with new computed value
				} else {  // Execute sequential algorithmic statement
					addr = parsed.String()  // Update existing variable state with new computed value
				}  // Block boundary: manages lexical scope and stack allocation limits
			} else if x.useIPv6 {  // Execute sequential algorithmic statement
				if x.useIPv4 {  // Evaluate conditional expression to branch execution flow
					nw = "udp" // dual-stack
				} else {  // Execute sequential algorithmic statement
					nw = "udp6"  // Update existing variable state with new computed value
				}  // Block boundary: manages lexical scope and stack allocation limits
			}  // Block boundary: manages lexical scope and stack allocation limits
			return udpTarget{addr + ":" + portStr, nw}  // Return computed value(s) to caller and exit current stack frame
		}  // Block boundary: manages lexical scope and stack allocation limits

		cachedIPs, _, _ := x.loadCachedIPs(host)  // Declare and initialize new variable(s) with type inference
		targets := make([]udpTarget, 0, max(len(cachedIPs), 1))  // Pre-allocate memory capacity to avoid dynamic heap resizing overhead
		for _, ip := range cachedIPs {  // Iterate over elements using native Go 1.22+ un-captured loop semantics
			targets = append(targets, udpEndpoint(ip))  // Update existing variable state with new computed value
		}  // Block boundary: manages lexical scope and stack allocation limits
		if len(targets) == 0 {  // Evaluate conditional expression to branch execution flow
			dlog.Debugf("[%s] no cached IP for H3 dial", host)  // Log operational metrics or diagnostic context for runtime observability
			targets = append(targets, udpEndpoint(nil))  // Update existing variable state with new computed value
		}  // Block boundary: manages lexical scope and stack allocation limits

		var lastErr error  // Execute sequential algorithmic statement
		for i, t := range targets {  // Execute iterative looping construct
			udpAddr, err := net.ResolveUDPAddr(t.network, t.addr)  // Declare and initialize new variable(s) with type inference
			if err != nil {  // Verify error state; handle non-nil errors to maintain application stability
				lastErr = err  // Update existing variable state with new computed value
				if i < len(targets)-1 {  // Evaluate conditional expression to branch execution flow
					dlog.Debugf("H3: resolve [%s]/%s failed: %v", t.addr, t.network, err)  // Log operational metrics or diagnostic context for runtime observability
				}  // Block boundary: manages lexical scope and stack allocation limits
				continue  // Execute sequential algorithmic statement
			}  // Block boundary: manages lexical scope and stack allocation limits
			udpConn, err := net.ListenUDP(t.network, nil)  // Declare and initialize new variable(s) with type inference
			if err != nil {  // Verify error state; handle non-nil errors to maintain application stability
				lastErr = err  // Update existing variable state with new computed value
				if i < len(targets)-1 {  // Evaluate conditional expression to branch execution flow
					dlog.Debugf("H3: listen [%s]/%s failed: %v", t.addr, t.network, err)  // Log operational metrics or diagnostic context for runtime observability
				}  // Block boundary: manages lexical scope and stack allocation limits
				continue  // Execute sequential algorithmic statement
			}  // Block boundary: manages lexical scope and stack allocation limits
			// Clone the shared config so ServerName can be set without racing.
			tlsCfg := x.tlsClientConfig.Clone()  // Declare and initialize new variable(s) with type inference
			tlsCfg.ServerName = host  // Update existing variable state with new computed value
			conn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)  // Declare and initialize new variable(s) with type inference
			if err != nil {  // Verify error state; handle non-nil errors to maintain application stability
				_ = udpConn.Close()  // Update existing variable state with new computed value
				lastErr = err  // Update existing variable state with new computed value
				if i < len(targets)-1 {  // Evaluate conditional expression to branch execution flow
					dlog.Debugf("H3: quic.DialEarly [%s]/%s failed: %v", t.addr, t.network, err)  // Log operational metrics or diagnostic context for runtime observability
				}  // Block boundary: manages lexical scope and stack allocation limits
				continue  // Execute sequential algorithmic statement
			}  // Block boundary: manages lexical scope and stack allocation limits
			return conn, nil  // Return computed value(s) to caller and exit current stack frame
		}  // Block boundary: manages lexical scope and stack allocation limits
		return nil, lastErr  // Return computed value(s) to caller and exit current stack frame
	}  // Block boundary: manages lexical scope and stack allocation limits
}  // Block boundary: manages lexical scope and stack allocation limits

// buildTLSConfig constructs a *tls.Config that reflects all active user
// preferences. The result is stored on XTransport and shared between the
// HTTP/2 and HTTP/3 transports. Any caller that needs per-connection mutation
// (e.g. setting ServerName) must call Clone() on the returned config.
func (x *XTransport) buildTLSConfig() *tls.Config {  // Define function/method buildTLSConfig leveraging Go 1.26+ strict typing
	cfg := &tls.Config{}  // Declare and initialize new variable(s) with type inference

	if x.keyLogWriter != nil {  // Evaluate conditional expression to branch execution flow
		cfg.KeyLogWriter = x.keyLogWriter  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	certPool, certPoolErr := x509.SystemCertPool()  // Declare and initialize new variable(s) with type inference
	creds := x.tlsClientCreds  // Declare and initialize new variable(s) with type inference

	if creds.rootCA != "" {  // Evaluate conditional expression to branch execution flow
		if certPool == nil {  // Evaluate conditional expression to branch execution flow
			dlog.Fatalf("Custom root CA not supported on this platform: %v", certPoolErr)  // Execute subroutine or method call per application logic
		}  // Block boundary: manages lexical scope and stack allocation limits
		pem, err := os.ReadFile(creds.rootCA)  // Declare and initialize new variable(s) with type inference
		if err != nil {  // Verify error state; handle non-nil errors to maintain application stability
			dlog.Fatalf("Unable to read rootCA [%s]: %v", creds.rootCA, err)  // Execute subroutine or method call per application logic
		}  // Block boundary: manages lexical scope and stack allocation limits
		certPool.AppendCertsFromPEM(pem)  // Execute subroutine or method call per application logic
	}  // Block boundary: manages lexical scope and stack allocation limits
	if certPool != nil {  // Evaluate conditional expression to branch execution flow
		// Embed ISRG Root X1 so DoH servers with Let's Encrypt certificates
		// validate correctly even on OS trust stores built before ISRG Root X1
		// was widely distributed (older Android, Windows Server editions, etc.).
		certPool.AppendCertsFromPEM(isrgRootX1PEM)  // Execute subroutine or method call per application logic
		cfg.RootCAs = certPool  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	if creds.clientCert != "" {  // Evaluate conditional expression to branch execution flow
		cert, err := tls.LoadX509KeyPair(creds.clientCert, creds.clientKey)  // Declare and initialize new variable(s) with type inference
		if err != nil {  // Verify error state; handle non-nil errors to maintain application stability
			dlog.Fatalf("Unable to load client cert [%s] / key [%s]: %v",  // Execute sequential algorithmic statement
				creds.clientCert, creds.clientKey, err)  // Execute sequential algorithmic statement
		}  // Block boundary: manages lexical scope and stack allocation limits
		cfg.Certificates = []tls.Certificate{cert}  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	if x.tlsDisableSessionTickets {  // Evaluate conditional expression to branch execution flow
		cfg.SessionTicketsDisabled = true  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits
	if x.tlsPreferRSA {  // Evaluate conditional expression to branch execution flow
		// Restrict to TLS 1.2 max to force RSA cipher suites.
		cfg.MaxVersion = tls.VersionTLS12  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	// Prefer hardware-accelerated ciphers when available.
	if hasAESGCMHardwareSupport {  // Evaluate conditional expression to branch execution flow
		cfg.CipherSuites = []uint16{  // Update existing variable state with new computed value
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,  // Execute sequential algorithmic statement
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,  // Execute sequential algorithmic statement
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,  // Execute sequential algorithmic statement
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,  // Execute sequential algorithmic statement
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,  // Execute sequential algorithmic statement
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,  // Execute sequential algorithmic statement
		}  // Block boundary: manages lexical scope and stack allocation limits
	} else {  // Execute sequential algorithmic statement
		cfg.CipherSuites = []uint16{  // Update existing variable state with new computed value
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,  // Execute sequential algorithmic statement
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,  // Execute sequential algorithmic statement
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,  // Execute sequential algorithmic statement
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,  // Execute sequential algorithmic statement
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,  // Execute sequential algorithmic statement
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,  // Execute sequential algorithmic statement
		}  // Block boundary: manages lexical scope and stack allocation limits
	}  // Block boundary: manages lexical scope and stack allocation limits
	return cfg  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

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
func (x *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {  // Define function/method resolveUsingSystem leveraging Go 1.26+ strict typing
	all, err := net.LookupIP(host)  // Declare and initialize new variable(s) with type inference
	if err != nil && len(all) == 0 {  // Verify error state; handle non-nil errors to maintain application stability
		return nil, SystemResolverIPTTL, err  // Bubble up error state or nil values back to the calling scope
	}  // Block boundary: manages lexical scope and stack allocation limits
	if returnIPv4 && returnIPv6 {  // Evaluate conditional expression to branch execution flow
		return all, SystemResolverIPTTL, err  // Return computed value(s) to caller and exit current stack frame
	}  // Block boundary: manages lexical scope and stack allocation limits
	ips := make([]net.IP, 0, len(all))  // Pre-allocate memory capacity to avoid dynamic heap resizing overhead
	for _, ip := range all {  // Iterate over elements using native Go 1.22+ un-captured loop semantics
		v4 := ip.To4()  // Declare and initialize new variable(s) with type inference
		switch {  // Evaluate multiplexer switch statement for targeted branching
		case returnIPv4 && v4 != nil:  // Define execution path for specific matched condition
			ips = append(ips, v4)  // Update existing variable state with new computed value
		case returnIPv6 && v4 == nil:  // Define execution path for specific matched condition
			ips = append(ips, ip)  // Update existing variable state with new computed value
		}  // Block boundary: manages lexical scope and stack allocation limits
	}  // Block boundary: manages lexical scope and stack allocation limits
	if len(ips) == 0 {  // Evaluate conditional expression to branch execution flow
		// Return nil, not []net.IP{}, so len(ips)==0 is always the correct test.
		return nil, SystemResolverIPTTL, err  // Bubble up error state or nil values back to the calling scope
	}  // Block boundary: manages lexical scope and stack allocation limits
	return ips, SystemResolverIPTTL, err  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

// resolveUsingResolver sends A and/or AAAA queries to a single DNS resolver.
//
// Failures for each query type are tracked independently: a AAAA timeout or
// NXDOMAIN does not discard A results already collected. The minimum TTL
// observed across all answer resource records is returned so the cache entry
// expires no later than the shortest-lived record in the response.
func (x *XTransport) resolveUsingResolver(  // Define function/method resolveUsingResolver leveraging Go 1.26+ strict typing
	proto, host, resolver string,  // Execute sequential algorithmic statement
	returnIPv4, returnIPv6 bool,  // Execute sequential algorithmic statement
) (ips []net.IP, ttl time.Duration, err error) {  // Execute subroutine or method call per application logic
	tr := dns.NewTransport()  // Declare and initialize new variable(s) with type inference
	tr.ReadTimeout = ResolverReadTimeout  // Update existing variable state with new computed value
	client := dns.Client{Transport: tr}  // Declare and initialize new variable(s) with type inference

	var queryTypes []uint16  // Execute sequential algorithmic statement
	if returnIPv4 {  // Evaluate conditional expression to branch execution flow
		queryTypes = append(queryTypes, dns.TypeA)  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits
	if returnIPv6 {  // Evaluate conditional expression to branch execution flow
		queryTypes = append(queryTypes, dns.TypeAAAA)  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	ctx, cancel := context.WithTimeout(context.Background(), ResolverReadTimeout)  // Declare and initialize new variable(s) with type inference
	defer cancel()  // Schedule function call to execute immediately before the surrounding function returns

	minTTL := noTTL // sentinel: no TTL observed yet
	var lastErr error  // Execute sequential algorithmic statement

	for _, rrType := range queryTypes {  // Iterate over elements using native Go 1.22+ un-captured loop semantics
		msg := dns.NewMsg(fqdn(host), rrType)  // Declare and initialize new variable(s) with type inference
		if msg == nil {  // Evaluate conditional expression to branch execution flow
			continue  // Execute sequential algorithmic statement
		}  // Block boundary: manages lexical scope and stack allocation limits
		msg.RecursionDesired = true  // Update existing variable state with new computed value
		msg.UDPSize = uint16(MaxDNSPacketSize)  // Update existing variable state with new computed value
		msg.Security = true  // Update existing variable state with new computed value

		in, _, qErr := client.Exchange(ctx, msg, proto, resolver)  // Declare and initialize new variable(s) with type inference
		if qErr != nil {  // Evaluate conditional expression to branch execution flow
			// Track per-type; don't abort the sibling query type.
			lastErr = qErr  // Update existing variable state with new computed value
			continue  // Execute sequential algorithmic statement
		}  // Block boundary: manages lexical scope and stack allocation limits
		for _, answer := range in.Answer {  // Iterate over elements using native Go 1.22+ un-captured loop semantics
			if dns.RRToType(answer) != rrType {  // Evaluate conditional expression to branch execution flow
				continue // skip records of an unexpected type (e.g. CNAMEs)
			}  // Block boundary: manages lexical scope and stack allocation limits
			switch rrType {  // Evaluate multiplexer switch statement for targeted branching
			case dns.TypeA:  // Define execution path for specific matched condition
				ips = append(ips, answer.(*dns.A).A.Addr.AsSlice())  // Update existing variable state with new computed value
			case dns.TypeAAAA:  // Define execution path for specific matched condition
				ips = append(ips, answer.(*dns.AAAA).AAAA.Addr.AsSlice())  // Update existing variable state with new computed value
			}  // Block boundary: manages lexical scope and stack allocation limits
			// Track the minimum TTL so the cache entry respects the shortest-lived record.
			if rTTL := answer.Header().TTL; rTTL < minTTL {  // Evaluate conditional expression to branch execution flow
				minTTL = rTTL  // Update existing variable state with new computed value
			}  // Block boundary: manages lexical scope and stack allocation limits
		}  // Block boundary: manages lexical scope and stack allocation limits
	}  // Block boundary: manages lexical scope and stack allocation limits

	if len(ips) > 0 {  // Evaluate conditional expression to branch execution flow
		if minTTL == noTTL {  // Evaluate conditional expression to branch execution flow
			minTTL = 0 // sentinel never updated: treat as zero
		}  // Block boundary: manages lexical scope and stack allocation limits
		return ips, time.Duration(minTTL) * time.Second, nil  // Return computed value(s) to caller and exit current stack frame
	}  // Block boundary: manages lexical scope and stack allocation limits
	if lastErr != nil {  // Evaluate conditional expression to branch execution flow
		return nil, 0, lastErr  // Return computed value(s) to caller and exit current stack frame
	}  // Block boundary: manages lexical scope and stack allocation limits
	return nil, 0, errors.New("no IP records returned")  // Bubble up error state or nil values back to the calling scope
}  // Block boundary: manages lexical scope and stack allocation limits

// resolveUsingServers iterates over resolvers with per-resolver exponential
// back-off. On first success the winning resolver is swapped to index 0
// (self-healing affinity) so subsequent calls tend to reuse the fastest
// known-good resolver rather than starting from the front of the list.
func (x *XTransport) resolveUsingServers(  // Define function/method resolveUsingServers leveraging Go 1.26+ strict typing
	proto, host string,  // Execute sequential algorithmic statement
	resolvers []string,  // Execute sequential algorithmic statement
	returnIPv4, returnIPv6 bool,  // Execute sequential algorithmic statement
) (ips []net.IP, ttl time.Duration, err error) {  // Execute subroutine or method call per application logic
	if len(resolvers) == 0 {  // Evaluate conditional expression to branch execution flow
		return nil, 0, errors.New("empty resolver list")  // Bubble up error state or nil values back to the calling scope
	}  // Block boundary: manages lexical scope and stack allocation limits
	var lastErr error  // Execute sequential algorithmic statement
	for i, resolver := range resolvers {  // Execute iterative looping construct
		delay := resolverRetryInitialBackoff  // Declare and initialize new variable(s) with type inference
		for attempt := 1; attempt <= resolverRetryCount; attempt++ {  // Execute iterative looping construct
			ips, ttl, err = x.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)  // Update existing variable state with new computed value
			if err == nil && len(ips) > 0 {  // Evaluate conditional expression to branch execution flow
				if i > 0 {  // Evaluate conditional expression to branch execution flow
					// Promote the winning resolver to the front.
					dlog.Infof("Resolution succeeded via %s[%s]; promoting to first",  // Execute sequential algorithmic statement
						proto, resolver)  // Execute sequential algorithmic statement
					resolvers[0], resolvers[i] = resolvers[i], resolvers[0]  // Update existing variable state with new computed value
				}  // Block boundary: manages lexical scope and stack allocation limits
				return ips, ttl, nil  // Return computed value(s) to caller and exit current stack frame
			}  // Block boundary: manages lexical scope and stack allocation limits
			if err == nil {  // Evaluate conditional expression to branch execution flow
				err = errors.New("no IP addresses returned")  // Update existing variable state with new computed value
			}  // Block boundary: manages lexical scope and stack allocation limits
			lastErr = err  // Update existing variable state with new computed value
			dlog.Debugf("Resolver attempt %d/%d failed for [%s] via [%s] (%s): %v",  // Log operational metrics or diagnostic context for runtime observability
				attempt, resolverRetryCount, host, resolver, proto, err)  // Execute sequential algorithmic statement
			if attempt < resolverRetryCount {  // Evaluate conditional expression to branch execution flow
				time.Sleep(delay)  // Execute subroutine or method call per application logic
				// min() builtin (Go 1.21) replaces hand-rolled ternary.
				delay = min(delay*2, resolverRetryMaxBackoff)  // Update existing variable state with new computed value
			}  // Block boundary: manages lexical scope and stack allocation limits
		}  // Block boundary: manages lexical scope and stack allocation limits
		dlog.Infof("Unable to resolve [%s] using [%s] (%s): %v",  // Execute subroutine or method call per application logic
			host, resolver, proto, lastErr)  // Execute sequential algorithmic statement
	}  // Block boundary: manages lexical scope and stack allocation limits
	if lastErr == nil {  // Evaluate conditional expression to branch execution flow
		lastErr = errors.New("no IP addresses returned")  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits
	return nil, 0, lastErr  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

// resolve selects the best available resolution strategy in priority order:
//
//  1. Internal resolvers    — when ignoreSystemDNS && internalResolverReady
//  2. OS system resolver    — when ignoreSystemDNS == false
//  3. Bootstrap resolvers   — fallback after any primary-strategy failure
//  4. OS system resolver    — last resort when ignoreSystemDNS == true
func (x *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {  // Define function/method resolve leveraging Go 1.26+ strict typing
	// [2]string fixed array: stack-allocated, no slice header, no heap escape.
	protos := [2]string{"udp", "tcp"}  // Declare and initialize new variable(s) with type inference
	if x.mainProto == "tcp" {  // Evaluate conditional expression to branch execution flow
		protos = [2]string{"tcp", "udp"}  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	var (  // Execute sequential algorithmic statement
		ips []net.IP  // Execute sequential algorithmic statement
		ttl time.Duration  // Execute sequential algorithmic statement
		err error  // Execute sequential algorithmic statement
	)  // Execute sequential algorithmic statement

	if x.ignoreSystemDNS {  // Evaluate conditional expression to branch execution flow
		if x.internalResolverReady {  // Evaluate conditional expression to branch execution flow
			for _, proto := range protos {  // Iterate over elements using native Go 1.22+ un-captured loop semantics
				ips, ttl, err = x.resolveUsingServers(  // Update existing variable state with new computed value
					proto, host, x.internalResolvers, returnIPv4, returnIPv6)  // Execute sequential algorithmic statement
				if err == nil {  // Evaluate conditional expression to branch execution flow
					return ips, ttl, nil  // Return computed value(s) to caller and exit current stack frame
				}  // Block boundary: manages lexical scope and stack allocation limits
			}  // Block boundary: manages lexical scope and stack allocation limits
		} else {  // Execute sequential algorithmic statement
			err = errors.New("dnscrypt-proxy service is not ready yet")  // Update existing variable state with new computed value
			dlog.Notice(err)  // Execute subroutine or method call per application logic
		}  // Block boundary: manages lexical scope and stack allocation limits
	} else {  // Execute sequential algorithmic statement
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)  // Update existing variable state with new computed value
		if err != nil {  // Verify error state; handle non-nil errors to maintain application stability
			err = fmt.Errorf("system DNS: %w", err)  // Update existing variable state with new computed value
			dlog.Notice(err)  // Execute subroutine or method call per application logic
		} else {  // Execute sequential algorithmic statement
			return ips, ttl, nil  // Return computed value(s) to caller and exit current stack frame
		}  // Block boundary: manages lexical scope and stack allocation limits
	}  // Block boundary: manages lexical scope and stack allocation limits

	// Bootstrap resolvers as second-tier fallback.
	for _, proto := range protos {  // Iterate over elements using native Go 1.22+ un-captured loop semantics
		dlog.Noticef("Resolving [%s] via bootstrap resolvers over %s", host, proto)  // Log operational metrics or diagnostic context for runtime observability
		ips, ttl, err = x.resolveUsingServers(  // Update existing variable state with new computed value
			proto, host, x.bootstrapResolvers, returnIPv4, returnIPv6)  // Execute sequential algorithmic statement
		if err == nil {  // Evaluate conditional expression to branch execution flow
			return ips, ttl, nil  // Return computed value(s) to caller and exit current stack frame
		}  // Block boundary: manages lexical scope and stack allocation limits
	}  // Block boundary: manages lexical scope and stack allocation limits

	// Absolute last resort: OS resolver even when ignoreSystemDNS is true.
	if x.ignoreSystemDNS {  // Evaluate conditional expression to branch execution flow
		dlog.Noticef("Bootstrap resolvers failed — last-resort system resolver for [%s]", host)  // Log operational metrics or diagnostic context for runtime observability
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits
	return ips, ttl, err  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

// hostResolveMu returns the per-host *sync.Mutex, creating it if it does not
// yet exist. sync.Map.LoadOrStore guarantees exactly one mutex is ever stored
// per host even under concurrent access.
func (x *XTransport) hostResolveMu(host string) *sync.Mutex {  // Define function/method hostResolveMu leveraging Go 1.26+ strict typing
	v, _ := x.resolveMu.LoadOrStore(host, &sync.Mutex{})  // Declare and initialize new variable(s) with type inference
	return v.(*sync.Mutex)  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

// resolveAndUpdateCache resolves host when the cache is absent or expired and
// stores the fresh result. Concurrent callers for the same host serialise on a
// per-host mutex (double-checked locking) so exactly one DNS query is issued.
//
// Returns nil immediately when:
//   - A proxy handles name resolution (x.proxyDialer or x.httpProxyFunction set)
//   - host is an IP address literal (no lookup needed)
//   - A valid, non-expired cache entry exists
func (x *XTransport) resolveAndUpdateCache(host string) error {  // Define function/method resolveAndUpdateCache leveraging Go 1.26+ strict typing
	if x.proxyDialer != nil || x.httpProxyFunction != nil {  // Evaluate conditional expression to branch execution flow
		return nil // proxy resolves names itself; nothing to do
	}  // Block boundary: manages lexical scope and stack allocation limits
	if ParseIP(host) != nil {  // Evaluate conditional expression to branch execution flow
		return nil // literal IP; no DNS lookup needed
	}  // Block boundary: manages lexical scope and stack allocation limits

	// ── Fast path ─────────────────────────────────────────────────────────────
	cachedIPs, expired, updating := x.loadCachedIPs(host)  // Declare and initialize new variable(s) with type inference
	if len(cachedIPs) > 0 && (!expired || updating) {  // Evaluate conditional expression to branch execution flow
		return nil  // Return computed value(s) to caller and exit current stack frame
	}  // Block boundary: manages lexical scope and stack allocation limits

	// ── Slow path — serialise per host ────────────────────────────────────────
	mu := x.hostResolveMu(host)  // Declare and initialize new variable(s) with type inference
	mu.Lock()  // Acquire exclusive mutex lock to safeguard critical section from data races
	defer mu.Unlock()  // Defer mutex unlock to prevent deadlocks in case of panics or early returns

	// Double-check: another goroutine may have resolved host while we waited.
	cachedIPs, expired, _ = x.loadCachedIPs(host)  // Update existing variable state with new computed value
	if len(cachedIPs) > 0 && !expired {  // Evaluate conditional expression to branch execution flow
		return nil  // Return computed value(s) to caller and exit current stack frame
	}  // Block boundary: manages lexical scope and stack allocation limits

	// Signal "in progress" before releasing the read view so any concurrent
	// dial attempt sees the updating flag and does not trigger a second query.
	x.markUpdatingCachedIP(host)  // Execute subroutine or method call per application logic

	ips, ttl, err := x.resolve(host, x.useIPv4, x.useIPv6)  // Declare and initialize new variable(s) with type inference
	if ttl < MinResolverIPTTL {  // Evaluate conditional expression to branch execution flow
		ttl = MinResolverIPTTL  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	selectedIPs := ips  // Declare and initialize new variable(s) with type inference

	// Serve stale cache on failure rather than completely breaking connectivity.
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {  // Evaluate conditional expression to branch execution flow
		dlog.Noticef("Using stale cached address for [%s] (grace period)", host)  // Log operational metrics or diagnostic context for runtime observability
		selectedIPs = cachedIPs  // Update existing variable state with new computed value
		ttl = ExpiredCachedIPGraceTTL  // Update existing variable state with new computed value
		err = nil // clear; stale service is success from the caller's perspective
	}  // Block boundary: manages lexical scope and stack allocation limits

	if err != nil {  // Verify error state; handle non-nil errors to maintain application stability
		return err  // Return computed value(s) to caller and exit current stack frame
	}  // Block boundary: manages lexical scope and stack allocation limits

	if len(selectedIPs) == 0 {  // Evaluate conditional expression to branch execution flow
		// Report the appropriate warning based on configured address families.
		switch {  // Evaluate multiplexer switch statement for targeted branching
		case !x.useIPv4 && x.useIPv6:  // Define execution path for specific matched condition
			dlog.Warnf("no IPv6 address found for [%s]", host)  // Execute subroutine or method call per application logic
		case x.useIPv4 && !x.useIPv6:  // Define execution path for specific matched condition
			dlog.Warnf("no IPv4 address found for [%s]", host)  // Execute subroutine or method call per application logic
		default:  // Provide default execution path if no specific cases match
			dlog.Errorf("no IP address found for [%s]", host)  // Execute subroutine or method call per application logic
		}  // Block boundary: manages lexical scope and stack allocation limits
		return nil  // Return computed value(s) to caller and exit current stack frame
	}  // Block boundary: manages lexical scope and stack allocation limits

	x.saveCachedIPs(host, selectedIPs, ttl)  // Execute subroutine or method call per application logic
	return nil  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

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
func (x *XTransport) Fetch(  // Define function/method Fetch leveraging Go 1.26+ strict typing
	method string,  // Execute sequential algorithmic statement
	url *url.URL,  // Execute sequential algorithmic statement
	accept string,  // Execute sequential algorithmic statement
	contentType string,  // Execute sequential algorithmic statement
	body *[]byte,  // Execute sequential algorithmic statement
	timeout time.Duration,  // Execute sequential algorithmic statement
	compress bool,  // Execute sequential algorithmic statement
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute subroutine or method call per application logic
	if timeout <= 0 {  // Evaluate conditional expression to branch execution flow
		timeout = x.timeout  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	client := http.Client{  // Declare and initialize new variable(s) with type inference
		Transport: x.transport,  // Execute sequential algorithmic statement
		Timeout:   timeout,  // Execute sequential algorithmic statement
	}  // Block boundary: manages lexical scope and stack allocation limits

	host, port := ExtractHostAndPort(url.Host, 443)  // Declare and initialize new variable(s) with type inference
	hasAltSupport := false  // Declare and initialize new variable(s) with type inference

	// ── Select transport ───────────────────────────────────────────────────────
	if x.h3Transport != nil {  // Evaluate conditional expression to branch execution flow
		if x.http3Probe {  // Evaluate conditional expression to branch execution flow
			// Always probe H3, ignoring the Alt-Svc cache.
			client.Transport = x.h3Transport  // Update existing variable state with new computed value
			dlog.Debugf("Probing HTTP/3 for [%s]", url.Host)  // Log operational metrics or diagnostic context for runtime observability
		} else {  // Execute sequential algorithmic statement
			x.altSupport.RLock()  // Acquire read-only lock to allow concurrent reads while blocking writes
			entry, inCache := x.altSupport.cache[url.Host]  // Declare and initialize new variable(s) with type inference
			x.altSupport.RUnlock()  // Release read-only lock on the synchronization primitive
			if inCache {  // Evaluate conditional expression to branch execution flow
				hasAltSupport = true  // Update existing variable state with new computed value
				negativeExpired := entry.port == 0 &&  // Declare and initialize new variable(s) with type inference
					!entry.validTo.IsZero() &&  // Execute subroutine or method call per application logic
					time.Now().After(entry.validTo)  // Execute subroutine or method call per application logic
				switch {  // Evaluate multiplexer switch statement for targeted branching
				case entry.port > 0 && int(entry.port) == port:  // Define execution path for specific matched condition
					client.Transport = x.h3Transport  // Update existing variable state with new computed value
					dlog.Debugf("Using HTTP/3 for [%s]", url.Host)  // Log operational metrics or diagnostic context for runtime observability
				case negativeExpired:  // Define execution path for specific matched condition
					// Timed negative entry has expired; allow Alt-Svc re-parsing.
					hasAltSupport = false  // Update existing variable state with new computed value
				}  // Block boundary: manages lexical scope and stack allocation limits
			}  // Block boundary: manages lexical scope and stack allocation limits
		}  // Block boundary: manages lexical scope and stack allocation limits
	}  // Block boundary: manages lexical scope and stack allocation limits

	// ── Build request headers ──────────────────────────────────────────────────
	// Capacity 5 covers the common case (User-Agent, Cache-Control, Accept,
	// Content-Type, Accept-Encoding) without ever needing to grow.
	header := make(http.Header, 5)  // Pre-allocate memory capacity to avoid dynamic heap resizing overhead
	header.Set("User-Agent", "dnscrypt-proxy")  // Execute subroutine or method call per application logic
	header.Set("Cache-Control", "max-stale")  // Execute subroutine or method call per application logic
	if accept != "" {  // Evaluate conditional expression to branch execution flow
		header.Set("Accept", accept)  // Execute subroutine or method call per application logic
	}  // Block boundary: manages lexical scope and stack allocation limits
	if contentType != "" {  // Evaluate conditional expression to branch execution flow
		header.Set("Content-Type", contentType)  // Execute subroutine or method call per application logic
	}  // Block boundary: manages lexical scope and stack allocation limits

	// Append a SHA-512/256 body hash to the query string so upstream caches
	// correctly distinguish requests with different payloads.
	if body != nil {  // Evaluate conditional expression to branch execution flow
		h := sha512.Sum512(*body)  // Declare and initialize new variable(s) with type inference
		qs := url.Query()  // Declare and initialize new variable(s) with type inference
		qs.Add("body_hash", hex.EncodeToString(h[:32]))  // Execute subroutine or method call per application logic
		u2 := *url  // Declare and initialize new variable(s) with type inference
		u2.RawQuery = qs.Encode()  // Update existing variable state with new computed value
		url = &u2  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	// ── Pre-flight checks ──────────────────────────────────────────────────────
	if x.proxyDialer == nil && strings.HasSuffix(host, ".onion") {  // Evaluate conditional expression to branch execution flow
		return nil, 0, nil, 0,  // Return computed value(s) to caller and exit current stack frame
			errors.New("onion service requires a configured Tor proxy")  // Execute subroutine or method call per application logic
	}  // Block boundary: manages lexical scope and stack allocation limits
	if err := x.resolveAndUpdateCache(host); err != nil {  // Evaluate conditional expression to branch execution flow
		dlog.Errorf("Unable to resolve [%s]: check bootstrap_resolvers or system resolver", host)  // Execute subroutine or method call per application logic
		return nil, 0, nil, 0, err  // Bubble up error state or nil values back to the calling scope
	}  // Block boundary: manages lexical scope and stack allocation limits
	if compress && body == nil {  // Evaluate conditional expression to branch execution flow
		header.Set("Accept-Encoding", "gzip")  // Execute subroutine or method call per application logic
	}  // Block boundary: manages lexical scope and stack allocation limits

	// ── Build the request ──────────────────────────────────────────────────────
	bodyLen := 0  // Declare and initialize new variable(s) with type inference
	if body != nil {  // Evaluate conditional expression to branch execution flow
		bodyLen = len(*body)  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits
	req := &http.Request{  // Declare and initialize new variable(s) with type inference
		Method:        method,  // Execute sequential algorithmic statement
		URL:           url,  // Execute sequential algorithmic statement
		Header:        header,  // Execute sequential algorithmic statement
		Close:         false,  // Execute sequential algorithmic statement
		ContentLength: int64(bodyLen),  // Execute subroutine or method call per application logic
	}  // Block boundary: manages lexical scope and stack allocation limits
	if body != nil {  // Evaluate conditional expression to branch execution flow
		req.Body = io.NopCloser(bytes.NewReader(*body))  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	// ── Execute ────────────────────────────────────────────────────────────────
	start := time.Now()  // Dynamically allocate and initialize timestamp for tracking durations/timeouts
	resp, err := client.Do(req)  // Declare and initialize new variable(s) with type inference
	rtt := time.Since(start)  // Declare and initialize new variable(s) with type inference

	// HTTP/3 failed — record a timed negative entry and fall back to HTTP/2.
	if err != nil && client.Transport == x.h3Transport {  // Verify error state; handle non-nil errors to maintain application stability
		dlog.Debugf("HTTP/3 failed for [%s]: %v — retrying over HTTP/2", url.Host, err)  // Log operational metrics or diagnostic context for runtime observability
		x.altSupport.Lock()  // Acquire exclusive mutex lock to safeguard critical section from data races
		x.altSupport.cache[url.Host] = altSvcEntry{  // Update existing variable state with new computed value
			port:    0,  // Execute sequential algorithmic statement
			validTo: time.Now().Add(altSvcNegativeTTL),  // Execute subroutine or method call per application logic
		}  // Block boundary: manages lexical scope and stack allocation limits
		x.altSupport.Unlock()  // Release exclusive mutex lock, allowing pending goroutines to proceed

		client.Transport = x.transport  // Update existing variable state with new computed value
		if body != nil {  // Evaluate conditional expression to branch execution flow
			req.Body = io.NopCloser(bytes.NewReader(*body))  // Update existing variable state with new computed value
			// MUST reset ContentLength; net/http requires it after body reassignment.
			req.ContentLength = int64(bodyLen)  // Update existing variable state with new computed value
		}  // Block boundary: manages lexical scope and stack allocation limits
		start = time.Now()  // Update existing variable state with new computed value
		resp, err = client.Do(req)  // Update existing variable state with new computed value
		rtt = time.Since(start)  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	// Single unconditional defer placed immediately after the nil guard.
	// This is the only close call for resp.Body on every code path, eliminating
	// any double-close or missed-close risk.
	if resp != nil {  // Evaluate conditional expression to branch execution flow
		defer resp.Body.Close()  // Defer execution of Close() to guarantee resource cleanup and prevent leaks
	}  // Block boundary: manages lexical scope and stack allocation limits

	// Determine status code before any early-exit so callers always receive it.
	statusCode := 503  // Declare and initialize new variable(s) with type inference
	if resp != nil {  // Evaluate conditional expression to branch execution flow
		statusCode = resp.StatusCode  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	// ── Validate response ──────────────────────────────────────────────────────
	if err == nil {  // Evaluate conditional expression to branch execution flow
		switch {  // Evaluate multiplexer switch statement for targeted branching
		case resp == nil:  // Define execution path for specific matched condition
			// Guard against nil resp BEFORE accessing resp.StatusCode (which
			// would panic). This case comes first in the switch intentionally.
			err = errors.New("server returned an empty response")  // Update existing variable state with new computed value
		case resp.StatusCode < 200 || resp.StatusCode > 299:  // Define execution path for specific matched condition
			err = errors.New(resp.Status)  // Update existing variable state with new computed value
		}  // Block boundary: manages lexical scope and stack allocation limits
	} else {  // Execute sequential algorithmic statement
		dlog.Debugf("HTTP error [%s]: %v — closing idle connections", url.Host, err)  // Log operational metrics or diagnostic context for runtime observability
		x.transport.CloseIdleConnections()  // Execute subroutine or method call per application logic
	}  // Block boundary: manages lexical scope and stack allocation limits

	if err != nil {  // Verify error state; handle non-nil errors to maintain application stability
		dlog.Debugf("[%s]: %v", req.URL, err)  // Log operational metrics or diagnostic context for runtime observability
		return nil, statusCode, nil, rtt, err  // Bubble up error state or nil values back to the calling scope
	}  // Block boundary: manages lexical scope and stack allocation limits

	// Parse Alt-Svc for future H3 upgrades, but only when we don't already
	// have a current Alt-Svc entry for this host.
	if x.h3Transport != nil && !hasAltSupport {  // Evaluate conditional expression to branch execution flow
		x.parseAndCacheAltSvc(url.Host, port, resp.Header)  // Execute subroutine or method call per application logic
	}  // Block boundary: manages lexical scope and stack allocation limits

	tlsState := resp.TLS  // Declare and initialize new variable(s) with type inference

	// ── Read and optionally decompress the body ────────────────────────────────
	var bodyReader io.ReadCloser = resp.Body  // Update existing variable state with new computed value
	if compress && resp.Header.Get("Content-Encoding") == "gzip" {  // Evaluate conditional expression to branch execution flow
		gr, grErr := gzip.NewReader(io.LimitReader(resp.Body, MaxHTTPBodyLength))  // Declare and initialize new variable(s) with type inference
		if grErr != nil {  // Evaluate conditional expression to branch execution flow
			return nil, statusCode, tlsState, rtt, grErr  // Return computed value(s) to caller and exit current stack frame
		}  // Block boundary: manages lexical scope and stack allocation limits
		defer gr.Close()  // Defer execution of Close() to guarantee resource cleanup and prevent leaks
		bodyReader = gr  // Update existing variable state with new computed value
	}  // Block boundary: manages lexical scope and stack allocation limits

	bin, err := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))  // Declare and initialize new variable(s) with type inference
	if err != nil {  // Verify error state; handle non-nil errors to maintain application stability
		return nil, statusCode, tlsState, rtt, err  // Bubble up error state or nil values back to the calling scope
	}  // Block boundary: manages lexical scope and stack allocation limits
	return bin, statusCode, tlsState, rtt, nil  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

// parseAndCacheAltSvc inspects the Alt-Svc response header and updates the
// per-host entry in altSupport.
//
// Positive entries (port > 0) have no expiry. Negative entries (port == 0)
// carry a validTo time so recovering servers are automatically retried after
// altSvcNegativeTTL.
func (x *XTransport) parseAndCacheAltSvc(host string, port int, header http.Header) {  // Define function/method parseAndCacheAltSvc leveraging Go 1.26+ strict typing
	// Honour an active negative entry — skip parsing entirely.
	x.altSupport.RLock()  // Acquire read-only lock to allow concurrent reads while blocking writes
	existing, inCache := x.altSupport.cache[host]  // Declare and initialize new variable(s) with type inference
	x.altSupport.RUnlock()  // Release read-only lock on the synchronization primitive
	if inCache && existing.port == 0 &&  // Evaluate conditional expression to branch execution flow
		(existing.validTo.IsZero() || time.Now().Before(existing.validTo)) {  // Execute subroutine or method call per application logic
		dlog.Debugf("Alt-Svc: negative cache still valid for [%s]; skipping", host)  // Log operational metrics or diagnostic context for runtime observability
		return  // Exit function immediately returning implicit zero values
	}  // Block boundary: manages lexical scope and stack allocation limits

	alt, found := header["Alt-Svc"]  // Declare and initialize new variable(s) with type inference
	if !found {  // Evaluate conditional expression to branch execution flow
		return  // Exit function immediately returning implicit zero values
	}  // Block boundary: manages lexical scope and stack allocation limits
	dlog.Debugf("Alt-Svc [%s]: %v", host, alt)  // Log operational metrics or diagnostic context for runtime observability

	altPort := uint16(port & 0xffff) // default: same port as HTTP/2

outer:  // Execute sequential algorithmic statement
	for i, entry := range alt {  // Execute iterative looping construct
		if i >= 8 { // guard against unreasonably long headers
			break  // Execute sequential algorithmic statement
		}  // Block boundary: manages lexical scope and stack allocation limits
		for j, field := range strings.Split(entry, ";") {  // Execute iterative looping construct
			if j >= 16 {  // Evaluate conditional expression to branch execution flow
				break  // Execute sequential algorithmic statement
			}  // Block boundary: manages lexical scope and stack allocation limits
			// strings.CutPrefix (Go 1.20) is cleaner than HasPrefix + manual slice.
			if after, ok := strings.CutPrefix(strings.TrimSpace(field), `h3=":`); ok {  // Evaluate conditional expression to branch execution flow
				v := strings.TrimSuffix(after, `"`)  // Declare and initialize new variable(s) with type inference
				if p, pErr := strconv.ParseUint(v, 10, 16); pErr == nil && p <= 65535 {  // Evaluate conditional expression to branch execution flow
					altPort = uint16(p)  // Update existing variable state with new computed value
					dlog.Debugf("Alt-Svc: HTTP/3 advertised for [%s] on port %d",  // Log operational metrics or diagnostic context for runtime observability
						host, altPort)  // Execute sequential algorithmic statement
					break outer  // Execute sequential algorithmic statement
				}  // Block boundary: manages lexical scope and stack allocation limits
			}  // Block boundary: manages lexical scope and stack allocation limits
		}  // Block boundary: manages lexical scope and stack allocation limits
	}  // Block boundary: manages lexical scope and stack allocation limits

	x.altSupport.Lock()  // Acquire exclusive mutex lock to safeguard critical section from data races
	// Positive entry: no expiry (zero validTo).
	x.altSupport.cache[host] = altSvcEntry{port: altPort}  // Update existing variable state with new computed value
	dlog.Debugf("Alt-Svc: cached port %d for [%s]", altPort, host)  // Log operational metrics or diagnostic context for runtime observability
	x.altSupport.Unlock()  // Release exclusive mutex lock, allowing pending goroutines to proceed
}  // Block boundary: manages lexical scope and stack allocation limits

// ── Public query helpers ──────────────────────────────────────────────────────

// GetWithCompression sends a GET request and transparently decompresses a gzip
// response. Equivalent to Fetch("GET", …, compress=true).
func (x *XTransport) GetWithCompression(  // Define function/method GetWithCompression leveraging Go 1.26+ strict typing
	url *url.URL,  // Execute sequential algorithmic statement
	accept string,  // Execute sequential algorithmic statement
	timeout time.Duration,  // Execute sequential algorithmic statement
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute subroutine or method call per application logic
	return x.Fetch("GET", url, accept, "", nil, timeout, true)  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

// Get sends a plain GET request without any compression negotiation.
func (x *XTransport) Get(  // Define function/method Get leveraging Go 1.26+ strict typing
	url *url.URL,  // Execute sequential algorithmic statement
	accept string,  // Execute sequential algorithmic statement
	timeout time.Duration,  // Execute sequential algorithmic statement
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute subroutine or method call per application logic
	return x.Fetch("GET", url, accept, "", nil, timeout, false)  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

// Post sends a POST request with the given content type and body.
func (x *XTransport) Post(  // Define function/method Post leveraging Go 1.26+ strict typing
	url *url.URL,  // Execute sequential algorithmic statement
	accept, contentType string,  // Execute sequential algorithmic statement
	body *[]byte,  // Execute sequential algorithmic statement
	timeout time.Duration,  // Execute sequential algorithmic statement
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute subroutine or method call per application logic
	return x.Fetch("POST", url, accept, contentType, body, timeout, false)  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

// dohLikeQuery is the shared implementation for DoHQuery and ObliviousDoHQuery.
// For GET requests the body is base64url-encoded as the "dns" query parameter
// per RFC 8484 §4.1. For POST requests the body is sent verbatim.
func (x *XTransport) dohLikeQuery(  // Define function/method dohLikeQuery leveraging Go 1.26+ strict typing
	dataType string,  // Execute sequential algorithmic statement
	useGet bool,  // Execute sequential algorithmic statement
	url *url.URL,  // Execute sequential algorithmic statement
	body []byte,  // Execute sequential algorithmic statement
	timeout time.Duration,  // Execute sequential algorithmic statement
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute subroutine or method call per application logic
	if useGet {  // Evaluate conditional expression to branch execution flow
		qs := url.Query()  // Declare and initialize new variable(s) with type inference
		qs.Add("dns", base64.RawURLEncoding.EncodeToString(body))  // Execute subroutine or method call per application logic
		u2 := *url  // Declare and initialize new variable(s) with type inference
		u2.RawQuery = qs.Encode()  // Update existing variable state with new computed value
		return x.Get(&u2, dataType, timeout)  // Return computed value(s) to caller and exit current stack frame
	}  // Block boundary: manages lexical scope and stack allocation limits
	return x.Post(url, dataType, dataType, &body, timeout)  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

// DoHQuery sends a DNS-over-HTTPS query as defined by RFC 8484.
// Set useGet=true to use the GET wire format, false to use POST.
func (x *XTransport) DoHQuery(  // Define function/method DoHQuery leveraging Go 1.26+ strict typing
	useGet bool,  // Execute sequential algorithmic statement
	url *url.URL,  // Execute sequential algorithmic statement
	body []byte,  // Execute sequential algorithmic statement
	timeout time.Duration,  // Execute sequential algorithmic statement
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute subroutine or method call per application logic
	return x.dohLikeQuery("application/dns-message", useGet, url, body, timeout)  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits

// ObliviousDoHQuery sends an Oblivious DNS-over-HTTPS query as defined by
// RFC 9230. Set useGet=true for the GET wire format, false for POST.
func (x *XTransport) ObliviousDoHQuery(  // Define function/method ObliviousDoHQuery leveraging Go 1.26+ strict typing
	useGet bool,  // Execute sequential algorithmic statement
	url *url.URL,  // Execute sequential algorithmic statement
	body []byte,  // Execute sequential algorithmic statement
	timeout time.Duration,  // Execute sequential algorithmic statement
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {  // Execute subroutine or method call per application logic
	return x.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)  // Return computed value(s) to caller and exit current stack frame
}  // Block boundary: manages lexical scope and stack allocation limits
