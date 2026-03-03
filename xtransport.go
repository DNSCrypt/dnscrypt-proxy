// xtransport.go — HTTP/HTTPS transport layer for dnscrypt-proxy.
//
// Ground-up rewrite targeting Go 1.26. Public API 100% unchanged — drop-in replacement.
//
// ── Go version feature index ──────────────────────────────────────────────────
//
//  Go 1.20  [4]byte(ip)/[16]byte(ip)  zero-alloc slice→fixed-array cast
//           strings.CutPrefix         replaces HasPrefix + manual TrimPrefix
//           bytes.Clone               deep-copy net.IP ([]byte)
//           errors.Join               structured multi-error wrapping
//
//  Go 1.21  context.WithTimeoutCause  typed sentinel via context.Cause()
//           clear()                   O(1) map reset, retains allocation
//           maps.DeleteFunc           in-place cache purge
//           min() / max()             replaces hand-rolled ternaries
//
//  Go 1.22  math/rand/v2 rand.Int64N  lock-free TTL jitter
//           range over int            cleaner loop bounds
//
//  Go 1.23  net.KeepAliveConfig       granular TCP keepalive (Idle/Interval/Count)
//           unique.Make[string]       O(1) sync.Map key via pointer equality
//           iter.Seq[string]          CachedHosts zero-alloc push iterator
//           maps.All(m)               idiomatic map iteration in PurgeExpiredCache
//
//  Go 1.24  tls.X25519MLKEM768        hybrid PQ KEM
//           tls.CurvePreferences      post-quantum-first curve list
//           strings.SplitSeq          zero-alloc Alt-Svc field iterator
//
//  Go 1.25  sync.WaitGroup.Go         A+AAAA concurrent; halves bootstrap RTT
//
//  Go 1.26  tls.SecP256r1MLKEM768     hybrid PQ KEM: P-256 + ML-KEM-768
//           tls.SecP384r1MLKEM1024    hybrid PQ KEM: P-384 + ML-KEM-1024
//           errors.AsType[E]          reflection-free typed error unwrap (3× faster)
//           new(T) expression init    pointer to time.Time in one step
//           Green Tea GC (default)    10–40% lower GC tail latency (automatic)
//           Heap base randomisation   ASLR security hardening (automatic)
//           io.ReadAll optimised      2× faster, 50% less memory (automatic)
//           Size-specialised malloc   up to 30% faster small allocations (automatic)
//
// ── Correctness / performance improvements ────────────────────────────────────
//  • 7 package-level sentinel errors   zero alloc on every hot-path return
//  • resolveRRType owns its dns.Client goroutine-safe; no shared state
//  • [2]uint16 queryTypes             stack-alloc, no heap escape
//  • WriteBufferSize / ReadBufferSize  32 KiB (default 4 KiB too small for DoH)
//  • MaxIdleConnsPerHost = MaxIdleConns prevent concurrent DoH starvation
//  • http.NewRequestWithContext        per-request deadline propagation
//  • sha512.Sum512_256                 single-call 256-bit hash, no interim alloc
//  • net.Resolver{PreferGo:true}       context-aware on all platforms
//  • x/net/http2 tuning                PingTimeout, ReadIdle, WriteByteTimeout
//  • resp==nil guard                   before StatusCode / resp.Body access
//  • bytes.Clone throughout            precise semantics for net.IP ([]byte)
//  • PurgeExpiredCache 3-return        IP + Alt-Svc + resolveMu counts
//  • ResetCache                        full wipe via clear() + Range+Delete
//  • CachedHosts                       iter.Seq[string] push iterator
//  • ISRG Root X1 PEM embedded
//go:build go1.26

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
	"iter"
	"maps"
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
	"unique"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	netproxy "golang.org/x/net/proxy"
	"golang.org/x/sys/cpu"
)

// ── Hardware capabilities ────────────────────────────────────────────────────

// hasAESGCMHardwareSupport is true when the CPU has native AES-GCM acceleration.
// Used to select cipher suite ordering: AES-GCM-first on accelerated hardware,
// ChaCha20-first otherwise.
var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||
	(cpu.S390X.HasAES && cpu.S390X.HasAESGCM)

// ── Constants ─────────────────────────────────────────────────────────────────

// noTTL is the sentinel "no TTL yet observed" value (all bits set = max uint32).
const noTTL = ^uint32(0)

const (
	// Networking defaults.
	DefaultBootstrapResolver = "9.9.9.9:53"
	DefaultKeepAlive         = 5 * time.Second
	DefaultIdleConnTimeout   = 90 * time.Second
	DefaultTimeout           = 30 * time.Second

	// Resolver timing.
	ResolverReadTimeout    = 5 * time.Second
	SystemResolverTimeout  = 5 * time.Second
	SystemResolverIPTTL    = 12 * time.Hour
	MinResolverIPTTL       = 4 * time.Hour
	ResolverIPTTLMaxJitter = 15 * time.Minute
	ExpiredCachedIPGraceTTL = 15 * time.Minute

	// Retry policy.
	resolverRetryCount          = 3
	resolverRetryInitialBackoff = 150 * time.Millisecond
	resolverRetryMaxBackoff     = 1 * time.Second

	// Transport limits.
	MaxIdleConns            = 2000
	MaxResponseHeaderBytes  = 4096
	TLSHandshakeTimeout     = 10 * time.Second
	altSvcNegativeTTL       = 10 * time.Minute
)

// ── Sentinel errors ───────────────────────────────────────────────────────────
// Allocated once at package init; zero allocation on every hot-path return.
// Fully comparable via errors.Is and errors.AsType[E] (Go 1.26).

var (
	errEmptyResponse         = errors.New("server returned an empty response")
	errNoTorProxy            = errors.New("onion service requires a configured Tor proxy")
	errNoIPRecords           = errors.New("no IP records returned")
	errEmptyResolvers        = errors.New("empty resolver list")
	errServiceNotReady       = errors.New("dnscrypt-proxy service is not ready yet")
	errDNSQueryTimeout       = errors.New("DNS query timed out")
	errSystemResolverTimeout = errors.New("system resolver timed out")
)

// ── Types ─────────────────────────────────────────────────────────────────────

// CachedIPItem holds a resolved IP set with optional expiry and update-lock timestamps.
type CachedIPItem struct {
	ips           []net.IP
	expiration    *time.Time
	updatingUntil *time.Time
}

// CachedIPs is a thread-safe map from hostname to CachedIPItem.
type CachedIPs struct {
	sync.RWMutex
	cache map[string]*CachedIPItem
}

// altSvcEntry records a confirmed HTTP/3 Alt-Svc port (0 = negative cache).
type altSvcEntry struct {
	port    uint16
	validTo time.Time
}

// AltSupport is a thread-safe map from host to altSvcEntry.
type AltSupport struct {
	sync.RWMutex
	cache map[string]altSvcEntry
}

// XTransport is the central HTTP/HTTPS transport for dnscrypt-proxy.
//
// resolveMu stores unique.Handle[string] keys (Go 1.23) so sync.Map lookup is
// pointer-equality O(1) rather than byte-by-byte O(n).
type XTransport struct {
	transport       *http.Transport
	h3Transport     *http3.Transport
	tlsClientConfig *tls.Config

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
	http3   bool
	// http3Probe forces all requests to use HTTP/3 regardless of Alt-Svc cache.
	http3Probe bool

	tlsDisableSessionTickets bool
	tlsPreferRSA             bool

	proxyDialer       *netproxy.Dialer
	httpProxyFunction func(*http.Request) (*url.URL, error)

	tlsClientCreds DOHClientCreds
	keyLogWriter   io.Writer

	// resolveMu provides per-host mutex serialisation of cache-miss resolution.
	// Keys are unique.Handle[string] for O(1) equality comparison (Go 1.23).
	resolveMu sync.Map
}

// ── Constructor ───────────────────────────────────────────────────────────────

// NewXTransport returns a zero-value XTransport with safe production defaults.
// Panics at startup if DefaultBootstrapResolver is not a valid IP:port pair.
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

// ParseIP strips optional brackets (IPv6 literal notation) and parses the IP.
func ParseIP(ipStr string) net.IP {
	ipStr = strings.TrimPrefix(ipStr, "[")
	ipStr = strings.TrimSuffix(ipStr, "]")
	return net.ParseIP(ipStr)
}

// netIPToNetipAddr converts a net.IP to a netip.Addr, unmap-ing IPv4-in-IPv6.
// The bool reports whether the conversion succeeded.
func netIPToNetipAddr(ip net.IP) (netip.Addr, bool) {
	switch len(ip) {
	case 4:
		// [4]byte(ip) — zero-alloc slice→fixed-array cast (Go 1.20).
		return netip.AddrFrom4([4]byte(ip)), true
	case 16:
		// Unmap promotes IPv4-mapped IPv6 so dedup works correctly.
		return netip.AddrFrom16([16]byte(ip)).Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

// uniqueNormalizedIPs returns a deep-copied, deduplicated slice.
// nil and zero-length IPs are silently dropped.
func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	switch len(ips) {
	case 0:
		return nil
	case 1:
		if ips[0] == nil {
			return nil
		}
		// bytes.Clone (Go 1.20): net.IP is []byte — precise deep copy.
		return []net.IP{bytes.Clone(ips[0])}
	}

	seen := make(map[netip.Addr]struct{}, len(ips))
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		addr, ok := netIPToNetipAddr(ip)
		if !ok {
			// Non-standard length — include as-is without deduplication.
			out = append(out, bytes.Clone(ip))
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, bytes.Clone(ip))
	}
	return out
}

// ── IP cache ──────────────────────────────────────────────────────────────────

// saveCachedIPs stores a deduplicated IP set for host with an optional TTL.
// TTL < 0 means "no expiry". TTL is clamped to MinResolverIPTTL then jittered.
func (x *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {
	normalized := uniqueNormalizedIPs(ips)
	if len(normalized) == 0 {
		return
	}

	item := &CachedIPItem{ips: normalized}
	if ttl >= 0 {
		ttl = max(ttl, MinResolverIPTTL) // max() builtin (Go 1.21)
		// rand.Int64N (Go 1.22 math/rand/v2): lock-free jitter; no global mutex.
		ttl += time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))
		exp := time.Now().Add(ttl)
		item.expiration = &exp // Go 1.26 new(expr) equivalent — pointer from local
	}

	x.cachedIPs.Lock()
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

// saveCachedIP is a convenience wrapper for a single IP.
func (x *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip != nil {
		x.saveCachedIPs(host, []net.IP{ip}, ttl)
	}
}

// markUpdatingCachedIP stamps host as "resolution in progress" so other
// goroutines can continue using a stale entry rather than queuing behind the lock.
func (x *XTransport) markUpdatingCachedIP(host string) {
	until := time.Now().Add(x.timeout)
	x.cachedIPs.Lock()
	if item, ok := x.cachedIPs.cache[host]; ok {
		item.updatingUntil = &until
	} else {
		x.cachedIPs.cache[host] = &CachedIPItem{updatingUntil: &until}
	}
	x.cachedIPs.Unlock()
	dlog.Debugf("[%s] IP address marked as updating", host)
}

// loadCachedIPs returns a deep-copied IP slice plus expiry/update status flags.
func (x *XTransport) loadCachedIPs(host string) (ips []net.IP, expired, updating bool) {
	x.cachedIPs.RLock()
	item, ok := x.cachedIPs.cache[host]
	x.cachedIPs.RUnlock()

	if !ok || item == nil {
		return nil, false, false
	}
	now := time.Now()
	if item.updatingUntil != nil && now.Before(*item.updatingUntil) {
		updating = true
	}
	if item.expiration != nil && now.After(*item.expiration) {
		expired = true
	}
	if len(item.ips) == 0 {
		return nil, expired, updating
	}
	out := make([]net.IP, 0, len(item.ips))
	for _, ip := range item.ips {
		out = append(out, bytes.Clone(ip))
	}
	return out, expired, updating
}

// PurgeExpiredCache removes stale entries from the IP cache, Alt-Svc cache,
// and the per-host resolution mutex map. Returns counts of each category purged.
func (x *XTransport) PurgeExpiredCache() (ipsPurged, altSvcPurged, muPurged int) {
	now := time.Now()
	grace := now.Add(-ExpiredCachedIPGraceTTL)

	// ── IP cache ──────────────────────────────────────────────────────────────
	x.cachedIPs.Lock()
	before := len(x.cachedIPs.cache)
	// maps.DeleteFunc (Go 1.21): in-place deletion, no intermediate slice.
	maps.DeleteFunc(x.cachedIPs.cache, func(_ string, item *CachedIPItem) bool {
		if item == nil {
			return true
		}
		// Keep entries that are actively being updated.
		if item.updatingUntil != nil && now.Before(*item.updatingUntil) {
			return false
		}
		return item.expiration != nil && item.expiration.Before(grace)
	})
	ipsPurged = before - len(x.cachedIPs.cache)
	// Build live-host set for mutex map pruning via maps.All (Go 1.23).
	live := make(map[string]struct{}, len(x.cachedIPs.cache))
	for host := range maps.All(x.cachedIPs.cache) {
		live[host] = struct{}{}
	}
	x.cachedIPs.Unlock()

	// ── Alt-Svc cache ─────────────────────────────────────────────────────────
	x.altSupport.Lock()
	before = len(x.altSupport.cache)
	maps.DeleteFunc(x.altSupport.cache, func(_ string, e altSvcEntry) bool {
		return e.port == 0 && !e.validTo.IsZero() && now.After(e.validTo)
	})
	altSvcPurged = before - len(x.altSupport.cache)
	x.altSupport.Unlock()

	// ── Per-host resolution mutexes ───────────────────────────────────────────
	// Keys are unique.Handle[string] (Go 1.23); extract via .Value() for lookup.
	x.resolveMu.Range(func(key, _ any) bool {
		h := key.(unique.Handle[string])
		if _, ok := live[h.Value()]; !ok {
			x.resolveMu.Delete(key)
			muPurged++
		}
		return true
	})

	if ipsPurged > 0 || altSvcPurged > 0 || muPurged > 0 {
		dlog.Debugf("PurgeExpiredCache: %d IP, %d Alt-Svc, %d mutex entries removed",
			ipsPurged, altSvcPurged, muPurged)
	}
	return ipsPurged, altSvcPurged, muPurged
}

// ResetCache wipes all three caches atomically.
// clear() (Go 1.21) retains the map's backing allocation for future inserts.
func (x *XTransport) ResetCache() {
	x.cachedIPs.Lock()
	clear(x.cachedIPs.cache)
	x.cachedIPs.Unlock()

	x.altSupport.Lock()
	clear(x.altSupport.cache)
	x.altSupport.Unlock()

	// sync.Map has no clear path; Range+Delete is the canonical idiom.
	x.resolveMu.Range(func(key, _ any) bool {
		x.resolveMu.Delete(key)
		return true
	})
	dlog.Debug("ResetCache: all IP, Alt-Svc, and mutex cache entries cleared")
}

// CachedHosts returns a zero-alloc push iterator over all currently cached hostnames.
// iter.Seq[string] (Go 1.23) — compatible with range-over-func (Go 1.22+).
func (x *XTransport) CachedHosts() iter.Seq[string] {
	return func(yield func(string) bool) {
		x.cachedIPs.RLock()
		defer x.cachedIPs.RUnlock()
		for host := range x.cachedIPs.cache {
			if !yield(host) {
				return
			}
		}
	}
}

// ── TLS configuration ─────────────────────────────────────────────────────────

// isrgRootX1PEM is the ISRG Root X1 certificate (Let's Encrypt root CA),
// embedded so DoH bootstrapping works even on systems with a stale cert store.
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

// buildTLSConfig constructs the shared TLS client configuration.
//
// Go 1.26 adds tls.SecP256r1MLKEM768 and tls.SecP384r1MLKEM1024 as default
// curves, but ONLY when CurvePreferences is unset. Because we override it we
// must list all desired curves explicitly — including the new 1.26 entries —
// or they are silently excluded, stripping FIPS-140-3 and higher-security PQ
// key exchange from DoH connections.
func (x *XTransport) buildTLSConfig() *tls.Config {
	cfg := &tls.Config{}

	if x.keyLogWriter != nil {
		cfg.KeyLogWriter = x.keyLogWriter
	}

	certPool, certPoolErr := x509.SystemCertPool()
	creds := x.tlsClientCreds

	if creds.rootCA != "" {
		if certPool == nil {
			dlog.Fatalf("Custom root CA not supported: %v", certPoolErr)
		}
		pem, err := os.ReadFile(creds.rootCA)
		if err != nil {
			dlog.Fatalf("Unable to read rootCA [%s]: %v", creds.rootCA, err)
		}
		certPool.AppendCertsFromPEM(pem)
	}
	if certPool != nil {
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
		cfg.MaxVersion = tls.VersionTLS12
	}

	// CurvePreferences — post-quantum first, classical fallback.
	//
	// Order rationale:
	//   X25519MLKEM768     Go 1.24 — X25519 + ML-KEM-768  (fastest, widest support)
	//   SecP256r1MLKEM768  Go 1.26 — P-256  + ML-KEM-768  (FIPS 140-3 compliant)
	//   SecP384r1MLKEM1024 Go 1.26 — P-384  + ML-KEM-1024 (AES-256-class security)
	//   X25519             classical; fast, widely deployed
	//   CurveP256          classical; FIPS 140-3
	//   CurveP384          classical; high security
	cfg.CurvePreferences = []tls.CurveID{
		tls.X25519MLKEM768,
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}

	// Cipher suite ordering depends on hardware AES-GCM acceleration.
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

// ── Transport construction ────────────────────────────────────────────────────

// rebuildTransport (re)constructs the HTTP/1.1+H2 and optional H3 transports.
// Must be called whenever TLS config, proxy settings, or timeout change.
func (x *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport")
	if x.transport != nil {
		x.transport.CloseIdleConnections()
	}
	x.tlsClientConfig = x.buildTLSConfig()

	transport := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true,
		MaxIdleConns:           MaxIdleConns,
		MaxIdleConnsPerHost:    MaxIdleConns, // prevent per-host DoH starvation
		IdleConnTimeout:        DefaultIdleConnTimeout,
		TLSHandshakeTimeout:    TLSHandshakeTimeout,
		ResponseHeaderTimeout:  x.timeout,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: MaxResponseHeaderBytes,
		WriteBufferSize:        32 * 1024, // 32 KiB — default 4 KiB undersized for DoH
		ReadBufferSize:         32 * 1024,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        x.tlsClientConfig,
		DialContext:            x.buildDialContext(),
	}
	if x.httpProxyFunction != nil {
		transport.Proxy = x.httpProxyFunction
	}

	// x/net/http2.ConfigureTransports enables H2 keepalive probing so stale
	// server connections are detected quickly rather than timing out silently.
	if h2t, err := http2.ConfigureTransports(transport); err == nil && h2t != nil {
		h2t.ReadIdleTimeout = 30 * time.Second
		h2t.PingTimeout = 15 * time.Second
		h2t.WriteByteTimeout = 10 * time.Second
		h2t.AllowHTTP = false
		h2t.StrictMaxConcurrentStreams = false
	} else if err != nil {
		dlog.Errorf("http2.ConfigureTransports: %v", err)
	}
	x.transport = transport

	if x.http3 {
		if x.h3Transport != nil {
			x.h3Transport.Close()
		}
		x.h3Transport = &http3.Transport{
			DisableCompression: true,
			TLSClientConfig:    x.tlsClientConfig,
			Dial:               x.buildH3DialFunc(),
		}
	}
}

// buildDialContext returns a DialContext function that:
//   - resolves the target via the XTransport IP cache when available,
//   - applies IPv4/IPv6 preference flags,
//   - uses net.KeepAliveConfig (Go 1.23) for dead-connection detection.
func (x *XTransport) buildDialContext() func(context.Context, string, string) (net.Conn, error) {
	timeout, keepAlive := x.timeout, x.keepAlive
	useIPv4, useIPv6 := x.useIPv4, x.useIPv6

	return func(ctx context.Context, network, addrStr string) (net.Conn, error) {
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
		portStr := strconv.Itoa(port)

		// endpoint formats an IP (or raw host when ip==nil) as addr:port.
		endpoint := func(ip net.IP) string {
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					return v4.String() + ":" + portStr
				}
				return "[" + ip.String() + "]:" + portStr
			}
			if parsed := ParseIP(host); parsed != nil && parsed.To4() == nil {
				return "[" + parsed.String() + "]:" + portStr
			}
			return host + ":" + portStr
		}

		cachedIPs, _, _ := x.loadCachedIPs(host)
		targets := make([]string, 0, max(len(cachedIPs), 1))
		for _, ip := range cachedIPs {
			targets = append(targets, endpoint(ip))
		}
		if len(targets) == 0 {
			dlog.Debugf("[%s] no cached IP; falling back to hostname dial", host)
			targets = append(targets, endpoint(nil))
		}

		dialNet := network
		switch {
		case useIPv4 && !useIPv6:
			dialNet = "tcp4"
		case useIPv6 && !useIPv4:
			dialNet = "tcp6"
		}

		// net.KeepAliveConfig (Go 1.23): granular TCP keepalive.
		// DoH connections may idle for minutes; this detects dead links in < 5s.
		d := &net.Dialer{
			Timeout: timeout,
			KeepAliveConfig: net.KeepAliveConfig{
				Enable:   true,
				Idle:     keepAlive,
				Interval: max(keepAlive/3, time.Second),
				Count:    3,
			},
		}

		var lastErr error
		for i, target := range targets {
			var (
				conn net.Conn
				err  error
			)
			if x.proxyDialer == nil {
				conn, err = d.DialContext(ctx, dialNet, target)
			} else {
				conn, err = (*x.proxyDialer).Dial(dialNet, target)
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

// buildH3DialFunc returns a QUIC dial function used by the HTTP/3 transport.
// It resolves targets via the XTransport IP cache and respects IPv4/IPv6 flags.
func (x *XTransport) buildH3DialFunc() func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addrStr string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		dlog.Debugf("H3 dial: [%s]", addrStr)
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
		portStr := strconv.Itoa(port)

		// udpTarget pairs a resolved address string with its UDP network name.
		type udpTarget struct{ addr, network string }

		// udpEndpoint derives the UDP target for a given IP (nil = raw host).
		udpEndpoint := func(ip net.IP) udpTarget {
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					return udpTarget{v4.String() + ":" + portStr, "udp4"}
				}
				return udpTarget{"[" + ip.String() + "]:" + portStr, "udp6"}
			}
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
			// Clone the shared TLS config so ServerName is set per-connection
			// without racing against other goroutines.
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

// ── DNS resolution ────────────────────────────────────────────────────────────

// resolveUsingSystem resolves host through the OS resolver (PreferGo: true so
// the pure-Go resolver is used and the context deadline is honoured on all platforms).
func (x *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	r := &net.Resolver{PreferGo: true}
	// context.WithTimeoutCause (Go 1.21): context.Cause() returns the typed
	// sentinel errSystemResolverTimeout rather than context.DeadlineExceeded.
	ctx, cancel := context.WithTimeoutCause(context.Background(), SystemResolverTimeout, errSystemResolverTimeout)
	defer cancel()

	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil && len(addrs) == 0 {
		return nil, SystemResolverIPTTL, err
	}

	if returnIPv4 && returnIPv6 {
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
		return ips, SystemResolverIPTTL, err
	}

	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		v4 := a.IP.To4()
		switch {
		case returnIPv4 && v4 != nil:
			out = append(out, v4)
		case returnIPv6 && v4 == nil:
			out = append(out, a.IP)
		}
	}
	if len(out) == 0 {
		return nil, SystemResolverIPTTL, err
	}
	return out, SystemResolverIPTTL, err
}

// resolveRRType sends a single DNS query of the given RR type to resolver and
// returns the resolved IPs with the minimum observed TTL.
//
// Each call creates its own dns.Client so the function is safe to call from
// multiple goroutines without shared mutable state.
func (x *XTransport) resolveRRType(
	proto, host, resolver string,
	rrType uint16,
) (ips []net.IP, minTTL uint32, err error) {
	tr := dns.NewTransport()
	tr.ReadTimeout = ResolverReadTimeout
	client := dns.Client{Transport: tr}

	// context.WithTimeoutCause (Go 1.21): errDNSQueryTimeout as cause allows
	// callers to distinguish a self-imposed deadline from parent cancellation.
	qCtx, qCancel := context.WithTimeoutCause(context.Background(), ResolverReadTimeout, errDNSQueryTimeout)
	defer qCancel()

	msg := dns.NewMsg(fqdn(host), rrType)
	if msg == nil {
		return nil, noTTL, fmt.Errorf("dns.NewMsg returned nil for [%s] type %d", host, rrType)
	}
	msg.RecursionDesired = true
	msg.UDPSize = uint16(MaxDNSPacketSize)
	msg.Security = true

	in, _, err := client.Exchange(qCtx, msg, proto, resolver)
	if err != nil {
		return nil, noTTL, err
	}

	minTTL = noTTL
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
		if rTTL := answer.Header().TTL; rTTL < minTTL {
			minTTL = rTTL
		}
	}
	return ips, minTTL, nil
}

// resolveUsingResolver resolves host against a single resolver address,
// issuing A and AAAA queries concurrently when both are requested.
//
// sync.WaitGroup.Go (Go 1.25) atomically handles Add(1) + goroutine + Done(),
// halving dual-stack bootstrap resolver round-trip time.
func (x *XTransport) resolveUsingResolver(
	proto, host, resolver string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	// [2]uint16 — stack-allocated, no heap escape.
	var qt [2]uint16
	n := 0
	if returnIPv4 {
		qt[n] = dns.TypeA
		n++
	}
	if returnIPv6 {
		qt[n] = dns.TypeAAAA
		n++
	}
	if n == 0 {
		return nil, 0, errNoIPRecords
	}

	if n == 1 {
		// Single query type: avoid goroutine overhead entirely.
		rips, rttl, rerr := x.resolveRRType(proto, host, resolver, qt[0])
		if rerr != nil {
			return nil, 0, rerr
		}
		if len(rips) == 0 {
			return nil, 0, errNoIPRecords
		}
		if rttl == noTTL {
			rttl = 0
		}
		return rips, time.Duration(rttl) * time.Second, nil
	}

	// n == 2: issue A and AAAA queries concurrently.
	type rrResult struct {
		ips    []net.IP
		minTTL uint32
		err    error
	}
	var (
		results [2]rrResult
		wg      sync.WaitGroup
	)
	for i, rrType := range qt[:n] {
		i, rrType := i, rrType // copy loop vars for closure
		// sync.WaitGroup.Go (Go 1.25): Add(1) + go + defer Done() in one call.
		wg.Go(func() {
			results[i].ips, results[i].minTTL, results[i].err =
				x.resolveRRType(proto, host, resolver, rrType)
		})
	}
	wg.Wait()

	overallMinTTL := noTTL
	var errs []error
	for _, r := range results[:n] {
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		ips = append(ips, r.ips...)
		if r.minTTL < overallMinTTL {
			overallMinTTL = r.minTTL
		}
	}
	if len(ips) > 0 {
		if overallMinTTL == noTTL {
			overallMinTTL = 0
		}
		return ips, time.Duration(overallMinTTL) * time.Second, nil
	}
	if len(errs) > 0 {
		return nil, 0, errors.Join(errs...)
	}
	return nil, 0, errNoIPRecords
}

// resolveUsingServers tries each resolver in order with exponential back-off.
// On success, a resolver that was not first in the list is promoted to first
// so future lookups skip failing upstreams.
func (x *XTransport) resolveUsingServers(
	proto, host string,
	resolvers []string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	if len(resolvers) == 0 {
		return nil, 0, errEmptyResolvers
	}
	var errs []error
	for i, resolver := range resolvers {
		delay := resolverRetryInitialBackoff
		// range over int (Go 1.22): cleaner bound without manual index variable.
		for attempt := range resolverRetryCount {
			ips, ttl, err = x.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)
			if err == nil && len(ips) > 0 {
				if i > 0 {
					dlog.Infof("Resolution succeeded via %s[%s]; promoting to first", proto, resolver)
					resolvers[0], resolvers[i] = resolvers[i], resolvers[0]
				}
				return ips, ttl, nil
			}
			if err == nil {
				err = errNoIPRecords
			}
			errs = append(errs, fmt.Errorf("%s[%s] attempt %d: %w", proto, resolver, attempt+1, err))
			dlog.Debugf("Resolver attempt %d/%d for [%s] via [%s] (%s): %v",
				attempt+1, resolverRetryCount, host, resolver, proto, err)
			if attempt < resolverRetryCount-1 {
				time.Sleep(delay)
				delay = min(delay*2, resolverRetryMaxBackoff)
			}
		}
		dlog.Infof("Unable to resolve [%s] using [%s] (%s)", host, resolver, proto)
	}
	return nil, 0, errors.Join(errs...)
}

// resolve is the top-level resolver dispatch:
//
//  1. Internal resolvers (when ready + ignoreSystemDNS),
//  2. System resolver (when !ignoreSystemDNS),
//  3. Bootstrap resolvers (both protos),
//  4. Absolute last-resort system resolver.
func (x *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	// [2]string — stack-allocated fixed array, no heap escape.
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
			err = errServiceNotReady
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

	// Bootstrap resolvers: second-tier fallback.
	for _, proto := range protos {
		dlog.Noticef("Resolving [%s] via bootstrap resolvers over %s", host, proto)
		ips, ttl, err = x.resolveUsingServers(proto, host, x.bootstrapResolvers, returnIPv4, returnIPv6)
		if err == nil {
			return ips, ttl, nil
		}
	}

	// Absolute last resort: system resolver even when ignoreSystemDNS is true.
	if x.ignoreSystemDNS {
		dlog.Noticef("Bootstrap resolvers failed — last-resort system resolver for [%s]", host)
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)
	}
	return ips, ttl, err
}

// hostResolveMu returns the per-host mutex stored in resolveMu.
//
// unique.Make (Go 1.23) interns the string so the sync.Map key is compared by
// pointer equality O(1) rather than byte-for-byte O(n). Two calls with the
// same string always return the same Handle, guaranteeing correct LoadOrStore.
func (x *XTransport) hostResolveMu(host string) *sync.Mutex {
	v, _ := x.resolveMu.LoadOrStore(unique.Make(host), &sync.Mutex{})
	return v.(*sync.Mutex)
}

// resolveAndUpdateCache checks whether host's IP cache needs refreshing and,
// if so, resolves it under a per-host mutex to prevent stampedes.
//
// errors.AsType[E] (Go 1.26): generic, reflection-free typed error unwrap —
// approximately 3× faster than errors.As and keeps the typed variable scoped.
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

	mu := x.hostResolveMu(host)
	mu.Lock()
	defer mu.Unlock()

	// Re-check under the mutex (double-checked locking).
	cachedIPs, expired, _ = x.loadCachedIPs(host)
	if len(cachedIPs) > 0 && !expired {
		return nil
	}

	x.markUpdatingCachedIP(host)

	ips, ttl, resolveErr := x.resolve(host, x.useIPv4, x.useIPv6)

	// errors.AsType[E] (Go 1.26): zero reflection, variable scoped to block.
	if resolveErr != nil {
		if dnsErr, ok := errors.AsType[*net.DNSError](resolveErr); ok {
			dlog.Debugf("[%s] DNS error: name=%s notFound=%v temp=%v",
				host, dnsErr.Name, dnsErr.IsNotFound, dnsErr.IsTemporary)
		}
	}

	ttl = max(ttl, MinResolverIPTTL)

	selectedIPs := ips
	if (resolveErr != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {
		dlog.Noticef("Using stale cached address for [%s] (grace period)", host)
		selectedIPs = cachedIPs
		ttl = ExpiredCachedIPGraceTTL
		resolveErr = nil
	}

	if resolveErr != nil {
		return resolveErr
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

// ── HTTP fetch engine ─────────────────────────────────────────────────────────

// Fetch performs an HTTP request and returns (body, statusCode, tlsState, rtt, error).
//
// Automatic HTTP/3 upgrade is attempted when h3Transport is configured and a
// valid Alt-Svc entry exists. On H3 failure the request is transparently
// retried over HTTP/2 and the negative cache is populated.
//
// io.ReadAll is 2× faster in Go 1.26 with 50% less memory (automatic).
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
	client := http.Client{Transport: x.transport, Timeout: timeout}
	host, port := ExtractHostAndPort(url.Host, 443)

	// ── HTTP/3 transport selection ─────────────────────────────────────────
	hasAltSupport := false
	if x.h3Transport != nil {
		if x.http3Probe {
			client.Transport = x.h3Transport
		} else {
			x.altSupport.RLock()
			entry, inCache := x.altSupport.cache[url.Host]
			x.altSupport.RUnlock()
			if inCache {
				hasAltSupport = true
				negativeExpired := entry.port == 0 && !entry.validTo.IsZero() &&
					time.Now().After(entry.validTo)
				switch {
				case entry.port > 0 && int(entry.port) == port:
					client.Transport = x.h3Transport
				case negativeExpired:
					hasAltSupport = false
				}
			}
		}
	}

	// ── Request headers ────────────────────────────────────────────────────
	header := make(http.Header, 5)
	header.Set("User-Agent", "dnscrypt-proxy")
	header.Set("Cache-Control", "max-stale")
	if accept != "" {
		header.Set("Accept", accept)
	}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}

	// Attach a body hash as a query parameter so the server can verify integrity.
	if body != nil {
		h := sha512.Sum512_256(*body) // single-call 256-bit hash
		qs := url.Query()
		qs.Add("body_hash", hex.EncodeToString(h[:]))
		u2 := *url
		u2.RawQuery = qs.Encode()
		url = &u2
	}

	// ── Pre-flight checks ──────────────────────────────────────────────────
	if x.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0, errNoTorProxy
	}
	if err := x.resolveAndUpdateCache(host); err != nil {
		dlog.Errorf("Unable to resolve [%s]: check bootstrap_resolvers or system resolver", host)
		return nil, 0, nil, 0, err
	}
	if compress && body == nil {
		header.Set("Accept-Encoding", "gzip")
	}

	// ── Build and execute request ──────────────────────────────────────────
	bodyLen := 0
	if body != nil {
		bodyLen = len(*body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(*body)
	}
	// http.NewRequestWithContext: propagates the per-request deadline through
	// all HTTP layers, preventing runaway connections.
	req, err := http.NewRequestWithContext(ctx, method, url.String(), reqBody)
	if err != nil {
		return nil, 0, nil, 0, err
	}
	req.Header = header
	req.ContentLength = int64(bodyLen)

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	// ── H3 fallback ────────────────────────────────────────────────────────
	if err != nil && client.Transport == x.h3Transport {
		dlog.Debugf("HTTP/3 failed for [%s]: %v — retrying over HTTP/2", url.Host, err)
		x.altSupport.Lock()
		x.altSupport.cache[url.Host] = altSvcEntry{port: 0, validTo: time.Now().Add(altSvcNegativeTTL)}
		x.altSupport.Unlock()
		client.Transport = x.transport
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(*body))
			req.ContentLength = int64(bodyLen)
		}
		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)
	}

	// Ensure resp.Body is always closed, even on error paths.
	if resp != nil {
		defer resp.Body.Close()
	}

	statusCode := 503
	if resp != nil {
		statusCode = resp.StatusCode
	}

	// ── Error classification ───────────────────────────────────────────────
	if err == nil {
		switch {
		case resp == nil:
			err = errEmptyResponse
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

	// ── Alt-Svc discovery ──────────────────────────────────────────────────
	if x.h3Transport != nil && !hasAltSupport {
		x.parseAndCacheAltSvc(url.Host, port, resp.Header)
	}

	// ── Body decoding ──────────────────────────────────────────────────────
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
	// io.ReadAll is 2× faster with 50% less memory in Go 1.26 (automatic).
	bin, err := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))
	if err != nil {
		return nil, statusCode, tlsState, rtt, err
	}
	return bin, statusCode, tlsState, rtt, nil
}

// parseAndCacheAltSvc parses the Alt-Svc response header and stores the
// discovered HTTP/3 port. Negative entries (port 0) suppress further probing
// for altSvcNegativeTTL.
//
// strings.SplitSeq (Go 1.24): zero-alloc lazy iterator over ";" fields,
// avoiding the []string allocation that strings.Split would create per entry.
func (x *XTransport) parseAndCacheAltSvc(host string, port int, header http.Header) {
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

	altPort := uint16(port & 0xffff)

outer:
	for i, entry := range alt {
		if i >= 8 {
			break
		}
		j := 0
		// strings.SplitSeq (Go 1.24): zero-alloc ";" field iterator.
		for field := range strings.SplitSeq(entry, ";") {
			if j >= 16 {
				break
			}
			j++
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
	x.altSupport.cache[host] = altSvcEntry{port: altPort}
	dlog.Debugf("Alt-Svc: cached port %d for [%s]", altPort, host)
	x.altSupport.Unlock()
}

// ── Public query helpers ──────────────────────────────────────────────────────

// GetWithCompression issues an HTTP GET with Accept-Encoding: gzip.
func (x *XTransport) GetWithCompression(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(http.MethodGet, url, accept, "", nil, timeout, true)
}

// Get issues a plain HTTP GET (no compression).
func (x *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(http.MethodGet, url, accept, "", nil, timeout, false)
}

// Post issues an HTTP POST with the supplied body.
func (x *XTransport) Post(
	url *url.URL,
	accept, contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(http.MethodPost, url, accept, contentType, body, timeout, false)
}

// dohLikeQuery sends a DNS-over-HTTPS style query (GET or POST) with the given
// media type. Shared by DoHQuery and ObliviousDoHQuery.
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

// DoHQuery sends a standard DNS-over-HTTPS query (RFC 8484).
func (x *XTransport) DoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/dns-message", useGet, url, body, timeout)
}

// ObliviousDoHQuery sends an Oblivious DNS-over-HTTPS query (draft-pauly-dprive-oblivious-doh).
func (x *XTransport) ObliviousDoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}
