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
	"sync/atomic"
	"syscall"
	"time"
	"unique"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	netproxy "golang.org/x/net/proxy"
	"golang.org/x/sys/cpu"
	"golang.org/x/sys/unix"
)

// ── Hardware acceleration detection ───────────────────────────────────────────
var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||
	(cpu.S390X.HasAES && cpu.S390X.HasAESGCM)

// ── Constants ─────────────────────────────────────────────────────────────────
const (
	ttlSentinel = ^uint32(0)

	DefaultBootstrapResolver    = "9.9.9.9:53"
	DefaultKeepAlive            = 5 * time.Second
	DefaultIdleConnTimeout      = 90 * time.Second
	DefaultTimeout              = 30 * time.Second
	ResolverReadTimeout         = 5 * time.Second
	SystemResolverTimeout       = 5 * time.Second
	SystemResolverIPTTL         = 12 * time.Hour
	MinResolverIPTTL            = 4 * time.Hour
	ResolverIPTTLMaxJitter      = 15 * time.Minute
	ExpiredCachedIPGraceTTL     = 15 * time.Minute
	resolverRetryCount          = 3
	resolverRetryInitialBackoff = 150 * time.Millisecond
	resolverRetryMaxBackoff     = 1 * time.Second
	MaxIdleConns                = 2000
	MaxResponseHeaderBytes      = 4096
	TLSHandshakeTimeout         = 10 * time.Second
	altSvcNegativeTTL           = 10 * time.Minute

	// ── HTTP/2 tuning – maximised for low‑latency DoH ────────────────────────
	h2MaxConcurrentStreams      = 1000
	h2MaxReadFrameSize          = 16 * 1024 * 1024 // 16 MiB
	h2MaxDecoderHeaderTableSize = 4*1024*1024 - 1  // ~4 MiB
	h2MaxEncoderHeaderTableSize = 4*1024*1024 - 1  // ~4 MiB
	h2MaxReceiveBufferPerConn   = 4*1024*1024 - 1  // ~4 MiB
	h2MaxReceiveBufferPerStream = 4*1024*1024 - 1  // ~4 MiB
	h2SendPingTimeout           = 15 * time.Second
	h2PingTimeout               = h2SendPingTimeout // same budget for both send and round-trip ping
	h2WriteByteTimeout          = 10 * time.Second
	h2TLSSessionCacheSize       = 512
	h2ReadWriteBufferSize       = 64 * 1024 // 64 KiB – larger I/O buffers reduce syscalls
	h2IdleConnTimeout           = 120 * time.Second
	h2MaxIdleConnsPerHost       = 64 // raised from 10 to reduce TLS/dial churn under bursty DoH traffic
	h2ExpectContinueTimeout     = 500 * time.Millisecond
	h2ResponseHeaderTimeout     = 20 * time.Second
	h2TLSHandshakeTimeout       = 15 * time.Second

	// ── QUIC / HTTP/3 flow-control windows ───────────────────────────────────
	// DNS responses are small but larger windows prevent ACK-stall on request
	// bursts and reduce WINDOW_UPDATE round-trips.
	h3InitialStreamWindow = 512 * 1024      // 512 KiB per stream
	h3MaxStreamWindow     = 4 * 1024 * 1024 // 4 MiB per stream
	h3InitialConnWindow   = 1024 * 1024     // 1 MiB per connection
	h3MaxConnWindow       = 8 * 1024 * 1024 // 8 MiB per connection

	// ── TCP socket buffer sizes ───────────────────────────────────────────────
	// Request 256 KiB send/recv buffers. Kernel caps at net.core.{w,r}mem_max.
	tcpSocketBufSize = 256 * 1024 // 256 KiB

	// ── TCP_NOTSENT_LOWAT value ───────────────────────────────────────────────
	// 16 KiB: enough slack to keep writes non-blocking while preventing
	// excessive kernel-side buffering that inflates write latency.
	tcpNotSentLowat = 16 * 1024 // 16 KiB

	// ── SO_BUSY_POLL value for H3 UDP sockets ────────────────────────────────
	// 50 µs of kernel busy-polling before sleeping. Eliminates the interrupt
	// context-switch on the receive path for latency-sensitive DoH/DoQ.
	udpBusyPollMicros = 50 // µs

	// ── Prewarm concurrency gate ───────────────────────────────────────────────
	// Caps simultaneous prewarm goroutines to prevent scheduler pressure during
	// bursty unique-host traffic. Goroutines that cannot acquire a slot are
	// skipped immediately — prewarming is best-effort and never blocks callers.
	prewarmMaxConcurrency = 16

	// ── Bounded dialTargetCache ────────────────────────────────────────────────
	dialTargetCacheMaxSize = 1024

	// hostPortCacheMaxSize bounds the global host:port cache.
	hostPortCacheMaxSize = 2048

	// cacheTrimWindow prevents repeated cache clears under bursty concurrent
	// insertions by allowing only a narrow clear window around max size.
	cacheTrimWindow = 16

	// ── H3 per-host failure / backoff thresholds ──────────────────────────────
	// After h3FailureThreshold consecutive H3 failures for a host, suppress H3
	// for an exponentially increasing window (h3BackoffInitial × 2^n, capped at
	// h3BackoffMax). H3 is retried automatically once the window expires.
	h3FailureThreshold = 3
	h3BackoffInitial   = 30 * time.Second
	h3BackoffMax       = 10 * time.Minute
	// h3BackoffShiftMax caps the left-shift in the exponential calculation.
	// 1 << 4 == 16, so the maximum multiplier is 16× h3BackoffInitial = 480s,
	// which is already capped to h3BackoffMax (10 min) anyway.
	h3BackoffShiftMax = 4
)

// ── Package‑level sentinel errors (zero‑allocation returns) ──────────────────
var (
	errEmptyResponse         = errors.New("server returned an empty response")
	errNoTorProxy            = errors.New("onion service requires a configured Tor proxy")
	errNoIPRecords           = errors.New("no IP records returned")
	errEmptyResolvers        = errors.New("empty resolver list")
	errServiceNotReady       = errors.New("dnscrypt-proxy service is not ready yet")
	errDNSQueryTimeout       = errors.New("DNS query timed out")
	errSystemResolverTimeout = errors.New("system resolver timed out")
)

var systemResolver = &net.Resolver{PreferGo: true}

// ── Global TLS session cache – saves one full TLS 1.3 RTT on reconnect ───────
var tlsSessionCache = tls.NewLRUClientSessionCache(h2TLSSessionCacheSize)

// ── Internal observability counters ──────────────────────────────────────────
// All counters are written atomically and never reset, making them safe to read
// concurrently at any time. They aid tuning without adding external dependencies.
var (
	h3FallbackTotal  atomic.Int64 // cumulative H3→H2 fallback events
	resolverRaceWins atomic.Int64 // cumulative parallel-race first-resolver wins
	prewarmSkipped   atomic.Int64 // prewarm goroutines skipped (semaphore full)
	cacheEvictions   atomic.Int64 // cumulative dial-target + prewarm cache evictions

	dialTargetCacheSize atomic.Int64
	hostPortCacheSize   atomic.Int64
)

// ── Prewarm concurrency gate ──────────────────────────────────────────────────
// Buffered channel used as a counting semaphore. Goroutines that cannot acquire
// a slot (channel full) are discarded — prewarming is always best-effort.
var prewarmSem = make(chan struct{}, prewarmMaxConcurrency)

// ── gzip.Reader pool – eliminates 32 KB allocations per compressed response ───
var gzipReaderPool = sync.Pool{
	New: func() any { return new(gzip.Reader) },
}

// ── Response buffer pool – reuses byte buffers for HTTP response body reads ───
// Typical DNS responses are 100–4096 bytes. The initial capacity of 4096 covers
// the vast majority of responses without re-allocation. Buffers that grow beyond
// this (rare large responses) are still returned to the pool.
var httpResponseBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

// Cached dial target strings – avoids repeated strconv.Itoa + string concat
// on the hot dial path. Key is a compact struct (netip.Addr + uint16 port).
type dialTargetKey struct {
	addr netip.Addr
	port uint16
}

var dialTargetCache sync.Map // map[dialTargetKey]string

// hostPortCache caches "host:port" strings to avoid repeated concatenation and
// strconv.Itoa allocations on the hot Fetch() path. Key is host+port.
type hostPortKey struct {
	host string
	port int
}

var hostPortCache sync.Map // map[hostPortKey]string

// formatHostPort returns a cached "host:port" string, allocating only on the
// first call for each unique (host, port) pair.
func formatHostPort(host string, port int) string {
	k := hostPortKey{host: host, port: port}
	if v, ok := hostPortCache.Load(k); ok {
		return v.(string)
	}
	s := net.JoinHostPort(host, strconv.Itoa(port))
	v, loaded := hostPortCache.LoadOrStore(k, s)
	if !loaded {
		trimStringCache(&hostPortCache, &hostPortCacheSize, hostPortCacheMaxSize)
	}
	return v.(string)
}

func formatDialTarget(addr netip.Addr, port uint16) string {
	k := dialTargetKey{addr: addr, port: port}
	if v, ok := dialTargetCache.Load(k); ok {
		return v.(string)
	}
	// Compute before LoadOrStore — no lock held during formatting.
	// Two goroutines may race on a cold miss; LoadOrStore ensures only one
	// value wins (the loser's allocation is simply discarded). This is
	// always correct and cheaper than a mutex around Store.
	portStr := strconv.FormatUint(uint64(port), 10)
	var s string
	if addr.Is4() {
		s = addr.String() + ":" + portStr
	} else {
		s = "[" + addr.String() + "]:" + portStr
	}
	v, loaded := dialTargetCache.LoadOrStore(k, s)
	if !loaded {
		trimStringCache(&dialTargetCache, &dialTargetCacheSize, dialTargetCacheMaxSize)
	}
	return v.(string)
}

func trimStringCache(cache *sync.Map, sizeCounter *atomic.Int64, maxSize int64) {
	size := sizeCounter.Add(1)
	if size < maxSize {
		return
	}
	if size%cacheTrimWindow != 0 {
		return
	}
	cache.Clear()
	sizeCounter.Store(0)
}

// appendFrom reads from r into buf, growing it as needed, and returns the
// extended slice. This replaces io.ReadAll on the hot path: when buf already
// has sufficient capacity (the common case for DNS responses), no new heap
// allocation occurs.
func appendFrom(buf []byte, r io.Reader) ([]byte, error) {
	for {
		// Exponential growth: start at 512 B, double up to 64 KiB per step.
		if len(buf) == cap(buf) {
			growth := 512
			if c := cap(buf); c >= 8*1024 {
				growth = min(c, 64*1024)
			}
			buf = append(buf, make([]byte, growth)...)[:len(buf)]
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err != nil {
			if errors.Is(err, io.EOF) {
				return buf, nil
			}
			return buf, err
		}
	}
}

// ── Cache types ───────────────────────────────────────────────────────────────
type CachedIPItem struct {
	addrs         []netip.Addr
	expiration    time.Time // zero == no expiry
	updatingUntil time.Time // zero == not updating
}

type CachedIPs struct {
	sync.RWMutex
	cache map[string]*CachedIPItem
}

// altSvcEntry records an Alt-Svc advertisement for a host.
//
// The noExpiry bool removes a zero-time ambiguity: previously validTo.IsZero()
// had dual meaning (valid-forever vs. ambiguous). noExpiry=true now
// unambiguously means "this entry never expires".
type altSvcEntry struct {
	validTo  time.Time
	port     uint16
	noExpiry bool // true → entry is permanent (no TTL)
}

type AltSupport struct {
	sync.RWMutex
	cache map[string]altSvcEntry
}

// isAltSvcExpired reports whether e has passed its validity window.
func isAltSvcExpired(e altSvcEntry, now time.Time) bool {
	if e.noExpiry {
		return false
	}
	return !e.validTo.IsZero() && now.After(e.validTo)
}

// ── H3 per-host health state ──────────────────────────────────────────────────
// Tracks consecutive H3 failures per host and suppresses H3 for an exponentially
// increasing backoff window after repeated failures. This avoids repeatedly burning
// time on expensive QUIC handshakes when H3 is broken for a specific host.
// H3 is automatically retried after the backoff window expires (probe-then-recover).
//
// The read path (inBackoff) is lock-free: it loads an atomic int64 timestamp
// and compares against the current time. Only the write paths (onFailure,
// onSuccess) take the mutex, which are rare events.
type h3HealthState struct {
	// backoffDeadline stores the backoff expiry as UnixNano. A value of 0
	// means no backoff is active. Reads are lock-free via atomic.Int64.
	backoffDeadline atomic.Int64

	mu       sync.Mutex // protects failures + backoff deadline writes
	failures int
}

// inBackoff reports whether H3 should currently be suppressed for this host.
// Lock-free: only performs an atomic load and a time comparison.
func (s *h3HealthState) inBackoff() bool {
	deadline := s.backoffDeadline.Load()
	return deadline != 0 && time.Now().UnixNano() < deadline
}

// onFailure increments the consecutive-failure counter and sets a backoff window
// once the threshold is crossed. The window grows exponentially (factor of 2 per
// extra failure beyond the threshold) up to h3BackoffMax.
func (s *h3HealthState) onFailure() (inBackoff bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures++
	if s.failures >= h3FailureThreshold {
		shift := s.failures - h3FailureThreshold
		if shift > h3BackoffShiftMax {
			shift = h3BackoffShiftMax
		}
		backoff := h3BackoffInitial * (1 << shift)
		if backoff > h3BackoffMax {
			backoff = h3BackoffMax
		}
		s.backoffDeadline.Store(time.Now().Add(backoff).UnixNano())
		return true
	}
	return false
}

// onSuccess resets the failure counter and clears any active backoff.
func (s *h3HealthState) onSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = 0
	s.backoffDeadline.Store(0)
}

// hostPrewarmer uses unique.Handle[string] keys so map comparisons are O(1)
// pointer-identity checks rather than full string-byte comparisons.
type hostPrewarmer struct {
	m sync.Map // map[unique.Handle[string]]*sync.Once
}

func (p *hostPrewarmer) do(hostport unique.Handle[string], fn func()) {
	v, _ := p.m.LoadOrStore(hostport, new(sync.Once))
	v.(*sync.Once).Do(fn)
}

// prebuiltHeaders are built once and assigned directly to requests without
// cloning. They are treated as immutable after construction.
type prebuiltHeaders struct {
	getGzip  http.Header // GET with Accept-Encoding: gzip
	getPlain http.Header // GET without gzip
	postDNS  http.Header // POST application/dns-message
	postODNS http.Header // POST application/oblivious-dns-message
}

func buildPrebuiltHeaders() prebuiltHeaders {
	base := func(extra int) http.Header {
		h := make(http.Header, 2+extra)
		h.Set("User-Agent", "dnscrypt-proxy")
		h.Set("Cache-Control", "max-stale")
		return h
	}

	getGzip := base(1)
	getGzip.Set("Accept-Encoding", "gzip")

	getPlain := base(0)

	postDNS := base(2)
	postDNS.Set("Accept", "application/dns-message")
	postDNS.Set("Content-Type", "application/dns-message")

	postODNS := base(2)
	postODNS.Set("Accept", "application/oblivious-dns-message")
	postODNS.Set("Content-Type", "application/oblivious-dns-message")

	return prebuiltHeaders{
		getGzip:  getGzip,
		getPlain: getPlain,
		postDNS:  postDNS,
		postODNS: postODNS,
	}
}

// ── XTransport – main transport structure ─────────────────────────────────────
type XTransport struct {
	transport       *http.Transport
	h3Transport     *http3.Transport
	tlsClientConfig *tls.Config

	// Cached http.Client instances – rebuilt in rebuildTransport(), selected in Fetch().
	// http.Client is safe for concurrent use (documented in net/http).
	httpClient http.Client
	h3Client   http.Client

	keepAlive time.Duration
	timeout   time.Duration

	cachedIPs  CachedIPs
	altSupport AltSupport

	internalResolvers     []string
	bootstrapResolvers    []string
	mainProto             string
	ignoreSystemDNS       bool
	internalResolverReady bool

	useIPv4    bool
	useIPv6    bool
	http3      bool
	http3Probe bool

	tlsDisableSessionTickets bool
	tlsPreferRSA             bool

	proxyDialer       *netproxy.Dialer
	httpProxyFunction func(*http.Request) (*url.URL, error)

	tlsClientCreds DOHClientCreds // defined in serversInfo.go
	keyLogWriter   io.Writer

	// Per‑host resolution mutexes (singleflight style)
	resolveMu sync.Map // map[unique.Handle[string]]*sync.Mutex

	headers prebuiltHeaders // pre-built immutable header maps; rebuilt on config reload

	prewarmed hostPrewarmer // per-host connection prewarmer

	dnsClient *dns.Client // shared DNS client for resolver queries

	BodyHashEnabled bool // when true, appends body_hash query parameter to POST requests

	// dialer is built once in rebuildTransport() with ControlContext set so
	// TCP_FASTOPEN_CONNECT is active for connect(). Zero allocation on the hot
	// dial path; rebuilt only on config reload.
	dialer net.Dialer

	// ── H3 per-host health state ──────────────────────────────────────────────
	// Tracks consecutive H3 failures per host and the active backoff window.
	// Loaded lazily via LoadOrStore; cleared on full transport rebuild.
	h3Health sync.Map // map[string]*h3HealthState
}

// ── Constructor ───────────────────────────────────────────────────────────────
func NewXTransport() *XTransport {
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
		panic("DefaultBootstrapResolver is not a valid IP:port — " + err.Error())
	}

	tr := dns.NewTransport()
	tr.ReadTimeout = ResolverReadTimeout
	dnsClient := &dns.Client{Transport: tr}

	return &XTransport{
		cachedIPs:          CachedIPs{cache: make(map[string]*CachedIPItem)},
		altSupport:         AltSupport{cache: make(map[string]altSvcEntry)},
		keepAlive:          DefaultKeepAlive,
		timeout:            DefaultTimeout,
		bootstrapResolvers: []string{DefaultBootstrapResolver},
		ignoreSystemDNS:    true,
		useIPv4:            true,
		headers:            buildPrebuiltHeaders(),
		dnsClient:          dnsClient,
	}
}

// ── IP helpers ────────────────────────────────────────────────────────────────
// ParseIP parses an IP address string, stripping optional IPv6 brackets.
// Returns net.IP (nil on failure) — public API, used by config.go, serversInfo.go etc.
func ParseIP(ipStr string) net.IP {
	ipStr = strings.TrimPrefix(ipStr, "[")
	ipStr = strings.TrimSuffix(ipStr, "]")
	return net.ParseIP(ipStr)
}

// parseIPAddr is the internal netip.Addr version — zero-allocation, stack-allocated.
// Used only within xtransport.go for cache lookups and dial target formatting.
func parseIPAddr(ipStr string) netip.Addr {
	ipStr = strings.TrimPrefix(ipStr, "[")
	ipStr = strings.TrimSuffix(ipStr, "]")
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// uniqueNormalizedAddrs deduplicates addrs using a stack-allocated array for up
// to 8 entries; beyond 8 the seen slice grows onto the heap automatically.
func uniqueNormalizedAddrs(addrs []netip.Addr) []netip.Addr {
	if len(addrs) == 0 {
		return nil
	}
	if len(addrs) == 1 {
		if addrs[0].IsValid() {
			a := addrs[0].Unmap()
			return []netip.Addr{a}
		}
		return nil
	}

	var seenBuf [8]netip.Addr
	seen := seenBuf[:0]
	out := make([]netip.Addr, 0, len(addrs))

	for _, addr := range addrs {
		if !addr.IsValid() {
			continue
		}
		a := addr.Unmap()
		isDup := false
		for _, s := range seen {
			if s == a {
				isDup = true
				break
			}
		}
		if !isDup {
			seen = append(seen, a)
			out = append(out, a)
		}
	}
	return out
}

// ── IP cache operations ────────────────────────────────────────────────────────
func (x *XTransport) saveCachedAddrs(host string, addrs []netip.Addr, ttl time.Duration) {
	normalized := uniqueNormalizedAddrs(addrs)
	if len(normalized) == 0 {
		return
	}

	item := &CachedIPItem{addrs: normalized}
	if ttl >= 0 {
		ttl = max(ttl, MinResolverIPTTL)
		ttl += time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))
		item.expiration = time.Now().Add(ttl)
	}

	x.cachedIPs.Lock()
	item.updatingUntil = time.Time{}
	x.cachedIPs.cache[host] = item
	x.cachedIPs.Unlock()

	if len(normalized) == 1 {
		dlog.Debugf("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)
	} else {
		dlog.Debugf("[%s] cached %d IPs (first: %s), valid for %v",
			host, len(normalized), normalized[0], ttl)
	}
}

// saveCachedIPs wraps saveCachedAddrs, converting net.IP to netip.Addr.
// Used by callers that still produce net.IP (e.g., DNS response parsing).
func (x *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		a, ok := netip.AddrFromSlice(ip)
		if ok {
			addrs = append(addrs, a.Unmap())
		}
	}
	x.saveCachedAddrs(host, addrs, ttl)
}

// saveCachedIP saves a single IP into the cache using a stack-allocated
// single-element array to avoid a heap allocation.
func (x *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip == nil {
		return
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return
	}
	buf := [1]netip.Addr{a.Unmap()}
	x.saveCachedAddrs(host, buf[:], ttl)
}

func (x *XTransport) markUpdatingCachedIP(host string) {
	updatingUntil := time.Now().Add(x.timeout)
	x.cachedIPs.Lock()
	if item, ok := x.cachedIPs.cache[host]; ok {
		item.updatingUntil = updatingUntil
	} else {
		x.cachedIPs.cache[host] = &CachedIPItem{updatingUntil: updatingUntil}
	}
	x.cachedIPs.Unlock()
	dlog.Debugf("[%s] IP address marked as updating", host)
}

// loadCachedAddrs returns cached netip.Addr values. Zero allocation on the
// read path — the returned slice is a copy of the slice header; the backing
// array contains immutable value-type netip.Addr entries.
func (x *XTransport) loadCachedAddrs(host string) (addrs []netip.Addr, expired, updating bool) {
	x.cachedIPs.RLock()
	item, ok := x.cachedIPs.cache[host]
	x.cachedIPs.RUnlock()
	if !ok || item == nil {
		return nil, false, false
	}
	now := time.Now()
	if !item.updatingUntil.IsZero() && now.Before(item.updatingUntil) {
		updating = true
	}
	if !item.expiration.IsZero() && now.After(item.expiration) {
		expired = true
	}
	if len(item.addrs) == 0 {
		return nil, expired, updating
	}
	// Zero-copy return: netip.Addr is a value type and writers replace the entire
	// *CachedIPItem, so the stored slice is immutable — return it directly.
	return item.addrs, expired, updating
}

func (x *XTransport) PurgeExpiredCache() (ipsPurged, altSvcPurged, muPurged int) {
	now := time.Now()
	grace := now.Add(-ExpiredCachedIPGraceTTL)

	// IP cache
	x.cachedIPs.Lock()
	before := len(x.cachedIPs.cache)
	maps.DeleteFunc(x.cachedIPs.cache, func(_ string, item *CachedIPItem) bool {
		if item == nil {
			return true
		}
		if !item.updatingUntil.IsZero() && now.Before(item.updatingUntil) {
			return false
		}
		return !item.expiration.IsZero() && item.expiration.Before(grace)
	})
	ipsPurged = before - len(x.cachedIPs.cache)

	// Build live set for later mutex + prewarmer + dial-target cleanup
	live := make(map[string]struct{}, len(x.cachedIPs.cache))
	liveAddrs := make(map[netip.Addr]struct{})
	for host, item := range x.cachedIPs.cache {
		live[host] = struct{}{}
		if item != nil {
			for _, addr := range item.addrs {
				liveAddrs[addr] = struct{}{}
			}
		}
	}
	x.cachedIPs.Unlock()

	// Alt‑Svc cache — use isAltSvcExpired helper
	x.altSupport.Lock()
	before = len(x.altSupport.cache)
	maps.DeleteFunc(x.altSupport.cache, func(_ string, e altSvcEntry) bool {
		// Only purge negative-cache entries (port==0) that have genuinely expired.
		return e.port == 0 && isAltSvcExpired(e, now)
	})
	altSvcPurged = before - len(x.altSupport.cache)
	x.altSupport.Unlock()

	// Clean up resolveMu entries for hosts no longer in cache
	x.resolveMu.Range(func(key, _ any) bool {
		h := key.(unique.Handle[string])
		if _, ok := live[h.Value()]; !ok {
			x.resolveMu.Delete(key)
			muPurged++
		}
		return true
	})

	// ── Evict stale dialTargetCache entries ───────────────────────────────────
	// Remove cached dial-target strings whose IP address is no longer in the live
	// IP set. This prevents the global sync.Map from growing unboundedly when CDN
	// or rotating resolver IPs cycle through many distinct addresses over time.
	var dialEvicted int
	dialTargetCache.Range(func(key, _ any) bool {
		k := key.(dialTargetKey)
		if _, ok := liveAddrs[k.addr]; !ok {
			dialTargetCache.Delete(key)
			dialEvicted++
		}
		return true
	})
	if dialEvicted > 0 {
		if dialTargetCacheSize.Add(-int64(dialEvicted)) < 0 {
			dialTargetCacheSize.Store(0)
		}
	}

	// ── Evict stale hostPrewarmer entries ─────────────────────────────────────
	// Remove prewarm sync.Once entries for hosts no longer in the live IP cache.
	// Without this, host churn (e.g., stamp list changes) causes the prewarmer
	// map to accumulate dead entries indefinitely.
	var prewarmEvicted int
	x.prewarmed.m.Range(func(key, _ any) bool {
		h := key.(unique.Handle[string])
		host, _ := splitHostPort(h.Value())
		if _, ok := live[host]; !ok {
			x.prewarmed.m.Delete(key)
			prewarmEvicted++
		}
		return true
	})

	if ipsPurged > 0 || altSvcPurged > 0 || muPurged > 0 || dialEvicted > 0 || prewarmEvicted > 0 {
		dlog.Debugf("PurgeExpiredCache: %d IP, %d Alt‑Svc, %d mutex, %d dial-target, %d prewarm entries removed",
			ipsPurged, altSvcPurged, muPurged, dialEvicted, prewarmEvicted)
		cacheEvictions.Add(int64(dialEvicted + prewarmEvicted))
	}
	return
}

func (x *XTransport) ResetCache() {
	x.cachedIPs.Lock()
	clear(x.cachedIPs.cache)
	x.cachedIPs.Unlock()

	x.altSupport.Lock()
	clear(x.altSupport.cache)
	x.altSupport.Unlock()

	dialTargetCache.Clear()
	hostPortCache.Clear()
	dialTargetCacheSize.Store(0)
	hostPortCacheSize.Store(0)

	x.resolveMu.Clear()

	dlog.Debug("ResetCache: all IP, Alt‑Svc, mutex, and dial-target cache entries cleared")
}

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

// ── TCP low‑level optimizations ─────────────────────────────────────────────
// (File has //go:build linux, so these use Linux-specific syscalls throughout.)

// tcpControlContext is assigned to net.Dialer.ControlContext.
// Called by the Go runtime after socket() but BEFORE connect() — the only
// correct placement for TCP_FASTOPEN_CONNECT, which the kernel silently ignores
// if set on an already-connected socket. SO_SNDBUF / SO_RCVBUF are also more
// effective here: the kernel sizes socket buffers at connect time.
//
// Package-level func (not a closure) — zero allocation cost as a struct field.
func tcpControlContext(_ context.Context, _, _ string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		ifd := int(fd)
		// TCP_FASTOPEN_CONNECT — MUST be pre-connect; saves one RTT on repeat conns
		_ = unix.SetsockoptInt(ifd, unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)
		// TCP_QUICKACK — disable delayed ACKs for faster ACK delivery
		_ = unix.SetsockoptInt(ifd, unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)
		// TCP_NOTSENT_LOWAT — prevents kernel-side send-buffer bloat
		_ = unix.SetsockoptInt(ifd, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, tcpNotSentLowat)
		// SO_SNDBUF / SO_RCVBUF — 256 KiB socket buffers reduce syscall frequency
		_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_SNDBUF, tcpSocketBufSize)
		_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_RCVBUF, tcpSocketBufSize)
	})
}

// setTCPOptions applies post-dial TCP socket options for proxy-path connections.
// Direct connections use tcpControlContext (pre-connect) — this function is
// ONLY called when a proxy dialer establishes the underlying TCP connection.
//
// TCP_FASTOPEN_CONNECT omitted — it is a no-op on already-connected sockets.
// TCP_NODELAY omitted — Go’s net package sets it automatically on every TCPConn.
func setTCPOptions(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		ifd := int(fd)
		_ = unix.SetsockoptInt(ifd, unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)
		_ = unix.SetsockoptInt(ifd, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, tcpNotSentLowat)
		_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_SNDBUF, tcpSocketBufSize)
		_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_RCVBUF, tcpSocketBufSize)
	})
}

// setUDPOptions applies Linux-specific latency optimizations to a UDP socket.
// Called on H3/QUIC UDP connections where microsecond latency matters.
func setUDPOptions(conn *net.UDPConn) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		ifd := int(fd)
		// SO_BUSY_POLL – kernel busy-polls for 50 µs before sleeping, avoiding the
		// interrupt + context-switch overhead on the receive path. Requires
		// CAP_NET_ADMIN; silently ignored if kernel or driver does not support it.
		_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_BUSY_POLL, udpBusyPollMicros)
		_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_SNDBUF, tcpSocketBufSize)
		_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_RCVBUF, tcpSocketBufSize)
	})
}

// ── Transport construction ────────────────────────────────────────────────────
func (x *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport")
	if x.transport != nil {
		x.transport.CloseIdleConnections()
	}
	x.tlsClientConfig = x.buildTLSConfig()

	// Build net.Dialer once with ControlContext so TCP_FASTOPEN_CONNECT is
	// active for the very first connect() call. Stored as a field for zero
	// allocation on the hot dial path; rebuilt only on config reload.
	x.dialer = net.Dialer{
		Timeout: x.timeout,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     x.keepAlive,
			Interval: max(x.keepAlive/3, time.Second),
			Count:    3,
		},
		ControlContext: tcpControlContext,
	}

	// Rebuild pre-built headers
	x.headers = buildPrebuiltHeaders()

	h2Cfg := &http.HTTP2Config{
		MaxConcurrentStreams:          h2MaxConcurrentStreams,
		MaxReadFrameSize:              h2MaxReadFrameSize,
		MaxDecoderHeaderTableSize:     h2MaxDecoderHeaderTableSize,
		MaxEncoderHeaderTableSize:     h2MaxEncoderHeaderTableSize,
		MaxReceiveBufferPerConnection: h2MaxReceiveBufferPerConn,
		MaxReceiveBufferPerStream:     h2MaxReceiveBufferPerStream,
		SendPingTimeout:               h2SendPingTimeout,
		PingTimeout:                   h2PingTimeout,
		WriteByteTimeout:              h2WriteByteTimeout,
		CountError: func(errType string) {
			dlog.Debugf("HTTP/2 error: %s", errType)
		},
	}

	transport := &http.Transport{
		DisableCompression:     true,
		MaxIdleConns:           MaxIdleConns,
		MaxIdleConnsPerHost:    h2MaxIdleConnsPerHost,
		IdleConnTimeout:        h2IdleConnTimeout,
		TLSHandshakeTimeout:    h2TLSHandshakeTimeout,
		ResponseHeaderTimeout:  h2ResponseHeaderTimeout,
		ExpectContinueTimeout:  h2ExpectContinueTimeout,
		MaxResponseHeaderBytes: MaxResponseHeaderBytes,
		WriteBufferSize:        h2ReadWriteBufferSize,
		ReadBufferSize:         h2ReadWriteBufferSize,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        x.tlsClientConfig,
		DialContext:            x.buildDialContext(),
		HTTP2:                  h2Cfg,
	}
	if x.httpProxyFunction != nil {
		transport.Proxy = x.httpProxyFunction
	}
	x.transport = transport

	// Rebuilding happens rarely (config reload); hot path in Fetch() is allocation-free.
	x.httpClient = http.Client{Transport: transport}

	// Reset prewarmer so new connections will be prewarmed on next request
	x.prewarmed = hostPrewarmer{}

	// Clear H3 health state so the rebuilt transport starts with a clean slate.
	x.h3Health.Clear()

	if x.http3 {
		if x.h3Transport != nil {
			x.h3Transport.Close()
		}

		// QUIC flow-control windows sized for DoH bursts; token store enables 0-RTT.
		quicCfg := &quic.Config{
			InitialStreamReceiveWindow:     h3InitialStreamWindow,
			MaxStreamReceiveWindow:         h3MaxStreamWindow,
			InitialConnectionReceiveWindow: h3InitialConnWindow,
			MaxConnectionReceiveWindow:     h3MaxConnWindow,
			TokenStore:                     quic.NewLRUTokenStore(256, 8),
		}

		x.h3Transport = &http3.Transport{
			DisableCompression: true,
			TLSClientConfig:    x.tlsClientConfig,
			QUICConfig:         quicCfg,
			Dial:               x.buildH3DialFunc(),
		}
		x.h3Client = http.Client{Transport: x.h3Transport}
	}
}

// prewarmConnection ensures a full TLS+HTTP/2 handshake (and optionally a QUIC
// handshake) is completed once per host before real traffic arrives.
//
// A HEAD request is issued via the stored httpClient so the transport performs
// the complete TLS+ALPN+HTTP/2 handshake and deposits an idle connection into
// its pool. The HEAD response is drained and discarded — we only care about
// warming the connection pool. When an Alt-Svc entry exists for the host, the
// h3Client is also warmed so the QUIC handshake is complete before the first
// real DoH request arrives.
func (x *XTransport) prewarmConnection(hostPort string) {
	hk := unique.Make(hostPort)
	x.prewarmed.do(hk, func() {
		go func() {
			// ── Concurrency gate: skip this prewarm if the semaphore is full ──────
			// prewarmSem is a buffered channel of size prewarmMaxConcurrency.
			// Non-blocking send: if the channel is full, all slots are occupied and
			// we skip rather than queue — prewarming is best-effort.
			select {
			case prewarmSem <- struct{}{}:
				defer func() { <-prewarmSem }()
			default:
				prewarmSkipped.Add(1)
				dlog.Debugf("Prewarm: semaphore full, skipping %s", hostPort)
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), h2TLSHandshakeTimeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodHead,
				"https://"+hostPort+"/", nil)
			if err != nil {
				dlog.Debugf("Prewarm: failed to build request for %s: %v", hostPort, err)
				return
			}
			req.Header = x.headers.getPlain

			resp, err := x.httpClient.Do(req)
			if err != nil {
				dlog.Debugf("Prewarm: %s: %v (connection may still be cached)", hostPort, err)
			} else {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
				resp.Body.Close()
				dlog.Debugf("Prewarmed HTTP/2 connection to %s (status %d)", hostPort, resp.StatusCode)
			}

			// Also warm H3 if transport is ready and Alt-Svc exists for the host.
			if x.h3Transport == nil {
				return
			}
			host, _ := splitHostPort(hostPort)
			x.altSupport.RLock()
			entry, inCache := x.altSupport.cache[host]
			x.altSupport.RUnlock()
			if !inCache || entry.port == 0 {
				return
			}
			h3Req, h3Err := http.NewRequestWithContext(ctx, http.MethodHead,
				"https://"+hostPort+"/", nil)
			if h3Err != nil {
				return
			}
			h3Req.Header = x.headers.getPlain
			h3Resp, h3Err := x.h3Client.Do(h3Req)
			if h3Err != nil {
				dlog.Debugf("Prewarm H3: %s: %v", hostPort, h3Err)
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(h3Resp.Body, 4*1024))
			h3Resp.Body.Close()
			dlog.Debugf("Prewarmed HTTP/3 connection to %s (status %d)", hostPort, h3Resp.StatusCode)
		}()
	})
}

// splitHostPort splits "host:port" → ("host", "port"), handling IPv6 brackets.
// Uses net.SplitHostPort for correct IPv6 address handling (e.g. "::1:443").
func splitHostPort(hostPort string) (host, port string) {
	if h, p, err := net.SplitHostPort(hostPort); err == nil {
		return h, p
	}
	return hostPort, ""
}

func (x *XTransport) buildDialContext() func(context.Context, string, string) (net.Conn, error) {
	useIPv4, useIPv6 := x.useIPv4, x.useIPv6
	return func(ctx context.Context, network, addrStr string) (net.Conn, error) {
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
		portU16 := uint16(port & 0xffff)

		cachedAddrs, expired, updating := x.loadCachedAddrs(host)
		if expired && !updating && len(cachedAddrs) > 0 {
			dlog.Debugf("[%s] dialing with expired cached IP (refresh pending)", host)
		}

		dialNet := network
		switch {
		case useIPv4 && !useIPv6:
			dialNet = "tcp4"
		case useIPv6 && !useIPv4:
			dialNet = "tcp6"
		}

		dialOne := func(ctx context.Context, dialNet, target string) (net.Conn, error) {
			if x.proxyDialer == nil {
				return x.dialer.DialContext(ctx, dialNet, target)
			}
			// Proxy path: ControlContext cannot run (proxy owns the socket).
			// Apply options post-dial; TCP_FASTOPEN_CONNECT is omitted as it
			// is a no-op on already-connected sockets.
			var conn net.Conn
			var err error
			if pdCtx, ok := (*x.proxyDialer).(netproxy.ContextDialer); ok {
				conn, err = pdCtx.DialContext(ctx, dialNet, target)
			} else {
				conn, err = (*x.proxyDialer).Dial(dialNet, target)
			}
			if err == nil {
				setTCPOptions(conn)
			}
			return conn, err
		}

		var lastErr error
		for i, addr := range cachedAddrs {
			target := formatDialTarget(addr, portU16)
			conn, err := dialOne(ctx, dialNet, target)
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if i < len(cachedAddrs)-1 {
				dlog.Debugf("Dial [%s] failed: %v", target, err)
			}
		}

		if len(cachedAddrs) > 0 {
			return nil, lastErr
		}
		dlog.Debugf("[%s] no cached IP; falling back to hostname dial", host)

		var fallbackTarget string
		if parsedHost := parseIPAddr(host); parsedHost.IsValid() {
			fallbackTarget = formatDialTarget(parsedHost, portU16)
		} else {
			// formatHostPort caches the "host:port" string, avoiding a repeated
			// strconv.Itoa call on every dial attempt for uncached IP hosts.
			fallbackTarget = formatHostPort(host, port)
		}
		return dialOne(ctx, dialNet, fallbackTarget)
	}
}

func (x *XTransport) buildH3DialFunc() func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addrStr string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		dlog.Debugf("H3 dial: [%s]", addrStr)
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
		portU16 := uint16(port & 0xffff)

		type udpTarget struct {
			addr    string
			network string
		}

		// Use cached dial target strings for UDP (avoids repeated formatting).
		udpEndpoint := func(addr netip.Addr) udpTarget {
			if addr.IsValid() {
				nw := "udp4"
				if addr.Is6() {
					nw = "udp6"
				}
				return udpTarget{formatDialTarget(addr, portU16), nw}
			}
			parsed := parseIPAddr(host)
			if parsed.IsValid() {
				nw := "udp4"
				if parsed.Is6() {
					nw = "udp6"
				}
				return udpTarget{formatDialTarget(parsed, portU16), nw}
			}
			nw := "udp4"
			if x.useIPv6 {
				if x.useIPv4 {
					nw = "udp"
				} else {
					nw = "udp6"
				}
			}
			return udpTarget{host + ":" + strconv.Itoa(port), nw}
		}

		cachedAddrs, expired, updating := x.loadCachedAddrs(host)
		if expired && !updating && len(cachedAddrs) > 0 {
			dlog.Debugf("[%s] H3 dialing with expired cached IP (refresh pending)", host)
		}
		targets := make([]udpTarget, 0, max(len(cachedAddrs), 1))
		for _, addr := range cachedAddrs {
			targets = append(targets, udpEndpoint(addr))
		}
		if len(targets) == 0 {
			dlog.Debugf("[%s] no cached IP for H3 dial", host)
			targets = append(targets, udpEndpoint(netip.Addr{}))
		}

		var lastErr error
		tlsCfg := x.tlsClientConfig.Clone()
		tlsCfg.ServerName = host

		for i, t := range targets {
			udpAddr, err := net.ResolveUDPAddr(t.network, t.addr)
			if err != nil {
				lastErr = err
				if i < len(targets)-1 {
					dlog.Debugf("H3: resolve [%s]/%s failed: %v", t.addr, t.network, err)
				}
				continue
			}
			// Wrap ListenUDP+DialEarly in an IIFE so defer fires per-iteration.
			conn, dialErr := func() (*quic.Conn, error) {
				udpConn, listenErr := net.ListenUDP(t.network, nil)
				if listenErr != nil {
					return nil, listenErr
				}
				setUDPOptions(udpConn)

				connClosed := false
				defer func() {
					if !connClosed {
						_ = udpConn.Close()
					}
				}()
				c, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
				if err != nil {
					return nil, err
				}
				connClosed = true // QUIC conn now owns the socket
				return c, nil
			}()
			if dialErr != nil {
				lastErr = dialErr
				if i < len(targets)-1 {
					dlog.Debugf("H3: quic.DialEarly [%s]/%s failed: %v", t.addr, t.network, dialErr)
				}
				continue
			}
			return conn, nil
		}
		return nil, lastErr
	}
}

// ── TLS configuration ─────────────────────────────────────────────────────────
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
			dlog.Fatalf("Custom root CA not supported: %v", certPoolErr)
		}
		pem, err := os.ReadFile(creds.rootCA)
		if err != nil {
			dlog.Fatalf("Unable to read rootCA [%s]: %v", creds.rootCA, err)
		}
		certPool.AppendCertsFromPEM(pem)
	}
	// Ensure the ISRG Root X1 certificate is always installed, even when
	// SystemCertPool returns (nil, nil) in sandboxed or minimal environments.
	if certPool == nil {
		certPool = x509.NewCertPool()
	}
	certPool.AppendCertsFromPEM(isrgRootX1PEM)
	cfg.RootCAs = certPool
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
	cfg.ClientSessionCache = tlsSessionCache

	if x.tlsPreferRSA {
		cfg.MaxVersion = tls.VersionTLS13
	}

	cfg.CurvePreferences = []tls.CurveID{
		tls.X25519MLKEM768,
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}

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

// ── DNS resolution ────────────────────────────────────────────────────────────
func (x *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	ctx, cancel := context.WithTimeoutCause(context.Background(), SystemResolverTimeout, errSystemResolverTimeout)
	defer cancel()
	addrs, err := systemResolver.LookupIPAddr(ctx, host)
	if err != nil && len(addrs) == 0 {
		return nil, SystemResolverIPTTL, err
	}
	if returnIPv4 && returnIPv6 {
		if len(addrs) == 0 {
			return nil, SystemResolverIPTTL, err
		}
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

func (x *XTransport) resolveRRType(
	proto, host, resolver string,
	rrType uint16,
) (ips []net.IP, minTTL uint32, err error) {
	ctx, cancel := context.WithTimeoutCause(context.Background(), ResolverReadTimeout, errDNSQueryTimeout)
	defer cancel()

	msg := dns.NewMsg(fqdn(host), rrType) // fqdn is defined in common.go
	if msg == nil {
		return nil, ttlSentinel, fmt.Errorf("dns.NewMsg returned nil for [%s] type %d", host, rrType)
	}
	msg.RecursionDesired = true
	msg.UDPSize = uint16(MaxDNSPacketSize) // defined in common.go
	msg.Security = true

	in, _, err := x.dnsClient.Exchange(ctx, msg, proto, resolver)
	if err != nil {
		return nil, ttlSentinel, err
	}

	minTTL = ttlSentinel
	for _, answer := range in.Answer {
		if dns.RRToType(answer) != rrType {
			continue
		}
		switch rrType {
		case dns.TypeA:
			if a, ok := answer.(*dns.A); ok {
				ips = append(ips, a.A.Addr.AsSlice())
			} else {
				continue
			}
		case dns.TypeAAAA:
			if aaaa, ok := answer.(*dns.AAAA); ok {
				ips = append(ips, aaaa.AAAA.Addr.AsSlice())
			} else {
				continue
			}
		}
		if ttl := answer.Header().TTL; ttl < minTTL {
			minTTL = ttl
		}
	}
	return
}

func (x *XTransport) resolveUsingResolver(
	proto, host, resolver string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
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
		rips, rttl, rerr := x.resolveRRType(proto, host, resolver, qt[0])
		if rerr != nil {
			return nil, 0, rerr
		}
		if len(rips) == 0 {
			return nil, 0, errNoIPRecords
		}
		if rttl == ttlSentinel {
			rttl = 0
		}
		return rips, time.Duration(rttl) * time.Second, nil
	}

	type rrResult struct {
		ips    []net.IP
		minTTL uint32
		err    error
	}
	var results [2]rrResult
	var wg sync.WaitGroup
	for i, rrType := range qt[:n] {
		wg.Go(func() {
			results[i].ips, results[i].minTTL, results[i].err =
				x.resolveRRType(proto, host, resolver, rrType)
		})
	}
	wg.Wait()

	overallMinTTL := ttlSentinel
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
		if overallMinTTL == ttlSentinel {
			overallMinTTL = 0
		}
		return ips, time.Duration(overallMinTTL) * time.Second, nil
	}
	if len(errs) > 0 {
		return nil, 0, errors.Join(errs...)
	}
	return nil, 0, errNoIPRecords
}

func (x *XTransport) resolveUsingServers(
	proto, host string,
	resolvers []string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	if len(resolvers) == 0 {
		return nil, 0, errEmptyResolvers
	}
	// Deep-copy the resolvers slice so the promotion swap never races against
	// concurrent readers of x.internalResolvers / x.bootstrapResolvers.
	resolversCopy := make([]string, len(resolvers))
	copy(resolversCopy, resolvers)

	// ── Parallel race: try top-2 resolvers concurrently for the first attempt ──
	// Whichever responds first with a valid answer wins. This cuts P95/P99 tail
	// latency significantly when one resolver is occasionally slow: instead of
	// waiting up to ResolverReadTimeout for resolver[0] before trying resolver[1],
	// both are queried simultaneously and the faster result is used.
	//
	// The goroutines use buffered channels (size raceN) so they can always send
	// without blocking even after we have returned, and will complete within at
	// most ResolverReadTimeout on their own. If both fail we fall through to the
	// full serial+retry loop below (which re-tries with exponential backoff).
	if len(resolversCopy) >= 2 {
		type raceItem struct {
			ips []net.IP
			ttl time.Duration
			idx int // -1 signals failure
		}
		const raceN = 2
		ch := make(chan raceItem, raceN) // buffered so goroutines never block on send
		for i := 0; i < raceN; i++ {
			go func(idx int, resolver string) {
				rips, rttl, rerr := x.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)
				if rerr == nil && len(rips) > 0 {
					ch <- raceItem{rips, rttl, idx}
				} else {
					ch <- raceItem{idx: -1}
				}
			}(i, resolversCopy[i])
		}
		failures := 0
		for failures < raceN {
			res := <-ch
			if res.idx >= 0 {
				// First success: promote the winning resolver to position 0 so
				// future calls (and the serial loop below) try it first.
				if res.idx > 0 {
					resolversCopy[0], resolversCopy[res.idx] = resolversCopy[res.idx], resolversCopy[0]
					dlog.Debugf("Resolver race: %s[%s] won for [%s]; promoting to first",
						proto, resolversCopy[0], host)
				}
				resolverRaceWins.Add(1)
				return res.ips, res.ttl, nil
			}
			failures++
		}
		// Both race attempts failed; fall through to the full serial+retry loop.
	}

	var errs []error
	var retryTimer *time.Timer
	defer func() {
		if retryTimer != nil && !retryTimer.Stop() {
			select {
			case <-retryTimer.C:
			default:
			}
		}
	}()
	for i, resolver := range resolversCopy {
		delay := resolverRetryInitialBackoff
		for attempt := range resolverRetryCount {
			ips, ttl, err = x.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)
			if err == nil && len(ips) > 0 {
				if i > 0 {
					dlog.Infof("Resolution succeeded via %s[%s]; promoting to first", proto, resolver)
					resolversCopy[0], resolversCopy[i] = resolversCopy[i], resolversCopy[0]
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
				// Reuse a single timer across retries to avoid per-retry allocations.
				if retryTimer == nil {
					retryTimer = time.NewTimer(delay)
				} else {
					if !retryTimer.Stop() {
						select {
						case <-retryTimer.C:
						default:
						}
					}
					retryTimer.Reset(delay)
				}
				<-retryTimer.C
				delay = min(delay*2, resolverRetryMaxBackoff)
			}
		}
		dlog.Infof("Unable to resolve [%s] using [%s] (%s)", host, resolver, proto)
	}
	return nil, 0, errors.Join(errs...)
}

func (x *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	primary, fallback := "udp", "tcp"
	if x.mainProto == "tcp" {
		primary, fallback = "tcp", "udp"
	}
	protos := [2]string{primary, fallback}

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

	for _, proto := range protos {
		dlog.Noticef("Resolving [%s] via bootstrap resolvers over %s", host, proto)
		ips, ttl, err = x.resolveUsingServers(
			proto, host, x.bootstrapResolvers, returnIPv4, returnIPv6)
		if err == nil {
			return ips, ttl, nil
		}
	}

	if !x.ignoreSystemDNS {
		dlog.Noticef("Bootstrap resolvers failed — last-resort system resolver for [%s]", host)
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)
	}
	return ips, ttl, err
}

// ── Per‑host resolution mutex ─────────────────────────────────────────────────
func (x *XTransport) hostResolveMu(host string) *sync.Mutex {
	k := unique.Make(host)
	// Single LoadOrStore — one atomic operation regardless of cache hit/miss.
	v, _ := x.resolveMu.LoadOrStore(k, new(sync.Mutex))
	return v.(*sync.Mutex)
}

func (x *XTransport) resolveAndUpdateCache(host string) error {
	if x.proxyDialer != nil || x.httpProxyFunction != nil {
		return nil
	}
	if parseIPAddr(host).IsValid() {
		return nil
	}

	cachedAddrs, expired, updating := x.loadCachedAddrs(host)
	if len(cachedAddrs) > 0 && (!expired || updating) {
		return nil
	}

	mu := x.hostResolveMu(host)
	mu.Lock()
	defer mu.Unlock()

	cachedAddrs, expired, _ = x.loadCachedAddrs(host)
	if len(cachedAddrs) > 0 && !expired {
		return nil
	}

	x.markUpdatingCachedIP(host)

	ips, ttl, resolveErr := x.resolve(host, x.useIPv4, x.useIPv6)

	if resolveErr != nil {
		if dnsErr, ok := errors.AsType[*net.DNSError](resolveErr); ok {
			dlog.Debugf("[%s] DNS error: name=%s notFound=%v temp=%v",
				host, dnsErr.Name, dnsErr.IsNotFound, dnsErr.IsTemporary)
		}
	}

	ttl = max(ttl, MinResolverIPTTL)

	if (resolveErr != nil || len(ips) == 0) && len(cachedAddrs) > 0 {
		dlog.Noticef("Using stale cached address for [%s] (grace period)", host)
		// We already have []netip.Addr; call saveCachedAddrs directly to avoid
		// an unnecessary netip.Addr → net.IP → netip.Addr round-trip.
		x.saveCachedAddrs(host, cachedAddrs, ExpiredCachedIPGraceTTL)
		return nil
	}

	if resolveErr != nil {
		return resolveErr
	}

	if len(ips) == 0 {
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

	x.saveCachedIPs(host, ips, ttl)
	return nil
}

// ── HTTP fetch engine ─────────────────────────────────────────────────────────
// Callers with an existing deadline pass ctx directly; pass context.Background()
// to use the default x.timeout.
func (x *XTransport) Fetch(
	ctx context.Context,
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

	if url == nil {
		return nil, 0, nil, 0, errors.New("nil URL")
	}
	if url.Host == "" {
		return nil, 0, nil, 0, errors.New("empty host in URL")
	}

	client := &x.httpClient

	host, port := ExtractHostAndPort(url.Host, 443)
	if x.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0, errNoTorProxy
	}

	// Prewarm a full TLS+HTTP/2 (and optionally H3) connection once per host.
	// Use the cached "host:port" string to avoid a string concatenation per request.
	x.prewarmConnection(formatHostPort(host, port))

	hasAltSupport := false
	if x.h3Transport != nil {
		// Cache the backoff result to avoid calling isH3InBackoff twice for
		// the same host within a single request.
		h3InBackoff := x.isH3InBackoff(url.Host)
		if x.http3Probe {
			// Respect H3 health backoff even in probe mode to avoid hammering
			// a transiently broken QUIC endpoint.
			if !h3InBackoff {
				client = &x.h3Client
			}
		} else {
			x.altSupport.RLock()
			entry, inCache := x.altSupport.cache[url.Host]
			x.altSupport.RUnlock()
			if inCache {
				hasAltSupport = true
				// Use isAltSvcExpired for an unambiguous negative-cache check.
				negativeExpired := entry.port == 0 && isAltSvcExpired(entry, time.Now())
				switch {
				case entry.port > 0 && int(entry.port) == port && !h3InBackoff:
					// Use H3 only when within its Alt-Svc advertisement AND not in
					// a per-host backoff window caused by repeated H3 failures.
					client = &x.h3Client
				case negativeExpired:
					hasAltSupport = false
				}
			}
		}
	}

	// Select pre-built header map — zero allocation on the hot path.
	var header http.Header
	switch {
	case method == http.MethodPost && contentType == "application/dns-message":
		header = x.headers.postDNS
	case method == http.MethodPost && contentType == "application/oblivious-dns-message":
		header = x.headers.postODNS
	case compress && body == nil:
		header = x.headers.getGzip
	default:
		header = x.headers.getPlain
	}

	// If custom accept is different from what's pre-built, we need to clone
	if accept != "" && header.Get("Accept") != accept {
		header = header.Clone()
		header.Set("Accept", accept)
	}

	// Append body_hash query parameter only when the feature is enabled.
	// Direct string concatenation is safe here: hex.EncodeToString produces
	// only [0-9a-f] characters (URL-safe), and url.RawQuery is already
	// percent-encoded. This avoids allocating a url.Values map.
	if body != nil && x.BodyHashEnabled {
		h := sha512.Sum512_256(*body)
		hashHex := hex.EncodeToString(h[:])
		u2 := *url
		if url.RawQuery == "" {
			u2.RawQuery = "body_hash=" + hashHex
		} else {
			u2.RawQuery = url.RawQuery + "&body_hash=" + hashHex
		}
		url = &u2
	}
	// IP-literal hosts bypass the resolver entirely.
	if !parseIPAddr(host).IsValid() {
		if err := x.resolveAndUpdateCache(host); err != nil {
			dlog.Errorf("[%s]: unable to resolve host: %v", host, err)
			return nil, 0, nil, 0, fmt.Errorf("resolve %s: %w", host, err)
		}
	}

	bodyLen := 0
	if body != nil {
		bodyLen = len(*body)
	}
	requestURL := url.String()

	// Use the caller's context when it already has a deadline; only create a
	// child WithTimeout context when no deadline is set. This avoids one context
	// allocation per request on the hot path.
	fetchCtx := ctx
	cancel := func() {} // noop by default — no allocation
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		fetchCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	newRequest := func() (*http.Request, error) {
		var reqBody io.Reader
		if body != nil {
			reqBody = bytes.NewReader(*body)
		}
		req, err := http.NewRequestWithContext(fetchCtx, method, requestURL, reqBody)
		if err != nil {
			return nil, err
		}
		req.Header = header
		req.ContentLength = int64(bodyLen)
		return req, nil
	}

	req, err := newRequest()
	if err != nil {
		return nil, 0, nil, 0, err
	}

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	// Track whether the initial request used H3 so we can update its health state.
	usedH3 := client == &x.h3Client

	if err != nil && client == &x.h3Client {
		// Close any non-nil H3 response body before resp is overwritten.
		if resp != nil {
			resp.Body.Close()
			resp = nil
		}
		dlog.Debugf("HTTP/3 failed for [%s]: %v — retrying over HTTP/2", url.Host, err)
		// Record H3 failure for adaptive backoff. After h3FailureThreshold
		// consecutive failures the host enters a backoff window.
		x.recordH3Failure(url.Host)
		negativeUntil := time.Now().Add(altSvcNegativeTTL)
		x.altSupport.Lock()
		x.altSupport.cache[url.Host] = altSvcEntry{port: 0, validTo: negativeUntil}
		x.altSupport.Unlock()

		// Build a fresh *http.Request for the H2 retry: reusing the original req
		// after Do() violates the net/http contract.
		usedH3 = false // fallback occurred; H3 did not produce the response
		client = &x.httpClient
		req, err = newRequest()
		if err != nil {
			return nil, 0, nil, 0, err
		}
		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)
	}

	// Record H3 success: resets failure counter and clears any active backoff.
	// Only called when the H3 request itself succeeded (no fallback triggered).
	// Intentionally placed before the status-code check: a 4xx/5xx HTTP response
	// is an application-layer error, not an H3 transport failure — the QUIC path
	// is working correctly if we received any response without a Do() error.
	// We do not record success for 5xx responses to avoid masking H3-specific
	// server-side degradation patterns; partial success is treated conservatively.
	if usedH3 && err == nil && resp != nil && resp.StatusCode < 500 {
		x.recordH3Success(url.Host)
	}

	// ── Body close ────────────────────────────────────────────────────────────
	// Always register the defer (outside the resp != nil guard so it fires
	// regardless of the code path taken above). The closure captures resp by
	// reference, so it always closes the final resp value — nil-safe.
	defer func() {
		if resp != nil {
			resp.Body.Close()
		}
	}()
	statusCode := 503
	if resp != nil {
		statusCode = resp.StatusCode
	}
	if err == nil {
		switch {
		case resp == nil:
			err = errEmptyResponse
		case resp.StatusCode < 200 || resp.StatusCode > 299:
			// Drain a small amount so the underlying connection can be reused.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32*1024))
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
	if x.h3Transport != nil && !hasAltSupport {
		x.parseAndCacheAltSvc(url.Host, port, resp.Header)
	}
	tlsState := resp.TLS
	var bodyReader io.ReadCloser = resp.Body
	if compress && resp.Header.Get("Content-Encoding") == "gzip" {
		gr := gzipReaderPool.Get().(*gzip.Reader)
		grErr := gr.Reset(io.LimitReader(resp.Body, MaxHTTPBodyLength))
		if grErr != nil {
			// Do not return a failed-Reset reader to the pool.
			return nil, statusCode, tlsState, rtt, grErr
		}
		defer func() {
			// Only return healthy readers to the pool.
			if closeErr := gr.Close(); closeErr == nil {
				gzipReaderPool.Put(gr)
			}
		}()
		bodyReader = gr
	}

	// Read the response body into a pooled buffer to avoid the internal
	// reallocation chain of io.ReadAll (which starts at 512 bytes and doubles
	// on each grow). The pooled buffer is pre-sized to 4096 bytes, covering
	// the vast majority of DNS responses in a single read with no reallocation.
	//
	// A right-sized copy is made before returning. This is intentional: the
	// pooled buffer must be returned immediately so it can be reused by the
	// next query. Returning the pooled slice directly would create a
	// use-after-return hazard since callers (processDoHQuery, plugin cache)
	// retain the response across goroutine lifetimes. The net gain is still
	// positive: one exact-size allocation + copy vs io.ReadAll's O(log n)
	// growing reallocation chain.
	bufp := httpResponseBufPool.Get().(*[]byte)
	buf := (*bufp)[:0]
	buf, err = appendFrom(buf, io.LimitReader(bodyReader, MaxHTTPBodyLength))
	if err != nil {
		*bufp = buf
		httpResponseBufPool.Put(bufp)
		return nil, statusCode, tlsState, rtt, err
	}
	// Make an owned copy so the pooled buffer can be returned immediately.
	bin := make([]byte, len(buf))
	copy(bin, buf)
	*bufp = buf
	httpResponseBufPool.Put(bufp)
	return bin, statusCode, tlsState, rtt, nil
}

func (x *XTransport) parseAndCacheAltSvc(host string, port int, header http.Header) {
	now := time.Now()
	x.altSupport.RLock()
	existing, inCache := x.altSupport.cache[host]
	x.altSupport.RUnlock()
	if inCache && existing.port == 0 && !isAltSvcExpired(existing, now) {
		dlog.Debugf("Alt-Svc: negative cache still valid for [%s]; skipping", host)
		return
	}

	alt, found := header["Alt-Svc"]
	if !found {
		return
	}
	dlog.Debugf("Alt-Svc [%s]: %v", host, alt)

	altPort := uint16(port & 0xffff)
	h3Found := false

outer:
	for i, entry := range alt {
		if i >= 8 {
			break
		}
		j := 0
		for field := range strings.SplitSeq(entry, ";") {
			if j >= 16 {
				break
			}
			j++
			if after, ok := strings.CutPrefix(strings.TrimSpace(field), `h3="`); ok {
				v := strings.TrimSuffix(after, `"`)
				// ParseUint(v, 10, 16) already restricts the result to [0, 65535]
				// by construction (bitSize=16).
				if p, pErr := strconv.ParseUint(v, 10, 16); pErr == nil {
					altPort = uint16(p)
					h3Found = true
					dlog.Debugf("Alt-Svc: HTTP/3 advertised for [%s] on port %d", host, altPort)
					break outer
				}
			}
		}
	}

	// If no h3= field was found in the Alt-Svc header, do not cache a
	// positive entry — altPort still equals the current port, and caching
	// it would incorrectly route all future requests through the H3 client.
	if !h3Found {
		dlog.Debugf("Alt-Svc: no h3= field found for [%s]; not caching", host)
		return
	}

	x.altSupport.Lock()
	// TOCTOU double-check under write lock: between the RLock read at the top
	// of this function and this Lock, another goroutine could have written a
	// fresh negative-cache entry. Re-check to avoid overwriting it.
	if cur, ok := x.altSupport.cache[host]; ok && cur.port == 0 && !isAltSvcExpired(cur, now) {
		x.altSupport.Unlock()
		dlog.Debugf("Alt-Svc: concurrent negative cache write for [%s]; skipping", host)
		return
	}
	x.altSupport.cache[host] = altSvcEntry{port: altPort, noExpiry: true}
	dlog.Debugf("Alt-Svc: cached port %d for [%s]", altPort, host)
	x.altSupport.Unlock()
}

// ── H3 per-host health helpers ────────────────────────────────────────────────

// h3HealthFor returns (or lazily creates) the h3HealthState for host.
func (x *XTransport) h3HealthFor(host string) *h3HealthState {
	v, _ := x.h3Health.LoadOrStore(host, &h3HealthState{})
	return v.(*h3HealthState)
}

// isH3InBackoff reports whether H3 should currently be suppressed for host.
// Called on the hot path; uses a short lock only inside h3HealthState.inBackoff.
func (x *XTransport) isH3InBackoff(host string) bool {
	if v, ok := x.h3Health.Load(host); ok {
		return v.(*h3HealthState).inBackoff()
	}
	return false
}

// recordH3Failure increments the per-host H3 failure counter and sets a backoff
// window once the threshold is crossed. Also increments the global h3FallbackTotal
// counter for observability.
func (x *XTransport) recordH3Failure(host string) {
	if inBackoff := x.h3HealthFor(host).onFailure(); inBackoff {
		dlog.Debugf("H3 health: [%s] entered backoff after %d failures", host, h3FailureThreshold)
	}
	h3FallbackTotal.Add(1)
}

// recordH3Success resets the per-host H3 health state, clearing any active backoff
// so H3 will be used again on the next applicable request.
func (x *XTransport) recordH3Success(host string) {
	if v, ok := x.h3Health.Load(host); ok {
		v.(*h3HealthState).onSuccess()
	}
}

// ── Public query helpers ──────────────────────────────────────────────────────
func (x *XTransport) GetWithCompression(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(context.Background(), http.MethodGet, url, accept, "", nil, timeout, true)
}

func (x *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(context.Background(), http.MethodGet, url, accept, "", nil, timeout, false)
}

func (x *XTransport) Post(
	url *url.URL,
	accept, contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(context.Background(), http.MethodPost, url, accept, contentType, body, timeout, false)
}

func (x *XTransport) dohLikeQuery(
	dataType string,
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if useGet {
		// Build the query string directly instead of going through url.Query()
		// (which allocates a url.Values map) + qs.Encode() (which re-encodes).
		// The "dns" parameter value is already URL-safe (base64 raw-URL encoding).
		encoded := base64.RawURLEncoding.EncodeToString(body)
		u2 := *url
		if url.RawQuery == "" {
			u2.RawQuery = "dns=" + encoded
		} else {
			u2.RawQuery = url.RawQuery + "&dns=" + encoded
		}
		return x.Get(&u2, dataType, timeout)
	}
	return x.Post(url, dataType, dataType, &body, timeout)
}

func (x *XTransport) DoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/dns-message", useGet, url, body, timeout)
}

func (x *XTransport) ObliviousDoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}
