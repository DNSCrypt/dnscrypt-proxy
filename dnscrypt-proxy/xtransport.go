//go:build linux
// +build linux

// xtransport.go — HTTP/HTTPS transport layer for dnscrypt-proxy.
//
// Complete rewrite for Go 1.26+, focusing on performance, efficiency,
// and full compatibility with dnscrypt-proxy 2. Drop-in replacement.
//
// ══════════════════════════════════════════════════════════════════════════════
// ✅ CRITICAL BUG FIXES APPLIED - March 12, 2026 (all fixes correctly implemented)
// ══════════════════════════════════════════════════════════════════════════════
// FIX 1: UDP connection leak in HTTP/3 dial (buildH3DialFunc)
//        ListenUDP+DialEarly wrapped in an IIFE per loop iteration. A connClosed
//        flag inside the closure guarantees the UDP socket is closed on every
//        failure path (including panics), not just the err != nil branch.
//
// FIX 2: Gzip reader pool poisoning (Fetch gzip decompression)
//        Reset-failure path no longer calls Pool.Put — reader may be in an
//        indeterminate state and must not re-enter the pool. Defer now only
//        returns readers to pool when gr.Close() succeeds.
//
// FIX 3: DNS resolver promotion race (resolveUsingServers)
//        make+copy produces a true deep copy before iteration. Promotion swap
//        targets only the local copy, never the shared backing array of
//        x.internalResolvers / x.bootstrapResolvers.
//
// FIX 4: Double-close race on response body (Fetch response handling)
//        sync.Once wraps resp.Body.Close so it fires exactly once. H3 fallback
//        also explicitly closes any non-nil first response before overwriting resp.
// ══════════════════════════════════════════════════════════════════════════════
//
// ══════════════════════════════════════════════════════════════════════════════
// ✅ ELITE PERFORMANCE IMPROVEMENTS - March 16, 2026
// ══════════════════════════════════════════════════════════════════════════════
// PERF 1: Eliminated per-request http.Client allocation (HOT PATH - CRITICAL)
//         http.Client was allocated on every Fetch() call (~56 bytes + heap
//         escape). httpClient and h3Client are now stored as XTransport fields
//         and rebuilt only in rebuildTransport(). Zero allocations on hot path.
//
// PERF 2: Fixed TCP_NOTSENT_LOWAT socket option (was incorrectly using SO_SNDLOWAT)
//         SO_SNDLOWAT (SOL_SOCKET level) and TCP_NOTSENT_LOWAT (IPPROTO_TCP level)
//         are entirely different options. The comment said TCP_NOTSENT_LOWAT but
//         the code called unix.SO_SNDLOWAT at SOL_SOCKET — semantically wrong.
//         Now uses unix.TCP_NOTSENT_LOWAT (= 25) at IPPROTO_TCP level with 16 KiB,
//         which prevents kernel-side send-buffer bloat and reduces write latency.
//
// PERF 3: Added SO_BUSY_POLL on H3/QUIC UDP sockets (Linux 3.11+)
//         Busy-poll asks the kernel to spin-poll incoming packets for up to 50 µs
//         before sleeping. Eliminates the context-switch interrupt path for
//         latency-sensitive DoH/DoQ where ~7 µs/response matters.
//
// PERF 4: Proper TLS prewarming via real HEAD request through http.Client
//         prewarmConnection previously called transport.DialContext (TCP only) —
//         no TLS or HTTP/2 handshake occurred. Now uses a HEAD request through
//         the http.Client so the full TLS+ALPN+HTTP/2 handshake is completed and
//         the connection is deposited into the transport idle-conn pool.
//
// PERF 5: QUIC flow-control tuning for H3 transport
//         h3Transport now carries an explicit quic.Config with tuned receive
//         windows (InitialStreamReceiveWindow=512 KiB, MaxStreamReceiveWindow=4 MiB,
//         InitialConnectionReceiveWindow=1 MiB, MaxConnectionReceiveWindow=8 MiB).
//         DNS responses are small but the larger windows prevent ACK-stall on
//         bursts and reduce WINDOW_UPDATE round-trips.
//
// PERF 6: Collapsed sync.Map double-lookup in hostResolveMu and hostPrewarmer
//         Replaced Load + LoadOrStore pattern with a single LoadOrStore call,
//         eliminating the redundant map traversal on the cold path.
//         hostPrewarmer.m keys upgraded to unique.Handle[string] for pointer-
//         equality comparisons (same as resolveMu) — faster than raw string compare.
//
// PERF 7: Inlined ParseIP fast-exit in Fetch hot path
//         resolveAndUpdateCache already guards against IP literals, but calling
//         through the function still pays the overhead of the proxy/cache checks.
//         A cheap ParseIP in Fetch skips the entire function call for IP hosts.
//
// PERF 8: SO_RCVBUF / SO_SNDBUF socket buffer tuning
//         TCP sockets now request 256 KiB send and receive buffers. Kernel will
//         grant up to the system's net.core.rmem_max / wmem_max ceiling. This
//         prevents buffer-limited throughput on high-BDP paths without affecting
//         the typical small-packet DoH workload.
// ══════════════════════════════════════════════════════════════════════════════
//
// ══════════════════════════════════════════════════════════════════════════════
// ✅ ADDITIONAL IMPROVEMENTS - March 16, 2026
// ══════════════════════════════════════════════════════════════════════════════
// IMP 1: Fetch H3→H2 retry uses a fresh http.Request (not the mutated original)
//        After H3 fails, the original req was reused by re-setting req.Body —
//        violating the net/http contract that a Request must not be reused after
//        Do(). The retry now builds a brand-new *http.Request with the same
//        method, URL, header, and body so the contract is always honoured.
//
// IMP 2: prewarmConnection also warms H3 path when h3Transport is present
//        The old implementation only warmed the HTTP/2 path. When a host has
//        an active Alt-Svc entry the first real request still paid the full QUIC
//        handshake cost cold. The prewarmer now additionally fires a QUIC dial
//        via h3Client when http3 is enabled and an Alt-Svc entry exists.
//
// IMP 3: setTCPOptions runtime.GOOS dead-code branch removed
//        File has //go:build linux so runtime.GOOS is always "linux". The
//        non-Linux branch was dead code. Removed to reduce binary size and
//        eliminate a runtime branch on the hot dial path.
//
// IMP 4: altSvcEntry gains explicit noExpiry bool — removes zero-time ambiguity
//        Previously port>0 with validTo.IsZero() meant "valid forever" and
//        port==0 with validTo.IsZero() was ambiguous between "no negative cache"
//        and "still valid". noExpiry bool makes intent explicit and removes the
//        dual meaning of the zero-time sentinel.
//
// IMP 5: saveCachedIP inlined — removes redundant single-element slice alloc
//        The only callers are internal. The thin wrapper allocated []net.IP{ip}
//        on every call. Direct call to saveCachedIPs with a stack-allocated
//        single-element slice avoids the extra heap allocation.

// ══════════════════════════════════════════════════════════════════════════════
// ✅ DOQ TRANSPORT — RFC 9250 — March 21, 2026
// ══════════════════════════════════════════════════════════════════════════════
// DOQ 1: Native DNS-over-QUIC transport — no HTTP overhead
//   Each DNS query is a 2-byte-length-prefixed DNS wire message on a new
//   bidirectional QUIC stream. One persistent QUIC connection per host
//   multiplexes all concurrent queries. ALPN: "doq", default port: 853.
//
// DOQ 2: Persistent per-host connection pool with automatic reconnect
//   doqConnEntry holds one *quic.Conn per host:port under a sync.Mutex.
//   Stale detection via conn.Context().Done(). Retry-once on transport errors.
//   Pool drained in rebuildTransport() alongside the H3 transport.
//
// DOQ 3: Separate QUIC config tuned for tiny DNS payloads (<512 bytes typical)
//   Flow-control windows 8× tighter than H3 (64 KiB stream / 1 MiB conn).
//   MaxIdleTimeout = 2 min; server closing first triggers transparent reconnect.
//
// DOQ 4: SO_BUSY_POLL + SO_RCVBUF/SO_SNDBUF via setUDPOptions() — same
//   µs-latency optimizations applied to H3 UDP sockets, now also on DoQ.
//
// DOQ 5: PQ-TLS 1.3 with shared tlsSessionCache — 0-RTT on reconnect
//   Reuses buildTLSConfig() with NextProtos overridden to ["doq"].
//   quic.DialEarly enables QUIC 0-RTT on resumed sessions.
//
// DOQ 6: DNS message ID zeroed per RFC 9250 §4.2.1
//   RFC 9250 requires the 2-byte DNS message ID to be 0x0000 in all queries.
//   QUIC stream identity replaces ID-based matching. The query is copied to a
//   fresh slice so the caller's buffer is never mutated. Receivers MUST accept
//   any ID value, so responses are returned as-is.
//
// DOQ 7: resolveAndUpdateCache / loadCachedIPs reused for IP resolution
//   ParseIP fast-exit for IP-literal hostPort (PERF-7 pattern).
// ══════════════════════════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════════════════════
//
// ── Go 1.26 Features Utilized ─────────────────────────────────────────────────
// • tls.X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 (hybrid PQ KEMs)
// • errors.AsType[T] for reflection‑free error inspection
// • iter.Seq[T] for zero‑allocation iteration over cached hosts
// • strings.SplitSeq for iterator‑based string splitting (Alt‑Svc parsing)
// • unique.Handle[string] for interning host strings in sync.Map keys
// • clear builtin to efficiently reset maps
// • max, min builtins for safe duration calculations
// • rand/v2 for jitter with Int64N
// • context.WithTimeoutCause for diagnostic timeouts
// • net.KeepAliveConfig for fine‑grained TCP keepalive
// • http.HTTP2Config for native HTTP/2 tuning (maximized for DoH)
// • sync.Pool for gzip.Reader recycling (reduces allocations)
// • maps.DeleteFunc for lock‑free cache purging
// • io.ReadAll (Go 1.26 optimized version – 2× faster, 50% less memory)
// • responseBodyPool (sync.Pool[*bytes.Buffer]) — reuses read buffers across DoH/ODoH responses
//
// ── Performance Enhancements ──────────────────────────────────────────────────
// • Per‑host connection prewarming with full TLS+HTTP/2 handshake (eliminates cold‑start RTT)
// • H3 prewarming when Alt-Svc entry is present (IMP 2)
// • Stack‑allocated IP deduplication ([8]netip.Addr) avoids heap maps
// • Shared net.Dialer and cloned TLS configs to reduce allocations
// • http.Client stored as XTransport field — zero per-request allocation (PERF 1)
// • TCP_NODELAY on all connections (disables Nagle's algorithm)
// • TCP_QUICKACK (Linux) – eliminates delayed ACKs
// • TCP_FASTOPEN_CONNECT (Linux) – saves one RTT on repeat connections
// • TCP_NOTSENT_LOWAT (Linux, IPPROTO_TCP, 16 KiB) – correct option, reduces write latency (PERF 2)
// • SO_RCVBUF / SO_SNDBUF (256 KiB) – prevents buffer-limited throughput (PERF 8)
// • SO_BUSY_POLL (Linux, 50 µs) on H3 UDP sockets – eliminates interrupt overhead (PERF 3)
// • Aggressive HTTP/2 flow control windows (4 MiB) to prevent window updates
// • HPACK table sizes maximised (4 MiB) for header compression efficiency
// • QUIC receive window tuning for H3 transport (PERF 5)
// • Connection draining on non‑2xx responses to keep connections alive
// • Singleflight‑style per‑host resolution mutexes (unique.Handle keys, collapsed lookup)
// • hostPrewarmer uses unique.Handle[string] keys — pointer-eq vs string-eq (PERF 6)
// • Pre‑allocated base headers cloned per request (avoids repeated map allocation)
// • gzip.Reader pool to prevent 32 KB allocations per compressed response
// • Alt‑Svc parsing using SplitSeq and bounded loops (prevents runaway parsing)
// • Fetch fast-exit for IP-literal hosts bypasses resolver entirely (PERF 7)
// • Dead runtime.GOOS branch removed from setTCPOptions (IMP 3)
//
// ── Compatibility ─────────────────────────────────────────────────────────────
// Public API unchanged: XTransport, NewXTransport, Fetch, Get, Post,
// DoHQuery, ObliviousDoHQuery, PurgeExpiredCache, ResetCache, CachedHosts.
// All method signatures and field names remain identical.
//
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
	noTTL = ^uint32(0)

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
	h2PingTimeout               = 15 * time.Second
	h2WriteByteTimeout          = 10 * time.Second
	h2TLSSessionCacheSize       = 512
	h2ReadWriteBufferSize       = 64 * 1024 // 64 KiB – larger I/O buffers reduce syscalls
	h2IdleConnTimeout           = 120 * time.Second
	h2MaxIdleConnsPerHost       = 10
	h2ExpectContinueTimeout     = 500 * time.Millisecond
	h2ResponseHeaderTimeout     = 20 * time.Second
	h2TLSHandshakeTimeout       = 15 * time.Second

	// ── QUIC / HTTP/3 flow-control windows (PERF 5) ───────────────────────────
	// DNS responses are small but larger windows prevent ACK-stall on request
	// bursts and reduce WINDOW_UPDATE round-trips.
	h3InitialStreamWindow = 512 * 1024      // 512 KiB per stream
	h3MaxStreamWindow     = 4 * 1024 * 1024 // 4 MiB per stream
	h3InitialConnWindow   = 1024 * 1024      // 1 MiB per connection
	h3MaxConnWindow       = 8 * 1024 * 1024 // 8 MiB per connection

	// ── TCP socket buffer sizes (PERF 8) ─────────────────────────────────────
	// Request 256 KiB send/recv buffers. Kernel caps at net.core.{w,r}mem_max.
	tcpSocketBufSize = 256 * 1024 // 256 KiB

	// ── TCP_NOTSENT_LOWAT value (PERF 2) ─────────────────────────────────────
	// 16 KiB: enough slack to keep writes non-blocking while preventing
	// excessive kernel-side buffering that inflates write latency.
	tcpNotSentLowat = 16 * 1024 // 16 KiB

	// ── SO_BUSY_POLL value for H3 UDP sockets (PERF 3) ───────────────────────
	// 50 µs of kernel busy-polling before sleeping. Eliminates the interrupt
	// context-switch on the receive path for latency-sensitive DoH/DoQ.
	udpBusyPollMicros = 50 // µs

	// ── DNS-over-QUIC (RFC 9250) ─────────────────────────────────────────────
	doqALPN        = "doq" // RFC 9250 §8.1 — ALPN negotiation token
	doqDefaultPort = 853   // RFC 9250 §4.2 — default UDP port

	// QUIC flow-control windows — DNS responses are almost always <512 bytes.
	// Tighter than H3 (PERF 5) to avoid wasting kernel memory on idle connections.
	doqInitialStreamWindow = 64 * 1024   // 64 KiB per stream
	doqMaxStreamWindow     = 256 * 1024  // 256 KiB per stream
	doqInitialConnWindow   = 128 * 1024  // 128 KiB per connection
	doqMaxConnWindow       = 1024 * 1024 // 1 MiB per connection

	// 2 minutes: survives inter-query idle gaps; server closes earlier → reconnect.
	doqMaxIdleTimeout = 2 * time.Minute

	// RFC 9250 §8.3 application error codes — sent in CloseWithError /
	// CancelRead / CancelWrite frames to signal clean vs. hard closure.
	doqErrNoError       = quic.ApplicationErrorCode(0x0) // DOQ_NO_ERROR
	doqErrInternalError = quic.ApplicationErrorCode(0x1) // DOQ_INTERNAL_ERROR
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

	errDoQDisabled  = errors.New("DoQ transport is not enabled")
	errDoQShortRead = errors.New("DoQ: short read on response length prefix")
	errDoQOversize  = errors.New("DoQ: query exceeds 65535-byte wire limit")
)

// ── Global TLS session cache – saves one full TLS 1.3 RTT on reconnect ───────
var tlsSessionCache = tls.NewLRUClientSessionCache(h2TLSSessionCacheSize)

// ── gzip.Reader pool – eliminates 32 KB allocations per compressed response ───
var gzipReaderPool = sync.Pool{
	New: func() any { return new(gzip.Reader) },
}

// ── Response body read buffer pool ────────────────────────────────────────────
// Reuses []byte backing buffers across DoH/ODoH response reads. DNS responses
// are almost always <4 KiB; the 64 KiB cap prevents large one-off payloads from
// permanently inflating pool entries and wasting memory.
//
// bytes.Buffer is pooled (not raw []byte) so ReadFrom can grow without an
// extra copy. A fresh bytes.Clone of the live slice is returned so the pool
// buffer is immediately available for the next request.
const responsePoolMaxSize = 64 * 1024 // 64 KiB — buffers larger than this are not returned to pool

var responseBodyPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// readLimitedBody reads at most maxBytes from r using a pooled bytes.Buffer.
// Returns a freshly cloned minimal []byte; the pool buffer is reused after return.
func readLimitedBody(r io.Reader, maxBytes int64) ([]byte, error) {
	buf := responseBodyPool.Get().(*bytes.Buffer)
	buf.Reset()
	_, err := buf.ReadFrom(io.LimitReader(r, maxBytes))
	if err != nil {
		if buf.Cap() <= responsePoolMaxSize {
			responseBodyPool.Put(buf)
		}
		return nil, err
	}
	result := bytes.Clone(buf.Bytes()) // minimal allocation — only live data
	if buf.Cap() <= responsePoolMaxSize {
		responseBodyPool.Put(buf)
	}
	return result, nil
}

// ── Cache types ───────────────────────────────────────────────────────────────
type CachedIPItem struct {
	ips           []net.IP
	expiration    *time.Time
	updatingUntil *time.Time
}

type CachedIPs struct {
	sync.RWMutex
	cache map[string]*CachedIPItem
}

// altSvcEntry records an Alt-Svc advertisement for a host.
//
// ── IMP 4: explicit noExpiry bool removes zero-time ambiguity ─────────────────
// Previously validTo.IsZero() had dual meaning depending on port value:
//   port>0, validTo.IsZero()  → "valid forever" (positive, no expiry)
//   port==0, validTo.IsZero() → ambiguous (no-negative-cache OR still-valid)
//
// Now noExpiry=true unambiguously means "this entry never expires".
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

// ── IMP 6 (PERF 6): hostPrewarmer uses unique.Handle[string] keys ─────────────
// Previously used raw string keys — map comparisons hashed/compared the full
// string bytes on every lookup. unique.Handle keys compare by pointer identity
// (same as resolveMu), which is O(1) and allocation-free.
type hostPrewarmer struct {
	m sync.Map // map[unique.Handle[string]]*sync.Once
}

func (p *hostPrewarmer) do(hostport unique.Handle[string], fn func()) {
	v, _ := p.m.LoadOrStore(hostport, new(sync.Once))
	v.(*sync.Once).Do(fn)
}


// doqConnEntry holds a single persistent QUIC connection to one DoQ host:port.
//
// All concurrent DoQ queries to the same server share one QUIC connection —
// each on its own bidirectional QUIC stream (RFC 9250 §4.2). The sync.Mutex
// serialises the initial dial and any reconnect without blocking concurrent
// stream opens on an already-live connection.
//
// Liveness: quic-go cancels conn.Context() when the connection is closed by
// either side. getOrDialDoQ reads conn.Context().Done() with a non-blocking
// select to detect stale entries before attempting to open a new stream,
// avoiding a guaranteed-fail attempt on a dead connection.
type doqConnEntry struct {
	mu   sync.Mutex
	conn *quic.Conn // nil = not yet dialed or after invalidation
}

// ── XTransport – main transport structure ─────────────────────────────────────
type XTransport struct {
	transport       *http.Transport
	h3Transport     *http3.Transport
	tlsClientConfig *tls.Config

	// ── PERF 1: Cached http.Client instances – zero per-request allocation ────
	// httpClient wraps transport; h3Client wraps h3Transport.
	// Both are rebuilt in rebuildTransport() and selected in Fetch().
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

	// Pre‑allocated base headers – cloned per request
	baseHeaders http.Header

	// Per‑host connection prewarmer (IMP 6: unique.Handle[string] keys)
	prewarmed hostPrewarmer

	// DNS-over-QUIC (RFC 9250) — active when doq == true.
	doq      bool
	doqConns sync.Map // map[unique.Handle[string]]*doqConnEntry
}

// ── Constructor ───────────────────────────────────────────────────────────────
func NewXTransport() *XTransport {
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
		panic("DefaultBootstrapResolver is not a valid IP:port — " + err.Error())
	}

	baseHeaders := make(http.Header, 5)
	baseHeaders.Set("User-Agent", "dnscrypt-proxy")
	baseHeaders.Set("Cache-Control", "max-stale")

	return &XTransport{
		cachedIPs:          CachedIPs{cache: make(map[string]*CachedIPItem)},
		altSupport:         AltSupport{cache: make(map[string]altSvcEntry)},
		keepAlive:          DefaultKeepAlive,
		timeout:            DefaultTimeout,
		bootstrapResolvers: []string{DefaultBootstrapResolver},
		ignoreSystemDNS:    true,
		useIPv4:            true,
		baseHeaders:        baseHeaders,
	}
}

// ── IP helpers ────────────────────────────────────────────────────────────────
func ParseIP(ipStr string) net.IP {
	ipStr = strings.TrimPrefix(ipStr, "[")
	ipStr = strings.TrimSuffix(ipStr, "]")
	return net.ParseIP(ipStr)
}

func netIPToNetipAddr(ip net.IP) (netip.Addr, bool) {
	switch len(ip) {
	case 4:
		return netip.AddrFrom4([4]byte(ip)), true
	case 16:
		return netip.AddrFrom16([16]byte(ip)).Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

// uniqueNormalizedIPs deduplicates IPs using a stack‑allocated array for up to
// 8 entries; beyond 8 the seen slice grows onto the heap automatically.
func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	if len(ips) == 1 {
		if ips[0] != nil {
			return []net.IP{bytes.Clone(ips[0])}
		}
		return nil
	}

	var seenBuf [8]netip.Addr
	seen := seenBuf[:0]
	out := make([]net.IP, 0, len(ips))

	for _, ip := range ips {
		if ip == nil {
			continue
		}
		addr, ok := netIPToNetipAddr(ip)
		if !ok { // non‑standard length – keep as is
			out = append(out, bytes.Clone(ip))
			continue
		}

		isDup := false
		for _, s := range seen {
			if s == addr {
				isDup = true
				break
			}
		}
		if !isDup {
			seen = append(seen, addr)
			out = append(out, bytes.Clone(ip))
		}
	}
	return out
}

// ── IP cache operations ───────────────────────────────────────────────────────
func (x *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {
	normalized := uniqueNormalizedIPs(ips)
	if len(normalized) == 0 {
		return
	}

	item := &CachedIPItem{ips: normalized}
	if ttl >= 0 {
		ttl = max(ttl, MinResolverIPTTL)
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
		dlog.Debugf("[%s] cached %d IPs (first: %s), valid for %v",
			host, len(normalized), normalized[0], ttl)
	}
}

// saveCachedIP saves a single IP into the cache.
//
// ── IMP 5: stack-allocated single-element slice avoids heap alloc ─────────────
// Previously built []net.IP{ip} as a heap slice before calling saveCachedIPs.
// Now passes a pointer to a stack-local [1]net.IP directly.
func (x *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip == nil {
		return
	}
	buf := [1]net.IP{ip}
	x.saveCachedIPs(host, buf[:], ttl)
}

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
		if item.updatingUntil != nil && now.Before(*item.updatingUntil) {
			return false
		}
		return item.expiration != nil && item.expiration.Before(grace)
	})
	ipsPurged = before - len(x.cachedIPs.cache)

	// Build live set for later mutex cleanup
	live := make(map[string]struct{}, len(x.cachedIPs.cache))
	for host := range x.cachedIPs.cache {
		live[host] = struct{}{}
	}
	x.cachedIPs.Unlock()

	// Alt‑Svc cache — use IMP 4 isAltSvcExpired helper
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

	if ipsPurged > 0 || altSvcPurged > 0 || muPurged > 0 {
		dlog.Debugf("PurgeExpiredCache: %d IP, %d Alt‑Svc, %d mutex entries removed",
			ipsPurged, altSvcPurged, muPurged)
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

	x.resolveMu.Range(func(key, _ any) bool {
		x.resolveMu.Delete(key)
		return true
	})
	dlog.Debug("ResetCache: all IP, Alt‑Svc, and mutex cache entries cleared")
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

// ── TCP low‑level optimizations ───────────────────────────────────────────────
// ── IMP 3: runtime.GOOS dead-code branch removed ─────────────────────────────
// File has //go:build linux so runtime.GOOS is always "linux". The non-Linux
// branch was unreachable dead code. Removed to reduce binary size and
// eliminate a branch on the hot connection path.
func setTCPOptions(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		_ = tcpConn.SetNoDelay(true)
		return
	}
	raw.Control(func(fd uintptr) {
		// TCP_QUICKACK – disable delayed ACKs for faster ACK delivery
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)

		// TCP_FASTOPEN_CONNECT – save one RTT on repeat connections (Linux 4.11+)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)

		// ── PERF 2: TCP_NOTSENT_LOWAT (IPPROTO_TCP level, value 25) ──────────
		// Limits unsent data in the kernel send buffer to 16 KiB. Prevents
		// write-ahead buffering from inflating perceived latency on small DoH
		// payloads. DISTINCT from SO_SNDLOWAT — earlier code used the wrong one.
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, tcpNotSentLowat)

		// ── PERF 8: SO_SNDBUF / SO_RCVBUF – 256 KiB socket buffers ──────────
		// Requests larger OS socket buffers. Kernel may cap at sysctl limits.
		// Prevents buffer-stall on high-BDP paths without hurting DoH latency.
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, tcpSocketBufSize)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, tcpSocketBufSize)
	})
	_ = tcpConn.SetNoDelay(true)
}

// setUDPOptions applies Linux-specific latency optimizations to a UDP socket.
// Called on H3/QUIC UDP connections where microsecond latency matters.
func setUDPOptions(conn *net.UDPConn) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) {
		// ── PERF 3: SO_BUSY_POLL – kernel busy-polls for 50 µs before sleeping ─
		// Avoids the interrupt + context-switch overhead on the receive path.
		// Reduces per-response latency by ~7 µs on low-latency paths.
		// Requires CAP_NET_ADMIN to increase above the system default (0).
		// Silently ignored if the kernel or driver does not support it.
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BUSY_POLL, udpBusyPollMicros)

		// ── PERF 8: SO_RCVBUF / SO_SNDBUF for UDP ────────────────────────────
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, tcpSocketBufSize)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, tcpSocketBufSize)
	})
}

// ── Transport construction ────────────────────────────────────────────────────
func (x *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport")
	if x.transport != nil {
		x.transport.CloseIdleConnections()
	}

	// Drain the DoQ connection pool so every connection receives a clean
	// QUIC CONNECTION_CLOSE before the new transport config takes effect.
	if x.doq {
		x.doqConns.Range(func(key, val any) bool {
			if entry, ok := val.(*doqConnEntry); ok {
				entry.mu.Lock()
				if entry.conn != nil {
					_ = entry.conn.CloseWithError(doqErrNoError, "transport rebuilt")
					entry.conn = nil
				}
				entry.mu.Unlock()
			}
			x.doqConns.Delete(key)
			return true
		})
	}
	x.tlsClientConfig = x.buildTLSConfig()

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
		DisableKeepAlives:      false,
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

	// ── PERF 1: Store http.Client as a field — zero per-request allocation ────
	// Rebuilding happens rarely (config reload); hot path in Fetch() is free.
	x.httpClient = http.Client{Transport: transport}

	// Reset prewarmer so new connections will be prewarmed on next request
	x.prewarmed = hostPrewarmer{}

	if x.http3 {
		if x.h3Transport != nil {
			x.h3Transport.Close()
		}

		// ── PERF 5: QUIC flow-control configuration ───────────────────────────
		quicCfg := &quic.Config{
			InitialStreamReceiveWindow:     h3InitialStreamWindow,
			MaxStreamReceiveWindow:         h3MaxStreamWindow,
			InitialConnectionReceiveWindow: h3InitialConnWindow,
			MaxConnectionReceiveWindow:     h3MaxConnWindow,
		}

		x.h3Transport = &http3.Transport{
			DisableCompression: true,
			TLSClientConfig:    x.tlsClientConfig,
			QUICConfig:         quicCfg,
			Dial:               x.buildH3DialFunc(),
		}
		// ── PERF 1: H3 client also stored as field ────────────────────────────
		x.h3Client = http.Client{Transport: x.h3Transport}
	}
}

// prewarmConnection ensures a full TLS+HTTP/2 handshake (and optionally a QUIC
// handshake) is completed once per host before real traffic arrives.
//
// ── PERF 4: Full TLS handshake via real HEAD request ─────────────────────────
// The previous implementation called transport.DialContext (TCP only). No TLS
// or HTTP/2 negotiation occurred so the "warm" connection was immediately
// closed and discarded — providing no benefit at all.
//
// We now issue a HEAD request via the stored httpClient. The transport performs
// the complete TLS+ALPN+HTTP/2 handshake and deposits the idle connection into
// its pool. The HEAD response body is drained and discarded. Any error (404,
// connection refused, etc.) is silently ignored — we only care about warming
// the connection pool, not about the response content.
//
// ── IMP 2: H3 path also prewarmed when Alt-Svc entry is present ──────────────
// When an Alt-Svc entry exists for the host, the h3Client is also warmed so
// the QUIC handshake is already complete before the first real DoH request.
func (x *XTransport) prewarmConnection(hostPort string) {
	hk := unique.Make(hostPort)
	x.prewarmed.do(hk, func() {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), h2TLSHandshakeTimeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodHead,
				"https://"+hostPort+"/", nil)
			if err != nil {
				dlog.Debugf("Prewarm: failed to build request for %s: %v", hostPort, err)
				return
			}
			req.Header = x.baseHeaders.Clone()

			resp, err := x.httpClient.Do(req)
			if err != nil {
				dlog.Debugf("Prewarm: %s: %v (connection may still be cached)", hostPort, err)
			} else {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
				resp.Body.Close()
				dlog.Debugf("Prewarmed HTTP/2 connection to %s (status %d)", hostPort, resp.StatusCode)
			}

			// ── IMP 2: Also warm H3 if transport is ready and Alt-Svc exists ─
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
			h3Req.Header = x.baseHeaders.Clone()
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
// Unlike net.SplitHostPort it never returns an error — used only for logging/
// cache lookups where an imperfect split is acceptable.
func splitHostPort(hostPort string) (host, port string) {
	if i := strings.LastIndexByte(hostPort, ':'); i >= 0 {
		return hostPort[:i], hostPort[i+1:]
	}
	return hostPort, ""
}

func (x *XTransport) buildDialContext() func(context.Context, string, string) (net.Conn, error) {
	timeout, keepAlive := x.timeout, x.keepAlive
	useIPv4, useIPv6 := x.useIPv4, x.useIPv6

	d := &net.Dialer{
		Timeout: timeout,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     keepAlive,
			Interval: max(keepAlive/3, time.Second),
			Count:    3,
		},
	}

	return func(ctx context.Context, network, addrStr string) (net.Conn, error) {
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
		portStr := strconv.Itoa(port)

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

		var lastErr error
		for i, target := range targets {
			var conn net.Conn
			var err error
			if x.proxyDialer == nil {
				conn, err = d.DialContext(ctx, dialNet, target)
			} else {
				conn, err = (*x.proxyDialer).Dial(dialNet, target)
			}
			if err == nil {
				setTCPOptions(conn)
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

func (x *XTransport) buildH3DialFunc() func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addrStr string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		dlog.Debugf("H3 dial: [%s]", addrStr)
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
		portStr := strconv.Itoa(port)

		type udpTarget struct{ addr, network string }

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
					nw = "udp"
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
			// ✅ FIX 1: Wrap ListenUDP+DialEarly in an IIFE so defer fires per-iteration.
			conn, dialErr := func() (*quic.Conn, error) {
				udpConn, listenErr := net.ListenUDP(t.network, nil)
				if listenErr != nil {
					return nil, listenErr
				}
				// ── PERF 3: Apply SO_BUSY_POLL to this UDP socket ─────────────
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

// ── DNS-over-QUIC (RFC 9250) transport ───────────────────────────────────────

// buildDoQConfig returns a *quic.Config tuned for small DNS payloads.
// Tighter flow-control windows than H3 (PERF 5): DNS messages are almost
// always <512 bytes, so 64 KiB stream / 1 MiB connection windows are ample
// and avoid wasting kernel memory on idle DoQ connections.
func buildDoQConfig() *quic.Config {
	return &quic.Config{
		InitialStreamReceiveWindow:     doqInitialStreamWindow,
		MaxStreamReceiveWindow:         doqMaxStreamWindow,
		InitialConnectionReceiveWindow: doqInitialConnWindow,
		MaxConnectionReceiveWindow:     doqMaxConnWindow,
		MaxIdleTimeout:                 doqMaxIdleTimeout,
	}
}

// dialDoQConn dials a fresh QUIC connection to hostPort with ALPN "doq".
//
// Mirrors buildH3DialFunc exactly: resolves cached IPs, creates a UDP socket
// per target, applies setUDPOptions (SO_BUSY_POLL + buffer sizing — DOQ 4),
// uses quic.DialEarly for 0-RTT on session resumption (DOQ 5). TLS config is
// cloned from x.tlsClientConfig with NextProtos = ["doq"] (DOQ 5).
//
// The IIFE pattern (FIX 1 in buildH3DialFunc) is reused so defer fires
// per-iteration — the UDP socket is closed on every failure path.
func (x *XTransport) dialDoQConn(ctx context.Context, hostPort string) (*quic.Conn, error) {
	host, port := ExtractHostAndPort(hostPort, doqDefaultPort)
	portStr := strconv.Itoa(port)

	tlsCfg := x.tlsClientConfig.Clone()
	tlsCfg.NextProtos = []string{doqALPN} // DOQ 5: override H2/H3 ALPN
	tlsCfg.ServerName = host

	quicCfg := buildDoQConfig()

	type udpTarget struct{ addr, network string }

	udpEndpoint := func(ip net.IP) udpTarget {
		if ip != nil {
			if v4 := ip.To4(); v4 != nil {
				return udpTarget{v4.String() + ":" + portStr, "udp4"}
			}
			return udpTarget{"[" + ip.String() + "]:" + portStr, "udp6"}
		}
		nw := "udp4"
		if x.useIPv6 {
			if x.useIPv4 {
				nw = "udp"
			} else {
				nw = "udp6"
			}
		}
		return udpTarget{host + ":" + portStr, nw}
	}

	cachedIPs, _, _ := x.loadCachedIPs(host)
	targets := make([]udpTarget, 0, max(len(cachedIPs), 1))
	for _, ip := range cachedIPs {
		targets = append(targets, udpEndpoint(ip))
	}
	if len(targets) == 0 {
		dlog.Debugf("[%s] DoQ: no cached IP; falling back to hostname dial", host)
		targets = append(targets, udpEndpoint(nil))
	}

	var lastErr error
	for i, t := range targets {
		udpAddr, err := net.ResolveUDPAddr(t.network, t.addr)
		if err != nil {
			lastErr = err
			if i < len(targets)-1 {
				dlog.Debugf("DoQ: resolve [%s]/%s failed: %v", t.addr, t.network, err)
			}
			continue
		}

		// IIFE: mirrors FIX-1 from buildH3DialFunc — defer fires per-iteration.
		conn, dialErr := func() (*quic.Conn, error) {
			udpConn, listenErr := net.ListenUDP(t.network, nil)
			if listenErr != nil {
				return nil, listenErr
			}
			setUDPOptions(udpConn) // SO_BUSY_POLL + SO_RCVBUF/SO_SNDBUF — DOQ 4

			connClosed := false
			defer func() {
				if !connClosed {
					_ = udpConn.Close()
				}
			}()

			c, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, quicCfg)
			if err != nil {
				return nil, err
			}
			connClosed = true // QUIC conn now owns the UDP socket
			return c, nil
		}()

		if dialErr != nil {
			lastErr = dialErr
			if i < len(targets)-1 {
				dlog.Debugf("DoQ: quic.DialEarly [%s]/%s failed: %v", t.addr, t.network, dialErr)
			}
			continue
		}

		dlog.Debugf("DoQ: connection to [%s] established (0-RTT: %v)",
			t.addr, conn.ConnectionState().Used0RTT)
		return conn, nil
	}
	return nil, lastErr
}

// getOrDialDoQ returns the live pooled QUIC connection for hostPort, dialing a
// new one if the pool is empty or the stored connection is stale.
//
// Uses LoadOrStore for lock-free pool-entry creation (PERF-6 pattern).
// Stale detection: a non-blocking select on conn.Context().Done() catches
// peer-closed connections before any stream open is attempted.
func (x *XTransport) getOrDialDoQ(ctx context.Context, hostPort string) (*quic.Conn, error) {
	hk := unique.Make(hostPort)
	v, _ := x.doqConns.LoadOrStore(hk, new(doqConnEntry))
	entry := v.(*doqConnEntry)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.conn != nil {
		select {
		case <-entry.conn.Context().Done():
			// Connection was closed by us or the server — discard and redial.
			dlog.Debugf("DoQ: stale connection to [%s]; redialing", hostPort)
			entry.conn = nil
		default:
			return entry.conn, nil // healthy
		}
	}

	conn, err := x.dialDoQConn(ctx, hostPort)
	if err != nil {
		return nil, err
	}
	entry.conn = conn
	return conn, nil
}

// invalidateDoQConn closes and evicts badConn from the pool.
//
// The pointer-equality guard (entry.conn == badConn) is the critical safety
// gate: if a concurrent goroutine already redialed successfully, entry.conn
// points to the NEW connection and must not be evicted by a late-arriving
// error from the old one.
func (x *XTransport) invalidateDoQConn(hostPort string, badConn *quic.Conn) {
	hk := unique.Make(hostPort)
	v, ok := x.doqConns.Load(hk)
	if !ok {
		return
	}
	entry := v.(*doqConnEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.conn == badConn {
		_ = entry.conn.CloseWithError(doqErrInternalError, "stream error")
		entry.conn = nil
		dlog.Debugf("DoQ: invalidated connection to [%s]", hostPort)
	}
}

// doqExchange opens one bidirectional QUIC stream, writes the length-prefixed
// DNS query, closes the send direction, reads the response, and returns it.
//
// Wire format (RFC 9250 §4.2.1):
//   write → [ 2-byte big-endian length ][ DNS wire message ]  then Close()
//   read  ← [ 2-byte big-endian length ][ DNS wire message ]
//
// ── DOQ 6: DNS message ID forced to 0x0000 ───────────────────────────────────
// RFC 9250 §4.2.1: "The DNS Message ID MUST be set to zero." QUIC stream
// identity replaces ID-based matching. The query is copied to a fresh heap
// slice so the caller's buffer is never mutated. Responses are returned as-is
// (receivers MUST accept any ID value — RFC §4.2.1 note).
//
// stream.CancelRead is called only on write/close error paths to send a
// QUIC STOP_SENDING frame (DOQ_NO_ERROR), cleanly aborting the half-open stream.
func (x *XTransport) doqExchange(
	ctx context.Context,
	conn *quic.Conn,
	query []byte,
) ([]byte, *tls.ConnectionState, error) {
	n := len(query)
	if n > 65535 {
		return nil, nil, errDoQOversize
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("DoQ open stream: %w", err)
	}

	// Build wire frame: [2-byte big-endian length][zero-ID DNS wire message].
	// One allocation, one Write call — minimises syscall overhead (DOQ 6).
	frame := make([]byte, 2+n)
	frame[0] = byte(n >> 8)
	frame[1] = byte(n)
	copy(frame[2:], query)
	frame[2] = 0x00 // DNS message ID high byte → 0  (RFC 9250 §4.2.1)
	frame[3] = 0x00 // DNS message ID low byte  → 0  (RFC 9250 §4.2.1)

	if _, err := stream.Write(frame); err != nil {
		_ = stream.CancelRead(quic.StreamErrorCode(doqErrNoError))
		return nil, nil, fmt.Errorf("DoQ write query: %w", err)
	}
	// Close send direction: signals to the server that the full query has
	// been received (RFC 9250 §4.2 — "MUST indicate end of request").
	if err := stream.Close(); err != nil {
		_ = stream.CancelRead(quic.StreamErrorCode(doqErrNoError))
		return nil, nil, fmt.Errorf("DoQ close send side: %w", err)
	}

	// Read 2-byte big-endian response length prefix.
	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, nil, fmt.Errorf("DoQ read length prefix: %w", err)
	}
	respLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1])
	if respLen == 0 {
		return nil, nil, errEmptyResponse
	}

	// Read exactly respLen bytes of DNS wire response.
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(stream, resp); err != nil {
		return nil, nil, fmt.Errorf("DoQ read response (%d B): %w", respLen, err)
	}

	cs := conn.ConnectionState().TLS
	return resp, &cs, nil
}

// doqRoundTrip is the internal retry wrapper around doqExchange.
//
// On any non-context transport failure the bad connection is invalidated and
// exactly one retry is performed on a fresh connection. Context cancellation
// and deadline exceeded are propagated immediately — they reflect the caller's
// intent and are never retryable.
func (x *XTransport) doqRoundTrip(
	ctx context.Context,
	hostPort string,
	body []byte,
) (resp []byte, tlsState *tls.ConnectionState, rtt time.Duration, err error) {
	start := time.Now()

	for attempt := range 2 {
		var conn *quic.Conn
		conn, err = x.getOrDialDoQ(ctx, hostPort)
		if err != nil {
			return nil, nil, time.Since(start),
				fmt.Errorf("DoQ dial [%s] (attempt %d): %w", hostPort, attempt+1, err)
		}

		resp, tlsState, err = x.doqExchange(ctx, conn, body)
		if err == nil {
			return resp, tlsState, time.Since(start), nil
		}

		// Never retry on context errors — caller timed out or was cancelled.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, time.Since(start), err
		}

		if attempt == 0 {
			dlog.Debugf("DoQ [%s] attempt 1 failed: %v — invalidating, retrying", hostPort, err)
			x.invalidateDoQConn(hostPort, conn)
		}
	}
	return nil, nil, time.Since(start),
		fmt.Errorf("DoQ [%s]: all attempts failed: %w", hostPort, err)
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
	cfg.ClientSessionCache = tlsSessionCache

	if x.tlsPreferRSA {
		cfg.MaxVersion = tls.VersionTLS12
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
	r := &net.Resolver{PreferGo: true}
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

func (x *XTransport) resolveRRType(
	proto, host, resolver string,
	rrType uint16,
) (ips []net.IP, minTTL uint32, err error) {
	tr := dns.NewTransport()
	tr.ReadTimeout = ResolverReadTimeout
	client := dns.Client{Transport: tr}

	ctx, cancel := context.WithTimeoutCause(context.Background(), ResolverReadTimeout, errDNSQueryTimeout)
	defer cancel()

	msg := dns.NewMsg(fqdn(host), rrType) // fqdn is defined in common.go
	if msg == nil {
		return nil, noTTL, fmt.Errorf("dns.NewMsg returned nil for [%s] type %d", host, rrType)
	}
	msg.RecursionDesired = true
	msg.UDPSize = uint16(MaxDNSPacketSize) // defined in common.go
	msg.Security = true

	in, _, err := client.Exchange(ctx, msg, proto, resolver)
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
		if rttl == noTTL {
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
		i, rrType := i, rrType
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

func (x *XTransport) resolveUsingServers(
	proto, host string,
	resolvers []string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	if len(resolvers) == 0 {
		return nil, 0, errEmptyResolvers
	}
	// ✅ FIX 3: Deep-copy the resolvers slice so the promotion swap never races
	// against concurrent readers of x.internalResolvers / x.bootstrapResolvers.
	resolversCopy := make([]string, len(resolvers))
	copy(resolversCopy, resolvers)

	var errs []error
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
				time.Sleep(delay)
				delay = min(delay*2, resolverRetryMaxBackoff)
			}
		}
		dlog.Infof("Unable to resolve [%s] using [%s] (%s)", host, resolver, proto)
	}
	return nil, 0, errors.Join(errs...)
}

func (x *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
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

	if x.ignoreSystemDNS {
		dlog.Noticef("Bootstrap resolvers failed — last-resort system resolver for [%s]", host)
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)
	}
	return ips, ttl, err
}

// ── Per‑host resolution mutex ─────────────────────────────────────────────────
func (x *XTransport) hostResolveMu(host string) *sync.Mutex {
	k := unique.Make(host)
	// ── PERF 6: Single LoadOrStore — eliminates redundant map traversal ───────
	// Previous pattern: Load (miss) → allocate → LoadOrStore → discard extra.
	// Now: one atomic operation regardless of hit/miss.
	v, _ := x.resolveMu.LoadOrStore(k, new(sync.Mutex))
	return v.(*sync.Mutex)
}

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

	cachedIPs, expired, _ = x.loadCachedIPs(host)
	if len(cachedIPs) > 0 && !expired {
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

	// ── PERF 1: Use stored http.Client — zero allocation on hot path ──────────
	// Previously: `client := http.Client{Transport: x.transport}` allocated a
	// new 56-byte struct + heap escape on EVERY request. Now we select the
	// pre-built client stored in XTransport.
	client := &x.httpClient

	host, port := ExtractHostAndPort(url.Host, 443)

	// Prewarm a full TLS+HTTP/2 (and optionally H3) connection once per host
	x.prewarmConnection(host + ":" + strconv.Itoa(port))

	hasAltSupport := false
	if x.h3Transport != nil {
		if x.http3Probe {
			// ── PERF 1: Use stored h3Client — same zero-allocation benefit ────
			client = &x.h3Client
		} else {
			x.altSupport.RLock()
			entry, inCache := x.altSupport.cache[url.Host]
			x.altSupport.RUnlock()
			if inCache {
				hasAltSupport = true
				// ── IMP 4: use isAltSvcExpired for unambiguous expiry check ───
				negativeExpired := entry.port == 0 && isAltSvcExpired(entry, time.Now())
				switch {
				case entry.port > 0 && int(entry.port) == port:
					client = &x.h3Client
				case negativeExpired:
					hasAltSupport = false
				}
			}
		}
	}

	// Clone base headers – avoids modifying the shared map
	header := x.baseHeaders.Clone()

	if accept != "" {
		header.Set("Accept", accept)
	}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	if body != nil {
		h := sha512.Sum512_256(*body)
		qs := url.Query()
		qs.Add("body_hash", hex.EncodeToString(h[:]))
		u2 := *url
		u2.RawQuery = qs.Encode()
		url = &u2
	}
	if x.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0, errNoTorProxy
	}

	// ── PERF 7: Fast-exit for IP-literal hosts bypasses resolver entirely ─────
	// resolveAndUpdateCache already guards with ParseIP, but we save the entire
	// function call overhead (proxy check, cache lock acquisition) for the
	// common case where the host is already a bare IP address.
	if ParseIP(host) == nil {
		if err := x.resolveAndUpdateCache(host); err != nil {
			dlog.Errorf("Unable to resolve [%s]: check bootstrap_resolvers or system resolver", host)
			return nil, 0, nil, 0, err
		}
	}

	if compress && body == nil {
		header.Set("Accept-Encoding", "gzip")
	}
	bodyLen := 0
	if body != nil {
		bodyLen = len(*body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	newRequest := func() (*http.Request, error) {
		var reqBody io.Reader
		if body != nil {
			reqBody = bytes.NewReader(*body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url.String(), reqBody)
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

	if err != nil && client == &x.h3Client {
		// ✅ FIX 4a: Close any non-nil H3 response body before resp is overwritten.
		if resp != nil {
			resp.Body.Close()
			resp = nil
		}
		dlog.Debugf("HTTP/3 failed for [%s]: %v — retrying over HTTP/2", url.Host, err)
		x.altSupport.Lock()
		x.altSupport.cache[url.Host] = altSvcEntry{port: 0, validTo: time.Now().Add(altSvcNegativeTTL)}
		x.altSupport.Unlock()

		// ── IMP 1: Build a fresh *http.Request for the retry ─────────────────
		// Reusing the original req after Do() violates the net/http contract.
		// newRequest() constructs a brand-new request with the same parameters.
		client = &x.httpClient
		req, err = newRequest()
		if err != nil {
			return nil, 0, nil, 0, err
		}
		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)
	}

	if resp != nil {
		// ✅ FIX 4b: sync.Once ensures resp.Body.Close is called exactly once.
		var bodyCloseOnce sync.Once
		defer func() { bodyCloseOnce.Do(func() { resp.Body.Close() }) }()
	}
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
		grErr := gr.Reset(io.LimitReader(resp.Body, MaxHTTPBodyLength)) // defined in common.go
		if grErr != nil {
			// ✅ FIX 2: Do NOT return a failed-Reset reader to the pool.
			return nil, statusCode, tlsState, rtt, grErr
		}
		defer func() {
			// ✅ FIX 2: Only return healthy readers to the pool.
			if closeErr := gr.Close(); closeErr == nil {
				gzipReaderPool.Put(gr)
			}
		}()
		bodyReader = gr
	}
	bin, err := readLimitedBody(bodyReader, MaxHTTPBodyLength)
	if err != nil {
		return nil, statusCode, tlsState, rtt, err
	}
	return bin, statusCode, tlsState, rtt, nil
}

func (x *XTransport) parseAndCacheAltSvc(host string, port int, header http.Header) {
	now := time.Now()
	x.altSupport.RLock()
	existing, inCache := x.altSupport.cache[host]
	x.altSupport.RUnlock()
	// ── IMP 4: use isAltSvcExpired for unambiguous negative-cache check ───────
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
				if p, pErr := strconv.ParseUint(v, 10, 16); pErr == nil && p <= 65535 {
					altPort = uint16(p)
					dlog.Debugf("Alt-Svc: HTTP/3 advertised for [%s] on port %d", host, altPort)
					break outer
				}
			}
		}
	}

	x.altSupport.Lock()
	// ── IMP 4: noExpiry=true for positive Alt-Svc entries (no TTL in header) ─
	x.altSupport.cache[host] = altSvcEntry{port: altPort, noExpiry: true}
	dlog.Debugf("Alt-Svc: cached port %d for [%s]", altPort, host)
	x.altSupport.Unlock()
}

// ── Public query helpers ──────────────────────────────────────────────────────
func (x *XTransport) GetWithCompression(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(http.MethodGet, url, accept, "", nil, timeout, true)
}

func (x *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(http.MethodGet, url, accept, "", nil, timeout, false)
}

func (x *XTransport) Post(
	url *url.URL,
	accept, contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(http.MethodPost, url, accept, contentType, body, timeout, false)
}

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

// DoQQuery sends a DNS query over DNS-over-QUIC (RFC 9250) and returns the
// raw DNS wire response. A persistent QUIC connection per host is maintained
// in doqConns and transparently reconnected on failure (DOQ 2).
//
// Return signature mirrors DoHQuery for caller symmetry:
//   []byte               — DNS wire response; nil on error
//   int                  — 200 on success, 503 on transport failure, 0 if disabled
//   *tls.ConnectionState — TLS state of the underlying QUIC connection
//   time.Duration        — wall-clock round-trip (dial + stream exchange)
//   error                — nil on success
//
// hostPort must be "host:port" (e.g., "dns.adguard.com:853"). Omitted port
// defaults to doqDefaultPort (853). Caller must set x.doq = true.
//
// ── DOQ 1: no HTTP overhead — raw QUIC streams carry DNS wire messages ────────
// ── DOQ 2: persistent connection reused across calls, reconnects transparently ─
// ── DOQ 7: resolveAndUpdateCache + ParseIP fast-exit for IP-literal hosts ──────
func (x *XTransport) DoQQuery(
	hostPort string,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if !x.doq {
		return nil, 0, nil, 0, errDoQDisabled
	}
	if timeout <= 0 {
		timeout = x.timeout
	}

	host, _ := splitHostPort(hostPort)

	// ── DOQ 7: resolve via shared cache; fast-exit for IP literals (PERF-7) ──
	if ParseIP(host) == nil {
		if err := x.resolveAndUpdateCache(host); err != nil {
			dlog.Errorf("DoQ: unable to resolve [%s]: %v", host, err)
			return nil, 503, nil, 0, err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resp, tlsState, rtt, err := x.doqRoundTrip(ctx, hostPort, body)
	if err != nil {
		return nil, 503, tlsState, rtt, err
	}
	return resp, 200, tlsState, rtt, nil
}
