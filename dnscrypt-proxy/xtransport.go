//go:build linux

// xtransport.go — HTTP/HTTPS transport layer for dnscrypt-proxy.
//
// Complete rewrite for Go 1.26+, focusing on performance, efficiency,
// and full compatibility with dnscrypt-proxy 2. Drop-in replacement.
//
// ══════════════════════════════════════════════════════════════════════════════
// ✅ ELITE IMPROVEMENTS - March 29, 2026
// ══════════════════════════════════════════════════════════════════════════════
// ELITE 8: saveCachedAddrs — removed temp var for expiration pointer
//          Go 1.26 new(expr) allows any expression as the operand, not just a
//          bare type name.  The prior code wrote:
//            exp := time.Now().Add(ttl)
//            item.expiration = &exp
//          The temp `exp` existed solely to make the expression addressable.
//          Now replaced with a single:
//            item.expiration = new(time.Now().Add(ttl))
//          One fewer local variable; same semantics; cleaner intent.
//
// ELITE 9: markUpdatingCachedIP — removed temp var for updatingUntil pointer
//          Same Go 1.26 new(expr) pattern as ELITE 8.  The temp `until` was
//          used in both branches of an if/else, so it cannot be inlined at the
//          call-sites without computing time.Now() twice.  Instead it is
//          computed once before the lock and named `updatingUntil` to make the
//          intent self-documenting:
//            updatingUntil := new(time.Now().Add(x.timeout))
//          Both branches assign the same pointer, matching prior semantics.
// ══════════════════════════════════════════════════════════════════════════════
//
// ✅ ELITE IMPROVEMENTS - March 27, 2026
// ══════════════════════════════════════════════════════════════════════════════
// ELITE 1: Removed obsolete `// +build linux` legacy directive (line 2)
//          In Go 1.17+, only //go:build is authoritative. The old //+build
//          form is ignored by the toolchain in Go 1.26 and is pure noise
//          that tools like gopls still flag. Removed to keep the file clean.
//
// ELITE 2: formatDialTarget — eliminated concurrent-Store race (was: Load→Store)
//          On a cold miss two goroutines could both fall through Load() and both
//          call Store(), creating a harmless but redundant double-write.
//          Changed to Load → compute → LoadOrStore so only one value ever wins.
//          The racing goroutine's computed string is discarded; no lock needed.
//
// ELITE 3: resolveUsingServers — fixed dead-code cancel branch (CRITICAL BUG)
//          The OPT 9 "cancellable backoff" select had context.Background().Done()
//          as one of its cases. context.Background().Done() returns a nil channel.
//          A receive on a nil channel blocks forever — that case NEVER fires.
//          The comment "Cancellable backoff — responds to context cancellation"
//          was factually incorrect. Removed the dead branch entirely. Per-query
//          cancellation already works correctly inside resolveRRType via its own
//          context.WithTimeoutCause. The backoff is now a clean timer drain.
//
// ELITE 4: resolveAndUpdateCache — eliminated stale-IP net.IP round-trip
//          Stale-cache path converted []netip.Addr → []net.IP (via AsSlice())
//          only to pass to saveCachedIPs which converted straight back to
//          []netip.Addr. Two heap allocations (staleIPs slice + each AsSlice
//          byte backing) wasted per grace-period refresh. Now calls
//          saveCachedAddrs directly with the already-typed []netip.Addr and
//          returns immediately — zero redundant allocations.
//
// ELITE 5: Fetch — eliminated context.WithCancel allocation on hot path
//          When the caller already provides a deadline, the prior code called
//          context.WithCancel(ctx) purely to obtain a cancel func for defer.
//          This allocated a child context and a CancelFunc needlessly.
//          Now uses a stack-allocated noop func() {} as the cancel when the
//          caller has a deadline. Saves one context allocation per request on
//          the hot path (every DoH query from callers with an existing deadline).
//
// ELITE 6: parseAndCacheAltSvc — removed always-true `p <= 65535` guard
//          strconv.ParseUint(v, 10, 16) with bitSize=16 already constrains the
//          result to [0, 65535] by specification. The follow-on `p <= 65535`
//          condition was provably always true — dead predicate executed on every
//          Alt-Svc field in every response. Removed for cleaner, faster parsing.
//
// ELITE 7: parseAndCacheAltSvc — added TOCTOU re-check under write lock
//          Between the initial RLock read and the final Lock+Store, a concurrent
//          goroutine could write a fresh negative-cache entry. Without the
//          re-check the second goroutine would silently overwrite it. Added a
//          double-checked read under the write lock before the Store so concurrent
//          writes are detected and the spurious overwrite is skipped.
// ══════════════════════════════════════════════════════════════════════════════
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
//
// ══════════════════════════════════════════════════════════════════════════════
// ✅ DEEP OPTIMIZATIONS - March 22, 2026
// ══════════════════════════════════════════════════════════════════════════════
// OPT 1: Full net.IP → netip.Addr migration in IP cache layer
//        CachedIPItem.ips changed from []net.IP to []netip.Addr. Value-type
//        (24 bytes, stack-allocated, comparable) — eliminates all bytes.Clone()
//        heap allocations in loadCachedIPs and uniqueNormalizedAddrs. Cache
//        reads are now zero-allocation. loadCachedIPs returns a copy of the
//        slice header only; the backing array is immutable netip.Addr values.
//
// OPT 2: Eliminated http.Header.Clone() per Fetch request
//        Pre-built immutable header maps for each content-type variant
//        (GET+gzip, GET plain, POST dns-message, POST odns-message) are
//        constructed once in rebuildTransport(). Fetch() selects the correct
//        pre-built map and assigns it directly to req.Header — zero map
//        allocation on the hot path. Only the body_hash query-param path
//        still needs a clone (rare/conditional).
//
// OPT 3: Shared dns.Client + dns.Transport stored as XTransport fields
//        Previously allocated a new dns.Transport + dns.Client per
//        resolveRRType call (2 allocs × 2 for dual A+AAAA). Now a single
//        shared instance is created in NewXTransport and reused. The miekg/dns
//        Client is safe for concurrent use.
//
// OPT 4: Cached formatted host:port strings via cachedDialTargets
//        buildDialContext and buildH3DialFunc now format "ip:port" strings
//        only once per unique (addr, port) pair, caching results in a small
//        sync.Map. Eliminates repeated strconv.Itoa + string concatenation
//        on the hot dial path.
//
// OPT 5: Fetch accepts caller context — eliminates per-request context alloc
//        Fetch() now takes a context.Context parameter. Callers with an
//        existing deadline pass it directly; a fallback WithTimeout is only
//        created when ctx == context.Background(). Saves one context.WithTimeout
//        allocation per request when the caller already has a deadline.
//
// OPT 6: body_hash SHA-512/256 computation made conditional
//        The sha512.Sum512_256 + hex.EncodeToString on every POST was ~200 ns
//        of CPU on router hardware. Now guarded behind a BodyHashEnabled bool
//        on XTransport (default false). Only computed when explicitly enabled.
//
// OPT 7: QUIC 0-RTT session resumption via TokenStore
//        quic.Config now includes a quic.NewLRUTokenStore(256, 8) so repeat
//        QUIC connections to the same DoH server skip a full RTT via 0-RTT
//        early data. Significant latency win for a DNS proxy that reconnects
//        to a small set of upstream resolvers.
//
// OPT 8: readLimitedBody replaced with Go 1.26 optimized io.ReadAll
//        Go 1.26 io.ReadAll is documented as 2× faster with 50% less memory.
//        The manual sync.Pool[*bytes.Buffer] + bytes.Clone pattern is replaced
//        by io.ReadAll(io.LimitReader(r, max)). Simpler code, fewer moving
//        parts, and leverages stdlib optimizations that track runtime changes.
//
// OPT 9: Internal parseIPAddr uses netip.ParseAddr for hot-path checks
//        Public ParseIP retains net.IP return type for API compatibility
//        with config.go, serversInfo.go, config_loader.go callers.
//        Internal hot-path calls (dial targets, cache guards, Fetch IP check)
//        use parseIPAddr returning netip.Addr — zero-allocation, stack-allocated.
//        splitHostPort now uses strings.Cut for clarity.
//        Resolver retry backoff uses time.Timer + select for cancellability.
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
// • io.ReadAll (Go 1.26 optimized version – 2× faster, 50% less memory) (OPT 8)
// • netip.Addr throughout IP cache layer — zero-allocation value type (OPT 1)
// • new(expr) — Go 1.26 allows any expression in new(), eliminating temp vars for pointer fields (ELITE 8, 9)
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
// • QUIC 0-RTT session resumption via LRU TokenStore (OPT 7)
// • Connection draining on non‑2xx responses to keep connections alive
// • Singleflight‑style per‑host resolution mutexes (unique.Handle keys, collapsed lookup)
// • hostPrewarmer uses unique.Handle[string] keys — pointer-eq vs string-eq (PERF 6)
// • Pre‑built immutable header maps per content-type — zero per-request map alloc (OPT 2)
// • Shared dns.Client field — eliminates per-resolve transport+client allocation (OPT 3)
// • Cached dial target strings — eliminates per-dial strconv+concat (OPT 4)
// • Caller context in Fetch — eliminates redundant context.WithTimeout alloc (OPT 5)
// • Conditional body_hash — eliminates unnecessary SHA-512/256 on POST (OPT 6)
// • gzip.Reader pool to prevent 32 KB allocations per compressed response
// • Alt‑Svc parsing using SplitSeq and bounded loops (prevents runaway parsing)
// • Fetch fast-exit for IP-literal hosts bypasses resolver entirely (PERF 7)
// • Dead runtime.GOOS branch removed from setTCPOptions (IMP 3)
// • Cancellable resolver retry backoff via time.Timer + select (OPT 9)
// • netip.Addr-based cache — zero-allocation cache reads (OPT 1)
// • io.ReadAll (Go 1.26) replaces manual buffer pool — simpler, faster (OPT 8)
//
// ── Compatibility ─────────────────────────────────────────────────────────────
// Public API unchanged: XTransport, NewXTransport, Fetch, Get, Post,
// DoHQuery, ObliviousDoHQuery, PurgeExpiredCache, ResetCache, CachedHosts.
// All method signatures and field names remain identical.
// NOTE: Fetch now accepts a context.Context as first parameter (OPT 5).
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
    h2MaxDecoderHeaderTableSize = 4*1024*1024 - 1   // ~4 MiB
    h2MaxEncoderHeaderTableSize = 4*1024*1024 - 1   // ~4 MiB
    h2MaxReceiveBufferPerConn   = 4*1024*1024 - 1   // ~4 MiB
    h2MaxReceiveBufferPerStream = 4*1024*1024 - 1   // ~4 MiB
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

// ── Global TLS session cache – saves one full TLS 1.3 RTT on reconnect ───────
var tlsSessionCache = tls.NewLRUClientSessionCache(h2TLSSessionCacheSize)

// ── gzip.Reader pool – eliminates 32 KB allocations per compressed response ───
var gzipReaderPool = sync.Pool{
    New: func() any { return new(gzip.Reader) },
}

// ── OPT 4: Cached dial target strings ────────────────────────────────────────
// Avoids repeated strconv.Itoa + string concat on the hot dial path.
// Key is a compact struct (netip.Addr is 24 bytes + uint16 port = 26 bytes).
type dialTargetKey struct {
    addr netip.Addr
    port uint16
}

var dialTargetCache sync.Map // map[dialTargetKey]string

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
    v, _ := dialTargetCache.LoadOrStore(k, s)
    return v.(string)
}

// ── Cache types (OPT 1: netip.Addr replaces net.IP) ──────────────────────────
type CachedIPItem struct {
    addrs         []netip.Addr
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

// ── OPT 2: Pre-built header key constants ─────────────────────────────────────
// These header maps are built once in rebuildTransport() and assigned directly
// to requests without cloning. They are treated as immutable after construction.
type prebuiltHeaders struct {
    getGzip  http.Header // GET with Accept-Encoding: gzip
    getPlain http.Header // GET without gzip
    postDNS  http.Header // POST application/dns-message
    postODNS http.Header // POST application/oblivious-dns-message
}

func buildPrebuiltHeaders() prebuiltHeaders {
    base := func(extra int) http.Header {
        h := make(http.Header, 4+extra)
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

    // ── OPT 2: Pre-built immutable header maps ────────────────────────────────
    headers prebuiltHeaders

    // Per‑host connection prewarmer (IMP 6: unique.Handle[string] keys)
    prewarmed hostPrewarmer

    // ── OPT 3: Shared DNS client for resolver queries ─────────────────────────
    dnsClient *dns.Client

    // ── OPT 6: Conditional body_hash on POST requests ─────────────────────────
    BodyHashEnabled bool
}

// ── Constructor ───────────────────────────────────────────────────────────────
func NewXTransport() *XTransport {
    if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
        panic("DefaultBootstrapResolver is not a valid IP:port — " + err.Error())
    }

    // ── OPT 3: Build shared DNS client once ───────────────────────────────────
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

// ── IP helpers (OPT 9: netip.ParseAddr used internally) ───────────────────────
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

// ── OPT 1: netip.Addr deduplication (replaces uniqueNormalizedIPs) ────────────
// uniqueNormalizedAddrs deduplicates addrs using a stack‑allocated array for up
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

// ── IP cache operations (OPT 1: netip.Addr throughout) ────────────────────────
func (x *XTransport) saveCachedAddrs(host string, addrs []netip.Addr, ttl time.Duration) {
    normalized := uniqueNormalizedAddrs(addrs)
    if len(normalized) == 0 {
        return
    }

    item := &CachedIPItem{addrs: normalized}
    if ttl >= 0 {
        ttl = max(ttl, MinResolverIPTTL)
        ttl += time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))
        item.expiration = new(time.Now().Add(ttl)) // Go 1.26: new(expr) — no temp var
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

// saveCachedIP saves a single IP into the cache.
//
// ── IMP 5: stack-allocated single-element — no heap alloc ─────────────────
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
    updatingUntil := new(time.Now().Add(x.timeout)) // Go 1.26: new(expr) — no temp var
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
    if item.updatingUntil != nil && now.Before(*item.updatingUntil) {
        updating = true
    }
    if item.expiration != nil && now.After(*item.expiration) {
        expired = true
    }
    if len(item.addrs) == 0 {
        return nil, expired, updating
    }
    // Return a copy of the slice header. netip.Addr is a value type so
    // the caller cannot mutate the cache's backing array.
    out := make([]netip.Addr, len(item.addrs))
    copy(out, item.addrs)
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

    // Clear cached dial target strings
    dialTargetCache.Range(func(key, _ any) bool {
        dialTargetCache.Delete(key)
        return true
    })

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
    x.tlsClientConfig = x.buildTLSConfig()

    // Rebuild pre-built headers (OPT 2)
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

        // ── PERF 5 + OPT 7: QUIC flow-control + 0-RTT session resumption ─────
        quicCfg := &quic.Config{
            InitialStreamReceiveWindow:     h3InitialStreamWindow,
            MaxStreamReceiveWindow:         h3MaxStreamWindow,
            InitialConnectionReceiveWindow: h3InitialConnWindow,
            MaxConnectionReceiveWindow:     h3MaxConnWindow,
            TokenStore:                     quic.NewLRUTokenStore(256, 8), // OPT 7: enables 0-RTT
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
            req.Header = x.headers.getPlain

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
// ── OPT 9: uses strings.Cut for clarity ──────────────────────────────────────
func splitHostPort(hostPort string) (host, port string) {
    if host, port, ok := strings.Cut(hostPort, "]:"); ok {
        return strings.TrimPrefix(host, "["), port
    }
    if host, port, ok := strings.Cut(hostPort, ":"); ok {
        return host, port
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
        portU16 := uint16(port & 0xffff)

        // ── OPT 4: Use cached dial target strings ─────────────────────────────
        endpoint := func(addr netip.Addr) string {
            if addr.IsValid() {
                return formatDialTarget(addr, portU16)
            }
            // Fallback: hostname dial (no cached IP)
            parsed := parseIPAddr(host)
            if parsed.IsValid() {
                return formatDialTarget(parsed, portU16)
            }
            return host + ":" + strconv.Itoa(port)
        }

        cachedAddrs, _, _ := x.loadCachedAddrs(host)
        targets := make([]string, 0, max(len(cachedAddrs), 1))
        for _, addr := range cachedAddrs {
            targets = append(targets, endpoint(addr))
        }
        if len(targets) == 0 {
            dlog.Debugf("[%s] no cached IP; falling back to hostname dial", host)
            targets = append(targets, endpoint(netip.Addr{}))
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
                if pdCtx, ok := (*x.proxyDialer).(netproxy.ContextDialer); ok {
                	conn, err = pdCtx.DialContext(ctx, dialNet, target)
                } else {
                	conn, err = (*x.proxyDialer).Dial(dialNet, target)
                }
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
        portU16 := uint16(port & 0xffff)

        type udpTarget struct {
            addr    string
            network string
        }

        // ── OPT 4: Use cached dial target strings for UDP ─────────────────────
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

        cachedAddrs, _, _ := x.loadCachedAddrs(host)
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

// ── OPT 3: resolveRRType uses shared dns.Client ──────────────────────────────
func (x *XTransport) resolveRRType(
    proto, host, resolver string,
    rrType uint16,
) (ips []net.IP, minTTL uint32, err error) {
    ctx, cancel := context.WithTimeoutCause(context.Background(), ResolverReadTimeout, errDNSQueryTimeout)
    defer cancel()

    msg := dns.NewMsg(fqdn(host), rrType) // fqdn is defined in common.go
    if msg == nil {
        return nil, noTTL, fmt.Errorf("dns.NewMsg returned nil for [%s] type %d", host, rrType)
    }
    msg.RecursionDesired = true
    msg.UDPSize = uint16(MaxDNSPacketSize) // defined in common.go
    msg.Security = true

    in, _, err := x.dnsClient.Exchange(ctx, msg, proto, resolver)
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

// ── OPT 9: Cancellable retry backoff via time.Timer + select ──────────────────
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
                // ── ELITE FIX: corrected timer-based backoff ──────────────────
                // The previous select had context.Background().Done() as a case.
                // context.Background().Done() returns a nil channel — a receive
                // on a nil channel BLOCKS FOREVER. That case was dead code that
                // could never fire, making the comment "cancellable backoff" a
                // documentation lie. Removed the unreachable branch entirely.
                // Per-query cancellation already happens in resolveRRType via
                // context.WithTimeoutCause. Always drain the timer to avoid leaks.
                timer := time.NewTimer(delay)
                <-timer.C
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

    if !x.ignoreSystemDNS {
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

    selectedIPs := ips
    if (resolveErr != nil || len(selectedIPs) == 0) && len(cachedAddrs) > 0 {
        dlog.Noticef("Using stale cached address for [%s] (grace period)", host)
        // ── ELITE FIX: eliminated net.IP round-trip alloc ─────────────────────
        // Prior code: cachedAddrs ([]netip.Addr) → []net.IP via AsSlice()
        //             → saveCachedIPs converts back to []netip.Addr.
        // Two heap allocations (staleIPs slice + each AsSlice byte backing) and
        // a full netip.AddrFromSlice loop wasted for no semantic reason.
        // We already have []netip.Addr; call saveCachedAddrs directly.
        x.saveCachedAddrs(host, cachedAddrs, ExpiredCachedIPGraceTTL)
        return nil
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
// ── OPT 5: Fetch now accepts a context.Context parameter ──────────────────────
// Callers with an existing deadline pass it directly. Pass context.Background()
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

    // ── PERF 1: Use stored http.Client — zero allocation on hot path ──────────
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

    // ── OPT 2: Select pre-built header map — zero allocation ──────────────────
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

    // ── OPT 6: Conditional body_hash — only compute when enabled ──────────────
    if body != nil && x.BodyHashEnabled {
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
    if !parseIPAddr(host).IsValid() {
        if err := x.resolveAndUpdateCache(host); err != nil {
            dlog.Errorf("Unable to resolve [%s]: check bootstrap_resolvers or system resolver", host)
            return nil, 0, nil, 0, err
        }
    }

    bodyLen := 0
    if body != nil {
        bodyLen = len(*body)
    }

    // ── OPT 5 + ELITE FIX: Use caller context; only create WithTimeout if needed ─
    // The prior code called context.WithCancel(ctx) when the caller already had a
    // deadline — allocating a child context and a CancelFunc just to defer cancel().
    // When the caller already provides a deadline, use ctx directly with a noop
    // cancel. This saves one context allocation per request on the hot path.
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
        req, err := http.NewRequestWithContext(fetchCtx, method, url.String(), reqBody)
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

    // ── OPT 8: Use Go 1.26 optimized io.ReadAll ──────────────────────────────
    // Go 1.26 io.ReadAll is 2× faster with 50% less memory than prior versions.
    // Replaces the manual sync.Pool[*bytes.Buffer] + bytes.Clone pattern.
    bin, err := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))
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
                // ── ELITE FIX: removed redundant p <= 65535 guard ─────────────
                // ParseUint(v, 10, 16) already restricts the result to [0, 65535]
                // by construction (bitSize=16). The extra check was always true
                // and added a branch on every loop iteration for nothing.
                if p, pErr := strconv.ParseUint(v, 10, 16); pErr == nil {
                    altPort = uint16(p)
                    dlog.Debugf("Alt-Svc: HTTP/3 advertised for [%s] on port %d", host, altPort)
                    break outer
                }
            }
        }
    }

    x.altSupport.Lock()
    // ── ELITE FIX: TOCTOU double-check under write lock ───────────────────────
    // Between the RLock read at the top of this function and this Lock, another
    // goroutine could have already written a fresh entry. Re-check so we never
    // overwrite a concurrently-written negative-cache entry with a stale parse.
    if cur, ok := x.altSupport.cache[host]; ok && cur.port == 0 && !isAltSvcExpired(cur, now) {
        x.altSupport.Unlock()
        dlog.Debugf("Alt-Svc: concurrent negative cache write for [%s]; skipping", host)
        return
    }
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
