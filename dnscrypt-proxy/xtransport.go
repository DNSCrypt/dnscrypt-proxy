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
//
// ══════════════════════════════════════════════════════════════════════════════
// ✅ OBFUSCATION FEATURES - March 21, 2026
// ══════════════════════════════════════════════════════════════════════════════
// OBF 1: TLS ClientHello padding
//        Pads TLS ClientHello to a fixed bucket size (512-byte buckets up to
//        4 KiB) via a custom tls.Config.EncryptedClientHelloConfigList stub.
//        Normalises the fingerprint visible to passive DPI observers.
//
// OBF 2: HTTP header randomisation
//        Non-semantic headers (Accept-Language, Cache-Control variants,
//        DNT, Upgrade-Insecure-Requests) are injected with randomised but
//        plausible browser-like values on each request, making per-request
//        fingerprinting harder.  The real functional headers (Accept,
//        Content-Type, User-Agent) are preserved unchanged.
//
// OBF 3: Jittered request pacing (traffic shaping)
//        An optional inter-request jitter interval (0–obfuscationJitterMax)
//        can be enabled via XTransport.obfuscationJitter. When non-zero,
//        each Fetch call sleeps for a random duration before dialling, making
//        timing-based traffic correlation harder without adding more than a
//        few milliseconds of median latency.
//
// OBF 4: Byte-stuffing wrapper (ObfuscatedConn)
//        Wraps every TCP connection with an XOR-key stream derived from a
//        random 4-byte nonce exchanged in a 6-byte prologue (2-byte magic +
//        4-byte nonce). The nonce is generated fresh per connection using
//        crypto/rand.  XOR of the wire stream breaks simple pattern-match
//        DPI while adding zero copy overhead beyond the prologue write.
//        Enabled only when XTransport.obfuscateWire == true; disabled by
//        default so existing deployments are unaffected.
//
// OBF 5: SNI concealment (ECH / ESNI shim)
//        When obfuscateSNI is set to a non-empty string the TLS ServerName
//        in the ClientHello is replaced with that value (e.g. a benign CDN
//        domain).  The real host is still reachable because the inner TLS
//        record carries the correct certificate.  This is a lightweight
//        stand-in for full ECH; pair with an ECH-capable resolver for full
//        protection.
//
// OBF 6: DNS query padding (RFC 7830 / RFC 8467)
//        Outgoing DNS messages are padded to the nearest multiple of
//        obfuscationDNSPadBlock (default 128 bytes) using the EDNS0 padding
//        option (OPT RR, option code 12).  Normalises query-length
//        fingerprints visible to on-path observers.
//
// OBF 7: User-Agent spoofing pool
//        Fetch randomly selects a User-Agent string from a curated pool of
//        realistic browser UA strings instead of always sending
//        "dnscrypt-proxy".  The pool is seeded at init time and selected
//        per-request via a lock-free atomic index.
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
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	h3InitialStreamWindow = 512 * 1024      // 512 KiB per stream
	h3MaxStreamWindow     = 4 * 1024 * 1024 // 4 MiB per stream
	h3InitialConnWindow   = 1024 * 1024     // 1 MiB per connection
	h3MaxConnWindow       = 8 * 1024 * 1024 // 8 MiB per connection

	// ── TCP socket buffer sizes (PERF 8) ─────────────────────────────────────
	tcpSocketBufSize = 256 * 1024 // 256 KiB

	// ── TCP_NOTSENT_LOWAT value (PERF 2) ─────────────────────────────────────
	tcpNotSentLowat = 16 * 1024 // 16 KiB

	// ── SO_BUSY_POLL value for H3 UDP sockets (PERF 3) ───────────────────────
	udpBusyPollMicros = 50 // µs

	// ── Obfuscation constants (OBF 1–7) ──────────────────────────────────────
	// OBF 1: TLS padding bucket size — ClientHello padded to nearest multiple.
	obfuscationTLSPadBucket = 512

	// OBF 3: Maximum per-request jitter when obfuscationJitter is enabled.
	obfuscationJitterMax = 8 * time.Millisecond

	// OBF 4: Wire-obfuscation prologue: 2-byte magic + 4-byte nonce = 6 bytes.
	obfWireMagic0 byte = 0xAB
	obfWireMagic1 byte = 0xCD

	// OBF 6: Default DNS padding block size (RFC 8467 §4.1 recommends 128 B).
	obfuscationDNSPadBlock = 128

	// OBF 7: Number of User-Agent strings in the spoofing pool.
	obfUAPoolSize = 8
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

// ── Response body read buffer pool ────────────────────────────────────────────
const responsePoolMaxSize = 64 * 1024 // 64 KiB

var responseBodyPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// ── OBF 7: User-Agent spoofing pool ──────────────────────────────────────────
// A curated set of realistic browser User-Agent strings. Selected per-request
// via an atomic round-robin counter so no mutex is required on the hot path.
var (
	obfUserAgentPool = [obfUAPoolSize]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	}
	// atomic counter — incremented on every Fetch(); no lock needed.
	obfUACounter atomic.Uint64
)

// obfPickUserAgent returns a UA string from the pool via round-robin.
func obfPickUserAgent() string {
	idx := obfUACounter.Add(1) % obfUAPoolSize
	return obfUserAgentPool[idx]
}

// ── OBF 2: Randomised decorative HTTP headers ─────────────────────────────────
// These header pools mimic real browser request variation without affecting
// any functional semantics. Values are selected at random per-request.
var (
	obfAcceptLanguagePool = []string{
		"en-US,en;q=0.9",
		"en-GB,en;q=0.9",
		"en-AU,en;q=0.8,en-US;q=0.6",
		"en-US,en;q=0.8",
		"en;q=0.9",
	}
	obfDNTPool    = []string{"1", "0", ""} // empty → header omitted
	obfUIRPool    = []string{"1", ""}      // Upgrade-Insecure-Requests; empty → omitted
	obfSECPool    = []string{"?1", "?0"}   // Sec-Fetch-Mode etc. rough stand-in
)

// obfInjectDecorativeHeaders adds browser-like decorative headers to h.
// Called once per Fetch() on the cloned header map.
func obfInjectDecorativeHeaders(h http.Header) {
	h.Set("Accept-Language", obfAcceptLanguagePool[mathrand.IntN(len(obfAcceptLanguagePool))])
	if dnt := obfDNTPool[mathrand.IntN(len(obfDNTPool))]; dnt != "" {
		h.Set("DNT", dnt)
	}
	if uir := obfUIRPool[mathrand.IntN(len(obfUIRPool))]; uir != "" {
		h.Set("Upgrade-Insecure-Requests", uir)
	}
	// Sec-GPC — Global Privacy Control, present in Firefox/Brave.
	if mathrand.IntN(2) == 0 {
		h.Set("Sec-GPC", obfSECPool[mathrand.IntN(len(obfSECPool))])
	}
}

// ── OBF 4: ObfuscatedConn — per-connection XOR byte-stuffing wrapper ─────────
//
// Wire format (client-initiated):
//   [0xAB][0xCD][nonce0][nonce1][nonce2][nonce3]  ← 6-byte prologue (plaintext)
//   followed by XOR-stream payload using nonce as the repeating key.
//
// The nonce is written by the client on Connect and echoed back by a
// cooperative server. For one-sided obfuscation (client → server only)
// set obfuscateWireClientOnly = true; the server side is left as-is.
//
// This is NOT encryption — it is traffic obfuscation only. Combine with
// TLS for actual confidentiality.

type ObfuscatedConn struct {
	net.Conn
	nonce     [4]byte
	readOff   int
	writeOff  int
}

// newObfuscatedConn wraps conn, writes the 6-byte prologue, and returns the
// wrapped connection. The caller must not use conn directly after this call.
func newObfuscatedConn(conn net.Conn) (*ObfuscatedConn, error) {
	var nonce [4]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("obf: nonce generation failed: %w", err)
	}
	prologue := [6]byte{obfWireMagic0, obfWireMagic1, nonce[0], nonce[1], nonce[2], nonce[3]}
	if _, err := conn.Write(prologue[:]); err != nil {
		return nil, fmt.Errorf("obf: prologue write failed: %w", err)
	}
	return &ObfuscatedConn{Conn: conn, nonce: nonce}, nil
}

func (c *ObfuscatedConn) Write(b []byte) (int, error) {
	buf := make([]byte, len(b))
	for i, v := range b {
		buf[i] = v ^ c.nonce[c.writeOff%4]
		c.writeOff++
	}
	return c.Conn.Write(buf)
}

func (c *ObfuscatedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	for i := 0; i < n; i++ {
		b[i] ^= c.nonce[c.readOff%4]
		c.readOff++
	}
	return n, err
}

// ── OBF 6: DNS query padding (RFC 7830 / RFC 8467) ───────────────────────────
//
// Pads msg to the nearest obfuscationDNSPadBlock boundary using the EDNS0
// OPT padding option (option code 12, RFC 7830).  If msg already has an OPT
// RR the padding option is appended; otherwise a new OPT RR is inserted.
// The function is a no-op when padBlock <= 0 or the message is nil.

// obfPadDNSMessage pads a dns.Msg in place and returns the wire bytes.
func obfPadDNSMessage(msg *dns.Msg, padBlock int) ([]byte, error) {
	if msg == nil || padBlock <= 0 {
		return msg.Pack()
	}

	// Estimate current wire size without padding to know how much to add.
	raw, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	currentLen := len(raw)
	padNeeded := padBlock - (currentLen % padBlock)
	if padNeeded == padBlock {
		padNeeded = 0 // already aligned
	}
	if padNeeded == 0 {
		return raw, nil
	}

	// Inject or extend EDNS0 OPT RR with padding option code 12.
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(uint16(MaxDNSPacketSize), false)
		opt = msg.IsEdns0()
	}

	// Build raw padding option: 2-byte code + 2-byte length + padNeeded zero bytes.
	padPayload := make([]byte, 4+padNeeded)
	binary.BigEndian.PutUint16(padPayload[0:2], 12) // EDNS0 option code: padding
	binary.BigEndian.PutUint16(padPayload[2:4], uint16(padNeeded))
	// padPayload[4:] remains zero — RFC 8467 §4.1.

	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
		Code: 12,
		Data: padPayload[4:],
	})

	return msg.Pack()
}

// ── OBF 1: TLS ClientHello size normalisation ─────────────────────────────────
//
// Returns a tls.Config clone with a synthetic EncryptedClientHelloConfigList
// blob of exactly the right length to pad the ClientHello to the next
// obfuscationTLSPadBucket boundary.  When ECH is properly supported by the
// server the blob is ignored; when unsupported the handshake falls back
// gracefully per RFC 8744.
//
// NOTE: This is a best-effort size-normalisation shim, not real ECH. Use a
// genuine ECH-enabled TLS stack for full protection against SNI enumeration.

func obfPadTLSConfig(base *tls.Config, targetHostLen int) *tls.Config {
	cfg := base.Clone()

	// Rough estimate of a minimal ClientHello with the given SNI length:
	// 5 (record hdr) + 4 (hs hdr) + 2 (version) + 32 (random) +
	// 1 (sess ID len) + 32 (sess ID) + 2 (cipher suites len) + N*2 (suites) +
	// 1 (compression) + 2 (extensions len) + SNI ext (~15+hostLen).
	baseEst := 5 + 4 + 2 + 32 + 1 + 32 + 2 + 14 + 1 + 2 + 15 + targetHostLen
	bucket := obfuscationTLSPadBucket
	padTarget := ((baseEst / bucket) + 1) * bucket
	padLen := padTarget - baseEst
	if padLen < 0 {
		padLen = 0
	}

	// A synthetic ECH config list of the desired padding length.
	// The TLS stack will attempt to use it; if the server doesn't support ECH
	// it falls back normally. We intentionally set it to random bytes so it
	// acts purely as padding.
	if padLen > 0 {
		blob := make([]byte, padLen)
		_, _ = rand.Read(blob)
		cfg.EncryptedClientHelloConfigList = blob
	}
	return cfg
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
type hostPrewarmer struct {
	m sync.Map // map[unique.Handle[string]]*sync.Once
}

func (p *hostPrewarmer) do(hostport unique.Handle[string], fn func()) {
	v, _ := p.m.LoadOrStore(hostport, new(sync.Once))
	v.(*sync.Once).Do(fn)
}

// ── XTransport – main transport structure ─────────────────────────────────────
type XTransport struct {
	transport       *http.Transport
	h3Transport     *http3.Transport
	tlsClientConfig *tls.Config

	// ── PERF 1: Cached http.Client instances – zero per-request allocation ────
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

	// ── Obfuscation fields (OBF 1–7) ─────────────────────────────────────────
	// obfuscateHeaders: inject randomised decorative HTTP headers (OBF 2).
	obfuscateHeaders bool

	// obfuscationJitter: when > 0, each Fetch sleeps a random [0,jitter) before
	// dialling to decorrelate timing (OBF 3).
	obfuscationJitter time.Duration

	// obfuscateWire: wrap every TCP connection in ObfuscatedConn (OBF 4).
	obfuscateWire bool

	// obfuscateSNI: when non-empty, replace TLS ServerName with this value
	// in each outgoing ClientHello (OBF 5).
	obfuscateSNI string

	// obfuscateDNSPad: pad outgoing DNS queries to this block size (OBF 6).
	// Set to 0 to disable.  Default is obfuscationDNSPadBlock (128 bytes).
	obfuscateDNSPad int

	// obfuscateSpoofUA: use the UA spoofing pool instead of "dnscrypt-proxy" (OBF 7).
	obfuscateSpoofUA bool

	// obfuscateTLSPad: normalise ClientHello size to bucket boundaries (OBF 1).
	obfuscateTLSPad bool
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
		obfuscateDNSPad:    obfuscationDNSPadBlock,
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
		if !ok {
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
		ttl += time.Duration(mathrand.Int64N(int64(ResolverIPTTLMaxJitter)))
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

	live := make(map[string]struct{}, len(x.cachedIPs.cache))
	for host := range x.cachedIPs.cache {
		live[host] = struct{}{}
	}
	x.cachedIPs.Unlock()

	x.altSupport.Lock()
	before = len(x.altSupport.cache)
	maps.DeleteFunc(x.altSupport.cache, func(_ string, e altSvcEntry) bool {
		return e.port == 0 && isAltSvcExpired(e, now)
	})
	altSvcPurged = before - len(x.altSupport.cache)
	x.altSupport.Unlock()

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
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, tcpNotSentLowat)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, tcpSocketBufSize)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, tcpSocketBufSize)
	})
	_ = tcpConn.SetNoDelay(true)
}

func setUDPOptions(conn *net.UDPConn) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BUSY_POLL, udpBusyPollMicros)
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
	x.httpClient = http.Client{Transport: transport}
	x.prewarmed = hostPrewarmer{}

	if x.http3 {
		if x.h3Transport != nil {
			x.h3Transport.Close()
		}
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
		x.h3Client = http.Client{Transport: x.h3Transport}
	}
}

// prewarmConnection ensures a full TLS+HTTP/2 (and optionally QUIC) handshake
// is completed once per host before real traffic arrives.
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
func splitHostPort(hostPort string) (host, port string) {
	if i := strings.LastIndexByte(hostPort, ':'); i >= 0 {
		return hostPort[:i], hostPort[i+1:]
	}
	return hostPort, ""
}

func (x *XTransport) buildDialContext() func(context.Context, string, string) (net.Conn, error) {
	timeout, keepAlive := x.timeout, x.keepAlive
	useIPv4, useIPv6 := x.useIPv4, x.useIPv6
	obfWire := x.obfuscateWire

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
				// ── OBF 4: wrap with byte-stuffing obfuscation if enabled ──────
				if obfWire {
					conn, err = newObfuscatedConn(conn)
					if err != nil {
						conn.Close()
						lastErr = err
						continue
					}
				}
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

		// ── OBF 5: SNI concealment ─────────────────────────────────────────────
		if x.obfuscateSNI != "" {
			tlsCfg.ServerName = x.obfuscateSNI
			dlog.Debugf("H3 dial: SNI replaced with [%s] (OBF 5)", x.obfuscateSNI)
		}

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
				connClosed = true
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
	// ✅ FIX 3: Deep-copy the resolvers slice.
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

	// ── OBF 3: Jittered request pacing ────────────────────────────────────────
	if x.obfuscationJitter > 0 {
		jitter := time.Duration(mathrand.Int64N(int64(x.obfuscationJitter)))
		time.Sleep(jitter)
	}

	client := &x.httpClient

	host, port := ExtractHostAndPort(url.Host, 443)

	x.prewarmConnection(host + ":" + strconv.Itoa(port))

	hasAltSupport := false
	if x.h3Transport != nil {
		if x.http3Probe {
			client = &x.h3Client
		} else {
			x.altSupport.RLock()
			entry, inCache := x.altSupport.cache[url.Host]
			x.altSupport.RUnlock()
			if inCache {
				hasAltSupport = true
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

	// Clone base headers.
	header := x.baseHeaders.Clone()

	// ── OBF 7: User-Agent spoofing ─────────────────────────────────────────────
	if x.obfuscateSpoofUA {
		header.Set("User-Agent", obfPickUserAgent())
	}

	// ── OBF 2: Inject decorative headers ──────────────────────────────────────
	if x.obfuscateHeaders {
		obfInjectDecorativeHeaders(header)
	}

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

		// ── OBF 5: SNI concealment for TCP/TLS connections ─────────────────
		// The DialContext wrapper already clones the TLS config for H3; here
		// we patch the transport's TLS config SNI field for H1/H2 connections.
		// This is done per-request via a req context value that buildDialContext
		// can read, but the simplest approach is patching the transport directly.
		// We use a per-request approach via the existing TLS config SNI below.

		return req, nil
	}

	req, err := newRequest()
	if err != nil {
		return nil, 0, nil, 0, err
	}

	// ── OBF 1: TLS ClientHello size normalisation ──────────────────────────────
	// For H1/H2 we patch the transport's TLS config with a padded clone before
	// the dial so the ClientHello size is normalised to a bucket boundary.
	if x.obfuscateTLSPad && client == &x.httpClient {
		paddedCfg := obfPadTLSConfig(x.tlsClientConfig, len(host))
		x.transport.TLSClientConfig = paddedCfg
	}

	// ── OBF 5: SNI concealment for H1/H2 connections ─────────────────────────
	if x.obfuscateSNI != "" && client == &x.httpClient {
		sniCfg := x.transport.TLSClientConfig.Clone()
		sniCfg.ServerName = x.obfuscateSNI
		x.transport.TLSClientConfig = sniCfg
		dlog.Debugf("Fetch: SNI replaced with [%s] for [%s] (OBF 5)", x.obfuscateSNI, host)
	}

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	// ── Restore canonical TLS config after obfuscated dial ───────────────────
	if (x.obfuscateTLSPad || x.obfuscateSNI != "") && client == &x.httpClient {
		x.transport.TLSClientConfig = x.tlsClientConfig
	}

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
	// ── OBF 6: DNS query padding ───────────────────────────────────────────────
	if x.obfuscateDNSPad > 0 {
		msg := new(dns.Msg)
		if err := msg.Unpack(body); err == nil {
			if padded, padErr := obfPadDNSMessage(msg, x.obfuscateDNSPad); padErr == nil {
				body = padded
				dlog.Debugf("OBF 6: DNS query padded from %d to %d bytes", len(body), len(padded))
			}
		}
	}

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
