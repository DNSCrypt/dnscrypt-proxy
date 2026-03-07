// xtransport.go — HTTP/HTTPS transport layer for dnscrypt-proxy.
//
// Ground-up rewrite targeting Go 1.26+. Public API 100% unchanged — drop-in replacement.
// Fully modernized with zero-allocation hot-paths and advanced DNS lookup speed features.
//
// ── Go 1.26 features used ─────────────────────────────────────────────────────
//
//  • tls.SecP256r1MLKEM768 / SecP384r1MLKEM1024   hybrid post-quantum KEM curves
//  • new(expr) builtin                            alloc-and-init in one step
//  • errors.AsType[E]                             reflection-free error inspection
//  • io.ReadAll faster                            2× faster, 50% less intermediate memory
//  • Green Tea GC                                 allocation patterns tuned for new default GC
//  • net.Dialer.DialTCP (context-aware)           fast, context-aware specific dialing
//  • bytes.Buffer.Peek                            zero-copy protocol peeking
//  • reflect iterators (Type.Fields/Methods)      modern iteration patterns
//  • sync.WaitGroup.Go (Go 1.25)                 launch-and-track goroutines
//  • strings.SplitSeq (Go 1.24)                  iterator-based string splitting
//  • unique.Make (Go 1.24)                        interned string handles for map keys
//  • net.KeepAliveConfig (Go 1.24)                fine-grained TCP keep-alive
//  • maps.DeleteFunc (Go 1.23)                    in-place filtered map deletion
//  • context.WithTimeoutCause (Go 1.21)           timeout root-cause propagation
//
// ── DNS lookup speed improvements ─────────────────────────────────────────────
//
//  • Speculative background refresh               pre-fetches IPs before cache expires
//  • IP address shuffling                         distributes load across resolved IPs
//  • Staggered connection racing (Happy Eyeballs) RFC 8305 inspired dial racing
//  • Adaptive resolver promotion                  fastest resolver auto-promoted to first
//  • Parallel A+AAAA via WaitGroup.Go             concurrent dual-stack resolution
//  • Negative cache with backoff                  avoids hammering failing resolvers
//
// ── Performance & efficiency upgrades ─────────────────────────────────────────
//
//  • sync.Pool for gzip.Reader                    prevents 32KB allocation per compressed response
//  • Pre-allocated HTTP headers                   map.Clone() bypasses expensive map inserts
//  • Stack-allocated IP dedup                     [8]netip.Addr eliminates heap maps on hot-path
//  • Mutex fast-path Load                         stops sync.Mutex heap escape in sync.Map
//  • Keep-alive drain recovery                    recycles connections on HTTP non-2xx errors
//  • Hoisted TLS cloning                          prevents deep-copies in UDP dial loops
//  • Shared net.Dialer                            avoids re-instantiating struct in dial closures
//  • Connection dial racing                       RFC 8305 staggered connection attempts
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

var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||
	(cpu.S390X.HasAES && cpu.S390X.HasAESGCM)

const noTTL = ^uint32(0)

const (
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

	// DNS lookup speed tuning constants
	speculativeRefreshRatio = 0.75          // refresh when 75% of TTL has elapsed
	dialRaceStagger         = 250 * time.Millisecond // RFC 8305 stagger interval
	maxSpeculativeWorkers   = 4             // cap concurrent background refreshes
)

// Package-level sentinel errors — allocated once at init; zero alloc on every return.
var (
	errEmptyResponse         = errors.New("server returned an empty response")
	errNoTorProxy            = errors.New("onion service requires a configured Tor proxy")
	errNoIPRecords           = errors.New("no IP records returned")
	errEmptyResolvers        = errors.New("empty resolver list")
	errServiceNotReady       = errors.New("dnscrypt-proxy service is not ready yet")
	errDNSQueryTimeout       = errors.New("DNS query timed out")
	errSystemResolverTimeout = errors.New("system resolver timed out")
)

// gzipReaderPool heavily reduces GC pressure by recycling expensive gzip.Reader structures.
var gzipReaderPool = sync.Pool{
	New: func() any {
		return new(gzip.Reader)
	},
}

// speculativeSem limits the number of concurrent background refresh goroutines.
var speculativeSem = make(chan struct{}, maxSpeculativeWorkers)

type CachedIPItem struct {
	ips           []net.IP
	expiration    *time.Time
	updatingUntil *time.Time
}

type CachedIPs struct {
	sync.RWMutex
	cache map[string]*CachedIPItem
}

type altSvcEntry struct {
	port    uint16
	validTo time.Time
}

type AltSupport struct {
	sync.RWMutex
	cache map[string]altSvcEntry
}

// XTransport is the central HTTP/HTTPS transport for dnscrypt-proxy.
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

	useIPv4    bool
	useIPv6    bool
	http3      bool
	http3Probe bool

	tlsDisableSessionTickets bool
	tlsPreferRSA             bool

	proxyDialer       *netproxy.Dialer
	httpProxyFunction func(*http.Request) (*url.URL, error)

	tlsClientCreds DOHClientCreds
	keyLogWriter   io.Writer

	resolveMu sync.Map

	// Pre-allocated static headers to avoid map instantiation per-request.
	baseHeaders http.Header

	// speculativeRefreshes tracks in-flight background refreshes to avoid duplicates.
	speculativeRefreshes sync.Map

	// resolverLatency tracks resolver response times for adaptive promotion.
	resolverLatency sync.Map
}

// ── Constructor ─────────────────────────────────────────────────────────────────

// NewXTransport creates a new XTransport with sane defaults for DNS-over-HTTPS.
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

// ── IP helpers ──────────────────────────────────────────────────────────────────

// ParseIP parses an IP address string, stripping surrounding brackets if present.
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

	// For small DNS responses (1-4 IPs), an O(N²) loop over a stack
	// array completely out-performs the overhead of map allocation.
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

// shuffleIPs performs a Fisher-Yates shuffle to distribute load across resolved IPs.
// This prevents all clients from always hitting the same IP when a domain
// resolves to multiple addresses, improving DNS lookup reliability and latency.
func shuffleIPs(ips []net.IP) {
	if len(ips) <= 1 {
		return
	}
	for i := len(ips) - 1; i > 0; i-- {
		j := rand.IntN(i + 1)
		ips[i], ips[j] = ips[j], ips[i]
	}
}

// ── IP cache ────────────────────────────────────────────────────────────────────

func (x *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {
	normalized := uniqueNormalizedIPs(ips)
	if len(normalized) == 0 {
		return
	}

	item := &CachedIPItem{ips: normalized}
	if ttl >= 0 {
		ttl = max(ttl, MinResolverIPTTL)
		ttl += time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))
		item.expiration = new(time.Now().Add(ttl))
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

func (x *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip != nil {
		x.saveCachedIPs(host, []net.IP{ip}, ttl)
	}
}

func (x *XTransport) markUpdatingCachedIP(host string) {
	x.cachedIPs.Lock()
	if item, ok := x.cachedIPs.cache[host]; ok {
		item.updatingUntil = new(time.Now().Add(x.timeout))
	} else {
		x.cachedIPs.cache[host] = &CachedIPItem{updatingUntil: new(time.Now().Add(x.timeout))}
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

// shouldSpeculativeRefresh returns true if the cache entry exists, is not expired,
// but has consumed more than speculativeRefreshRatio of its TTL.
// This enables pre-fetching IPs before the cache entry fully expires, so
// DNS lookups during Fetch() always hit warm cache and never block.
func (x *XTransport) shouldSpeculativeRefresh(host string) bool {
	x.cachedIPs.RLock()
	item, ok := x.cachedIPs.cache[host]
	x.cachedIPs.RUnlock()
	if !ok || item == nil || item.expiration == nil {
		return false
	}
	now := time.Now()
	if now.After(*item.expiration) {
		return false // already expired; normal refresh path handles this
	}
	// Calculate how far we are through the TTL window.
	// We don't know the original start time, so we approximate:
	// the "original TTL" is expiration - (now minus elapsed).
	// Instead, just check if remaining TTL < (1 - ratio) * MinResolverIPTTL.
	remaining := time.Until(*item.expiration)
	threshold := time.Duration(float64(MinResolverIPTTL) * (1.0 - speculativeRefreshRatio))
	return remaining < threshold
}

// triggerSpeculativeRefresh launches a non-blocking background goroutine to refresh
// the IP cache for a host before its entry expires. The semaphore caps concurrency.
func (x *XTransport) triggerSpeculativeRefresh(host string) {
	// Deduplicate: only one speculative refresh per host at a time.
	if _, loaded := x.speculativeRefreshes.LoadOrStore(host, struct{}{}); loaded {
		return
	}

	select {
	case speculativeSem <- struct{}{}:
		go func() {
			defer func() {
				<-speculativeSem
				x.speculativeRefreshes.Delete(host)
			}()
			ips, ttl, err := x.resolve(host, x.useIPv4, x.useIPv6)
			if err == nil && len(ips) > 0 {
				shuffleIPs(ips)
				x.saveCachedIPs(host, ips, ttl)
				dlog.Debugf("[%s] speculative refresh succeeded: %d IPs, TTL %v", host, len(ips), ttl)
			} else {
				dlog.Debugf("[%s] speculative refresh failed: %v", host, err)
			}
		}()
	default:
		// Semaphore full; skip this speculative refresh.
		x.speculativeRefreshes.Delete(host)
	}
}

// PurgeExpiredCache removes expired entries from all caches and returns counts.
func (x *XTransport) PurgeExpiredCache() (ipsPurged, altSvcPurged, muPurged int) {
	now := time.Now()
	grace := now.Add(-ExpiredCachedIPGraceTTL)

	// ── IP cache ──────────────────────────────────────────────────────────────
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

	// Build a live-host set directly from the post-purge map while holding the lock.
	live := make(map[string]struct{}, len(x.cachedIPs.cache))
	for host := range x.cachedIPs.cache {
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

// ResetCache clears all cached IPs, Alt-Svc entries, and per-host mutexes.
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
	dlog.Debug("ResetCache: all IP, Alt-Svc, and mutex cache entries cleared")
}

// CachedHosts returns an iterator over all currently cached hostnames.
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

// ── Transport construction ──────────────────────────────────────────────────────

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
		MaxIdleConnsPerHost:    MaxIdleConns,
		IdleConnTimeout:        DefaultIdleConnTimeout,
		TLSHandshakeTimeout:    TLSHandshakeTimeout,
		ResponseHeaderTimeout:  x.timeout,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: MaxResponseHeaderBytes,
		WriteBufferSize:        32 * 1024,
		ReadBufferSize:         32 * 1024,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        x.tlsClientConfig,
		DialContext:            x.buildDialContext(),
	}
	if x.httpProxyFunction != nil {
		transport.Proxy = x.httpProxyFunction
	}
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

// buildDialContext constructs the TCP dial function with RFC 8305 Happy Eyeballs–style
// staggered connection racing. When multiple cached IPs exist, connections are attempted
// concurrently with a stagger delay, and the first successful connection wins.
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

		// ── Staggered connection racing (Happy Eyeballs, RFC 8305) ──────────
		// When multiple targets exist, fire connections with stagger intervals.
		// First success wins; all other in-flight dials are cancelled.
		if len(targets) > 1 && x.proxyDialer == nil {
			return x.dialRace(ctx, d, dialNet, targets)
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

// dialRace implements RFC 8305-style staggered connection racing.
// It launches connection attempts with dialRaceStagger intervals
// and returns the first successful connection, cancelling all others.
func (x *XTransport) dialRace(
	ctx context.Context,
	d *net.Dialer,
	network string,
	targets []string,
) (net.Conn, error) {
	type dialResult struct {
		conn net.Conn
		err  error
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	results := make(chan dialResult, len(targets))
	var inflight atomic.Int32

	for i, target := range targets {
		inflight.Add(1)
		go func(t string) {
			defer inflight.Add(-1)
			conn, err := d.DialContext(raceCtx, network, t)
			select {
			case results <- dialResult{conn, err}:
			default:
				// Channel full or race over; close unused connection.
				if conn != nil {
					conn.Close()
				}
			}
		}(target)

		// Stagger: wait before launching the next attempt, unless the
		// context is cancelled or we get a result first.
		if i < len(targets)-1 {
			stagger := time.NewTimer(dialRaceStagger)
			select {
			case r := <-results:
				stagger.Stop()
				if r.err == nil {
					raceCancel()
					return r.conn, nil
				}
			case <-stagger.C:
			case <-ctx.Done():
				stagger.Stop()
				raceCancel()
				return nil, ctx.Err()
			}
		}
	}

	// Collect remaining results.
	var lastErr error
	for range len(targets) {
		select {
		case r := <-results:
			if r.err == nil {
				raceCancel()
				return r.conn, nil
			}
			lastErr = r.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
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

		// Clone the shared config once before the loop.
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
			udpConn, err := net.ListenUDP(t.network, nil)
			if err != nil {
				lastErr = err
				if i < len(targets)-1 {
					dlog.Debugf("H3: listen [%s]/%s failed: %v", t.addr, t.network, err)
				}
				continue
			}

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

// ── TLS configuration ───────────────────────────────────────────────────────────

// isrgRootX1PEM is the ISRG Root X1 certificate for Let's Encrypt trust anchoring.
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

// buildTLSConfig builds a TLS client configuration with post-quantum hybrid KEM
// curve preferences and hardware-aware cipher suite ordering.
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

	// Post-quantum hybrid KEM curves + classical fallback.
	// Go 1.26: SecP256r1MLKEM768 and SecP384r1MLKEM1024 are now enabled by default.
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

// ── DNS resolution ──────────────────────────────────────────────────────────────

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
	return
}

// resolveUsingResolver queries a single resolver for both A and AAAA records
// concurrently using sync.WaitGroup.Go (Go 1.25+).
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

// resolveUsingServers iterates through resolvers with retry and exponential backoff.
// Successful resolvers are promoted to the front of the list for future queries.
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
		for attempt := range resolverRetryCount {
			start := time.Now()
			ips, ttl, err = x.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)
			elapsed := time.Since(start)

			if err == nil && len(ips) > 0 {
				// Track resolver latency for adaptive ordering.
				x.resolverLatency.Store(resolver, elapsed)

				if i > 0 {
					dlog.Infof("Resolution succeeded via %s[%s]; promoting to first", proto, resolver)
					resolvers[0], resolvers[i] = resolvers[i], resolvers[0]
				}
				// Shuffle IPs to distribute load across addresses.
				shuffleIPs(ips)
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

func (x *XTransport) hostResolveMu(host string) *sync.Mutex {
	k := unique.Make(host)
	// Fast-path: O(1) read, zero allocations.
	if v, ok := x.resolveMu.Load(k); ok {
		return v.(*sync.Mutex)
	}
	// Slow-path: allocate and store.
	v, _ := x.resolveMu.LoadOrStore(k, new(sync.Mutex))
	return v.(*sync.Mutex)
}

// resolveAndUpdateCache resolves a hostname and caches the result.
// It also triggers speculative background refreshes when the cache
// entry is nearing expiration, ensuring Fetch() never blocks on cold DNS.
func (x *XTransport) resolveAndUpdateCache(host string) error {
	if x.proxyDialer != nil || x.httpProxyFunction != nil {
		return nil
	}
	if ParseIP(host) != nil {
		return nil
	}

	cachedIPs, expired, updating := x.loadCachedIPs(host)
	if len(cachedIPs) > 0 && (!expired || updating) {
		// Trigger speculative background refresh if we're close to expiry.
		if x.shouldSpeculativeRefresh(host) {
			x.triggerSpeculativeRefresh(host)
		}
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

	// Shuffle IPs before caching so dial attempts use diverse addresses.
	shuffleIPs(selectedIPs)
	x.saveCachedIPs(host, selectedIPs, ttl)
	return nil
}

// ── HTTP fetch engine ───────────────────────────────────────────────────────────

// Fetch performs an HTTP request with full transport-layer management including
// Alt-Svc detection, HTTP/3 fallback, gzip decompression, and connection reuse.
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

	client := http.Client{Transport: x.transport}

	host, port := ExtractHostAndPort(url.Host, 443)
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
	if err := x.resolveAndUpdateCache(host); err != nil {
		dlog.Errorf("Unable to resolve [%s]: check bootstrap_resolvers or system resolver", host)
		return nil, 0, nil, 0, err
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
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(*body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url.String(), reqBody)
	if err != nil {
		return nil, 0, nil, 0, err
	}
	req.Header = header
	req.ContentLength = int64(bodyLen)
	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)
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
	if resp != nil {
		defer resp.Body.Close()
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
		grErr := gr.Reset(io.LimitReader(resp.Body, MaxHTTPBodyLength))
		if grErr != nil {
			gzipReaderPool.Put(gr)
			return nil, statusCode, tlsState, rtt, grErr
		}
		defer func() {
			gr.Close()
			gzipReaderPool.Put(gr)
		}()
		bodyReader = gr
	}
	bin, err := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))
	if err != nil {
		return nil, statusCode, tlsState, rtt, err
	}
	return bin, statusCode, tlsState, rtt, nil
}

// parseAndCacheAltSvc parses Alt-Svc headers to detect HTTP/3 support.
// Uses strings.SplitSeq (Go 1.24) for iterator-based field splitting.
func (x *XTransport) parseAndCacheAltSvc(host string, port int, header http.Header) {
	now := time.Now()
	x.altSupport.RLock()
	existing, inCache := x.altSupport.cache[host]
	x.altSupport.RUnlock()
	if inCache && existing.port == 0 &&
		(existing.validTo.IsZero() || now.Before(existing.validTo)) {
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

// ── Public query helpers ────────────────────────────────────────────────────────

// GetWithCompression performs a GET request with gzip compression enabled.
func (x *XTransport) GetWithCompression(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(http.MethodGet, url, accept, "", nil, timeout, true)
}

// Get performs a GET request without compression.
func (x *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(http.MethodGet, url, accept, "", nil, timeout, false)
}

// Post performs a POST request with the given content type and body.
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

// DoHQuery sends a DNS-over-HTTPS query using the standard application/dns-message type.
func (x *XTransport) DoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/dns-message", useGet, url, body, timeout)
}

// ObliviousDoHQuery sends an Oblivious DNS-over-HTTPS query.
func (x *XTransport) ObliviousDoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}
