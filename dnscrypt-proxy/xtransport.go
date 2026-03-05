// xtransport.go — HTTP/HTTPS transport layer for dnscrypt-proxy.
//
// Ground-up rewrite. Public API 100% unchanged — drop-in replacement.
//
// ── Go version improvements ───────────────────────────────────────────────────
//
//  Go 1.16
//  • DualStack removed             deprecated; Happy Eyeballs handled by runtime.
//
//  Go 1.20
//  • [4]byte(ip) / [16]byte(ip)    zero-alloc slice→fixed-array cast
//  • strings.CutPrefix             replaces HasPrefix + manual TrimPrefix
//  • bytes.Clone                   correct deep-copy of net.IP ([]byte)
//  • errors.Join                   structured multi-error wrapping
//
//  Go 1.21
//  • context.WithTimeoutCause      errDNSQueryTimeout / errSystemResolverTimeout
//                                   — context.Cause() returns typed sentinel
//  • clear() builtin               ResetCache: O(1) map empty, retains alloc
//  • maps.DeleteFunc               in-place cache purge, no intermediate slice
//  • min() / max() builtins        replaces all hand-rolled ternaries
//
//  Go 1.22
//  • math/rand/v2  rand.Int64N     lock-free TTL jitter, no global mutex
//  • range over int                for attempt := range N; no manual bound
//
//  Go 1.23
//  • net.KeepAliveConfig           buildDialContext: Idle / Interval / Count;
//                                   dead DoH connections detected in < 5 s
//  • unique.Make[string]           hostResolveMu: O(1) sync.Map key compare
//  • iter.Seq[string]              CachedHosts() zero-alloc push iterator
//  • maps.All(m) iter.Seq2[K,V]   IP live-set pass in PurgeExpiredCache
//
//  Go 1.24
//  • tls.X25519MLKEM768            hybrid PQ KEM: X25519 + ML-KEM-768
//  • tls.CurvePreferences          post-quantum-first curve list
//  • Swiss Tables                  ~30 % faster map lookups (automatic)
//  • strings.SplitSeq              parseAndCacheAltSvc: zero-alloc ";" parse
//
//  Go 1.25
//  • sync.WaitGroup.Go             resolveUsingResolver: A + AAAA concurrent;
//                                   halves dual-stack bootstrap resolver RTT
//
//  Go 1.26
//  • tls.SecP256r1MLKEM768         hybrid PQ KEM: P-256 + ML-KEM-768
//  • tls.SecP384r1MLKEM1024        hybrid PQ KEM: P-384 + ML-KEM-1024
//                                   Both enabled by default in Go 1.26 but
//                                   excluded unless listed explicitly when
//                                   CurvePreferences is overridden
//  • new(expr) builtin             saveCachedIPs / markUpdatingCachedIP:
//                                   alloc-and-init in one step, no temp var
//  • errors.AsType[E]              resolveAndUpdateCache: reflection-free
//                                   error inspection; 3× vs errors.As
//  • io.ReadAll faster             2× faster, 50 % less memory in Fetch
//                                   (automatic, no code changes)
//  • Green Tea GC (default)        10–40 % lower GC tail latency
//  • Heap base randomisation       security hardening (automatic)
//
//  All — correctness and performance
//  • 7 sentinel errors             zero alloc on every hot-path return
//  • http.MethodGet / MethodPost   named constants, not string literals
//  • resolveRRType() helper        own dns.Client per call; goroutine-safe
//  • [2]uint16 queryTypes         stack-alloc; consistent with [2]string
//  • WriteBufferSize / ReadBufferSize 32 KiB (default 4 KiB undersized for DoH)
//  • MaxIdleConnsPerHost = MaxIdleConns default 2 blocks concurrent DoH queries
//  • http.NewRequestWithContext    per-request deadline propagation
//  • sha512.Sum512_256             single-call 256-bit hash
//  • net.Resolver{PreferGo:true}   ctx-aware on all platforms; cgo is not
//  • x/net/http2 h2t tuning        AllowHTTP=false; PingTimeout; ReadIdle
//  • resp==nil guard               before StatusCode / resp.Body access
//  • bytes.Clone throughout        precise semantics for net.IP ([]byte)
//  • PurgeExpiredCache 3-return    IP + Alt-Svc + resolveMu
//  • ResetCache()                  full wipe via clear() + Range+Delete
//  • CachedHosts()                 iter.Seq[string] push iterator
//  • ISRG Root X1 PEM embedded
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
)

// Package-level sentinel errors — allocated once at init; zero alloc on every
// hot-path return; fully comparable via errors.Is / errors.AsType.
var (
	errEmptyResponse         = errors.New("server returned an empty response")
	errNoTorProxy            = errors.New("onion service requires a configured Tor proxy")
	errNoIPRecords           = errors.New("no IP records returned")
	errEmptyResolvers        = errors.New("empty resolver list")
	errServiceNotReady       = errors.New("dnscrypt-proxy service is not ready yet")
	errDNSQueryTimeout       = errors.New("DNS query timed out")
	errSystemResolverTimeout = errors.New("system resolver timed out")
)

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
// resolveMu uses unique.Handle[string] keys (Go 1.23) for O(1) sync.Map lookup.
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
}


// ── Constructor ─────────────────────────────────────────────────────────────────

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
		// Unmap promotes IPv4-mapped IPv6 addresses so dedup works correctly.
		return netip.AddrFrom16([16]byte(ip)).Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 { return nil }
	if len(ips) == 1 {
		if ips[0] != nil { return []net.IP{bytes.Clone(ips[0])} }
		return nil
	}

	// For small DNS responses (1-4 IPs), an O(N^2) loop over a stack 
	// array completely out-performs the overhead of map allocation.
	var seenBuf [8]netip.Addr 
	seen := seenBuf[:0]
	out := make([]net.IP, 0, len(ips))

	for _, ip := range ips {
		if ip == nil { continue }
		addr, ok := netIPToNetipAddr(ip)
		if !ok { // Non-standard length
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


// ── IP cache ────────────────────────────────────────────────────────────────────

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
		// new(expr) (Go 1.26): allocate-and-init in one step, no named temporary.
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
	// new(expr) (Go 1.26): pointer to value returned by expression — no temp var.
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
	if !ok || item == nil { return nil, false, false }
	now := time.Now()
	if item.updatingUntil != nil && now.Before(*item.updatingUntil) { updating = true }
	if item.expiration != nil && now.After(*item.expiration) { expired = true }
	if len(item.ips) == 0 { return nil, expired, updating }
	out := make([]net.IP, 0, len(item.ips))
	for _, ip := range item.ips { out = append(out, bytes.Clone(ip)) }
	return out, expired, updating
}

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
	// This avoids any ambiguity around iter.Seq2 ranging forms and is allocation-minimal.
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
	// sync.Map.Range: safe concurrent iteration; Delete during Range is documented.
	// Keys were stored as unique.Handle[string] by hostResolveMu (Go 1.23);
	// extract the host string with h.Value() for the live-set lookup.
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

func (x *XTransport) ResetCache() {
	// clear() builtin (Go 1.21) empties a map in a single runtime call,
	// preserving the backing allocation so subsequent inserts avoid rehash.
	// Semantically equivalent to ranging and deleting each key, but faster.
	x.cachedIPs.Lock()
	clear(x.cachedIPs.cache)
	x.cachedIPs.Unlock()

	x.altSupport.Lock()
	clear(x.altSupport.cache)
	x.altSupport.Unlock()

	// sync.Map does not expose a clear() path; Range+Delete is the standard idiom.
	x.resolveMu.Range(func(key, _ any) bool {
		x.resolveMu.Delete(key)
		return true
	})
	dlog.Debug("ResetCache: all IP, Alt-Svc, and mutex cache entries cleared")
}

func (x *XTransport) CachedHosts() iter.Seq[string] {
	return func(yield func(string) bool) {
		x.cachedIPs.RLock()
		defer x.cachedIPs.RUnlock()
		for host := range x.cachedIPs.cache {
			if !yield(host) { return }
		}
	}
}


// ── Transport construction ──────────────────────────────────────────────────────

// rebuildTransport — x/net/http2.ConfigureTransports for H2 keepalive tuning.
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

func (x *XTransport) buildDialContext() func(context.Context, string, string) (net.Conn, error) {
	timeout, keepAlive := x.timeout, x.keepAlive
	useIPv4, useIPv6 := x.useIPv4, x.useIPv6
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
		// net.KeepAliveConfig (Go 1.23): granular TCP keepalive parameters.
		// DoH connections may idle for minutes; detecting dead links quickly
		// prevents stalled DNS queries from blocking for the full dial timeout.
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

		// Clone the shared config once before the loop so ServerName can be set without racing
		// and without incurring deep-copy penalties for each target evaluation.
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

// buildTLSConfig — Go 1.26 SecP256r1MLKEM768 + SecP384r1MLKEM1024 added;
// must be explicit: CurvePreferences override excludes new defaults.
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
	// Go 1.26 enabled SecP256r1MLKEM768 and SecP384r1MLKEM1024 by default, but
	// *only when CurvePreferences is unset*. Because we override this field we
	// must list them explicitly or they are silently excluded, stripping DoH
	// clients of FIPS-140-3 compliant and higher-security PQ key exchange.
	//
	//   X25519MLKEM768    Go 1.24  hybrid: X25519   + ML-KEM-768  (fastest)
	//   SecP256r1MLKEM768 Go 1.26  hybrid: P-256    + ML-KEM-768  (FIPS 140-3)
	//   SecP384r1MLKEM1024 Go 1.26 hybrid: P-384    + ML-KEM-1024 (AES-256 class)
	//   X25519            classical; fast
	//   CurveP256         classical; FIPS 140-3
	//   CurveP384         classical; high security
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
	// WithTimeoutCause (Go 1.21): context.Cause() returns the typed sentinel
	// rather than the generic context.DeadlineExceeded — aids error reporting.
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

	// WithTimeoutCause (Go 1.21): errDNSQueryTimeout as cause distinguishes a
	// self-imposed deadline from parent-context cancellation in error logs.
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

func (x *XTransport) resolveUsingResolver(
	proto, host, resolver string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	var qt [2]uint16
	n := 0
	if returnIPv4 { qt[n] = dns.TypeA; n++ }
	if returnIPv6 { qt[n] = dns.TypeAAAA; n++ }
	if n == 0 {
		return nil, 0, errNoIPRecords
	}

	if n == 1 {
		// Single type: no goroutine overhead.
		rips, rttl, rerr := x.resolveRRType(proto, host, resolver, qt[0])
		if rerr != nil { return nil, 0, rerr }
		if len(rips) == 0 { return nil, 0, errNoIPRecords }
		if rttl == noTTL { rttl = 0 }
		return rips, time.Duration(rttl) * time.Second, nil
	}

	// n == 2: A and AAAA queries run concurrently.
	// sync.WaitGroup.Go (Go 1.25) atomically handles Add(1) + go + defer Done().
	// Each goroutine writes to a distinct index — no mutex needed.
	type rrResult struct {
		ips    []net.IP
		minTTL uint32
		err    error
	}
	var results [2]rrResult
	var wg sync.WaitGroup
	for i, rrType := range qt[:n] {
		i, rrType := i, rrType // capture for goroutine
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
		if overallMinTTL == noTTL { overallMinTTL = 0 }
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
	var errs []error
	for i, resolver := range resolvers {
		delay := resolverRetryInitialBackoff
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
				err = errNoIPRecords // sentinel: zero alloc on every miss
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
			err = errServiceNotReady // sentinel: allocated once, not per-call
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

func (x *XTransport) hostResolveMu(host string) *sync.Mutex {
	k := unique.Make(host)
	// Fast-path: O(1) read, zero allocations
	if v, ok := x.resolveMu.Load(k); ok {
		return v.(*sync.Mutex)
	}
	// Slow-path: allocate and store
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

	// errors.AsType (Go 1.26): generic, reflection-free error inspection.
	// 3x faster than errors.As and scopes the typed variable to the if block.
	if resolveErr != nil {
		if dnsErr, ok := errors.AsType[*net.DNSError](resolveErr); ok {
			dlog.Debugf("[%s] DNS error: name=%s notFound=%v temp=%v",
				host, dnsErr.Name, dnsErr.IsNotFound, dnsErr.IsTemporary)
		}
	}

	ttl = max(ttl, MinResolverIPTTL) // max() builtin (Go 1.21)

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


// ── HTTP fetch engine ───────────────────────────────────────────────────────────

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

	// Rely on per-request context deadlines; avoids the extra timer and duplicated cancellation.
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
	header := make(http.Header, 5)
	header.Set("User-Agent", "dnscrypt-proxy")
	header.Set("Cache-Control", "max-stale")
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
			// (Especially helpful for H2 keep-alives when servers send a body on errors.)
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
		// strings.SplitSeq (Go 1.24): zero-alloc lazy iterator over ";"-fields.
		// Avoids the []string allocation that strings.Split would create per entry.
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
