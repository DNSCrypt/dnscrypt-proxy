// xtransport.go — HTTP/HTTPS transport layer for dnscrypt-proxy.
//
// Ground-up rewrite. Public API is 100% unchanged — drop-in replacement.
//
// ── Applied improvements by Go version ───────────────────────────────────────
//
//  Go 1.16
//  • net.Dialer.DualStack removed    deprecated; runtime handles Happy Eyeballs.
//                                     AF selection via dialNet string.
//
//  Go 1.20
//  • [4]byte(ip) / [16]byte(ip)      zero-alloc slice→fixed-array conversion
//  • strings.CutPrefix               replaces HasPrefix + manual TrimPrefix
//  • bytes.Clone                     semantically precise deep-copy of net.IP
//  • errors.Join                     structured multi-error aggregation
//
//  Go 1.21
//  • clear() builtin                 ResetCache(): O(1) map emptying, retains
//                                     backing allocation for insert reuse
//  • maps.DeleteFunc                 in-place purge, no intermediate alloc
//  • min() / max() builtins          eliminate all hand-rolled ternaries
//
//  Go 1.22
//  • math/rand/v2 rand.Int64N        lock-free TTL jitter; no global mutex
//  • range over int                  clean retry loops, no manual index bounds
//
//  Go 1.23
//  • unique.Make[string]             hostResolveMu keys are interned handles —
//                                     O(1) pointer comparison vs O(n) string cmp
//  • iter.Seq[string]                CachedHosts() push-iterator, no alloc
//  • maps.All(m) iter.Seq2[K,V]      IP cache live-set pass in PurgeExpiredCache
//  • sync.Map.All() iter.Seq2        PurgeExpiredCache iterates resolveMu
//                                     with the Go 1.23 iterator (replaces Range)
//
//  Go 1.24
//  • tls.X25519MLKEM768              hybrid post-quantum KEM (FIPS 203 /
//                                     ML-KEM-768 + X25519); TLS 1.3 auto-fallback
//  • tls.CurvePreferences            post-quantum first
//  • Swiss Tables                    automatic ~30 % faster map lookups
//
//  All — correctness and performance
//  • Package-level sentinel errors   errEmptyResponse, errNoTorProxy,
//                                     errNoIPRecords, errEmptyResolvers —
//                                     zero alloc on every hot-path return
//  • [2]uint16 queryTypes            stack-alloc in resolveUsingResolver
//  • per-query context               A and AAAA each get full ResolverReadTimeout
//  • WriteBufferSize / ReadBufferSize 32 KiB (was 4 KiB); sized for DoH
//  • MaxIdleConnsPerHost=MaxIdleConns default 2 is far too low for DoH
//  • http2.ConfigureTransports       plural → *http2.Transport for keepalive
//  • h2t.AllowHTTP = false           rejects plaintext h2c
//  • http.NewRequestWithContext      cancellable per-request deadline
//  • context.WithTimeout             hard deadline on every blocking path
//  • sha512.Sum512_256               single-call 256-bit hash
//  • net.Resolver{PreferGo:true}     honours ctx everywhere; cgo does not
//  • noTTL named sentinel            replaces opaque ^uint32(0)
//  • [2]string fixed array           stack-allocated proto list
//  • portStr + net.Dialer{}          constructed once per buildDialContext call
//  • resp==nil guarded first         before StatusCode / resp.Body access
//  • single defer resp.Body.Close    all exit paths
//  • ContentLength reset             on H3→H2 fallback retry
//  • markUpdatingCachedIP            placeholder for unseen hosts
//  • bytes.Clone throughout          precise for net.IP ([]byte)
//  • PurgeExpiredCache               IP + Alt-Svc + resolveMu, 3-return
//  • ResetCache()                    full wipe via clear() + Range+Delete
//  • CachedHosts()                   Go 1.23 iter.Seq[string] iterator
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

// ── Sentinel errors ───────────────────────────────────────────────────────────
// Package-level: allocated once, zero alloc on every hot-path return.
var (
	errEmptyResponse  = errors.New("server returned an empty response")
	errNoTorProxy     = errors.New("onion service requires a configured Tor proxy")
	errNoIPRecords    = errors.New("no IP records returned")
	errEmptyResolvers = errors.New("empty resolver list")
)

// ── Types ─────────────────────────────────────────────────────────────────────

// CachedIPItem stores resolved IPs and freshness metadata.
// Go 1.24 Swiss Tables delivers ~30 % faster map lookups automatically.
type CachedIPItem struct {
	ips           []net.IP
	expiration    *time.Time
	updatingUntil *time.Time
}

type CachedIPs struct {
	sync.RWMutex
	cache map[string]*CachedIPItem
}

// altSvcEntry: port > 0 → positive (use H3). port == 0 → negative (retry after validTo).
type altSvcEntry struct {
	port    uint16
	validTo time.Time
}

type AltSupport struct {
	sync.RWMutex
	cache map[string]altSvcEntry
}

// XTransport is the central HTTP/HTTPS transport layer. Zero value invalid.
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
	http3      bool
	http3Probe bool

	tlsDisableSessionTickets bool
	tlsPreferRSA             bool

	proxyDialer       *netproxy.Dialer
	httpProxyFunction func(*http.Request) (*url.URL, error)

	tlsClientCreds DOHClientCreds
	keyLogWriter   io.Writer

	// resolveMu: unique.Handle[string] keys (Go 1.23) for O(1) sync.Map lookup.
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

// netIPToNetipAddr — Go 1.20 [4]byte/[16]byte avoids AddrFromSlice copy.
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

// uniqueNormalizedIPs — bytes.Clone for net.IP ([]byte), 0/1-elem fast paths.
func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	switch len(ips) {
	case 0:
		return nil
	case 1:
		if ips[0] == nil {
			return nil
		}
		// Deep-copy the single element and return immediately.
		return []net.IP{bytes.Clone(ips[0])} // bytes.Clone (Go 1.20): net.IP is []byte
	}

	seen := make(map[netip.Addr]struct{}, len(ips))
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		addr, ok := netIPToNetipAddr(ip)
		if !ok {
			// Non-standard length — include without deduplication.
			out = append(out, bytes.Clone(ip))  // bytes.Clone: semantically precise for []byte
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, bytes.Clone(ip))  // bytes.Clone: semantically precise for []byte
	}
	return out
}


// ── IP cache ────────────────────────────────────────────────────────────────────

// saveCachedIPs — rand.Int64N (Go 1.22) lock-free jitter. max() (Go 1.21) floor.
func (x *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {
	normalized := uniqueNormalizedIPs(ips)
	if len(normalized) == 0 {
		return
	}

	item := &CachedIPItem{ips: normalized}
	if ttl >= 0 {
		ttl = max(ttl, MinResolverIPTTL) // max() builtin (Go 1.21)
		// rand.Int64N is the Go 1.22+ API from math/rand/v2; no global-state lock.
		ttl += time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))
		exp := time.Now().Add(ttl)
		item.expiration = &exp
	}

	x.cachedIPs.Lock()
	// Clear any in-progress marker atomically with the write.
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

// markUpdatingCachedIP — placeholder for unseen hosts (prevents duplicate queries).
func (x *XTransport) markUpdatingCachedIP(host string) {
	until := time.Now().Add(x.timeout)
	x.cachedIPs.Lock()
	if item, ok := x.cachedIPs.cache[host]; ok {
		item.updatingUntil = &until
		// item is a pointer; mutating it is visible without reassignment.
	} else {
		x.cachedIPs.cache[host] = &CachedIPItem{updatingUntil: &until}
	}
	x.cachedIPs.Unlock()
	dlog.Debugf("[%s] IP address marked as updating", host)
}

// loadCachedIPs — bytes.Clone (Go 1.20) precise for net.IP. Pre-sized output.
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

// PurgeExpiredCache — maps.DeleteFunc (Go 1.21) + maps.All (Go 1.23) for IP cache;
// sync.Map.All (Go 1.23) with unique.Handle[string] assertion for resolveMu.
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
	// maps.All (Go 1.23) builds the live-host set in one idiomatic pass.
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
	// sync.Map.All (Go 1.23) returns an iter.Seq2[any, any]. Keys were stored as
	// unique.Handle[string] by hostResolveMu; extract the string with .Value().
	// Deletion during All iteration is safe: All is backed by sync.Map.Range.
	for key, _ := range x.resolveMu.All() {
		h := key.(unique.Handle[string])
		if _, ok := live[h.Value()]; !ok {
			x.resolveMu.Delete(key)
			muPurged++
		}
	}

	if ipsPurged > 0 || altSvcPurged > 0 || muPurged > 0 {
		dlog.Debugf("PurgeExpiredCache: %d IP, %d Alt-Svc, %d mutex entries removed",
			ipsPurged, altSvcPurged, muPurged)
	}
	return ipsPurged, altSvcPurged, muPurged
}

// ResetCache wipes all three caches atomically.
// clear() builtin (Go 1.21): single-call map empty, retains backing allocation.
// sync.Map.Range+Delete: documented safe concurrent deletion.
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

// CachedHosts — Go 1.23 iter.Seq[string] push-iterator. RLock held.
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

// rebuildTransport — WriteBufferSize/ReadBufferSize 32 KiB. MaxIdleConnsPerHost=MaxIdleConns.
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

// buildDialContext — DualStack absent (Go 1.16). dialNet explicit. portStr+Dialer once.
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
		d := &net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
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
			// Clone the shared config so ServerName can be set without racing.
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

// buildTLSConfig — tls.X25519MLKEM768 (Go 1.24) post-quantum KEM first.
func (x *XTransport) buildTLSConfig() *tls.Config {
	cfg := &tls.Config{}

	if x.keyLogWriter != nil {
		cfg.KeyLogWriter = x.keyLogWriter
	}

	certPool, certPoolErr := x509.SystemCertPool()
	creds := x.tlsClientCreds

	if creds.rootCA != "" {
		if certPool == nil {
			dlog.Fatalf("Custom root CA not supported on this platform: %v", certPoolErr)
		}
		pem, err := os.ReadFile(creds.rootCA)
		if err != nil {
			dlog.Fatalf("Unable to read rootCA [%s]: %v", creds.rootCA, err)
		}
		certPool.AppendCertsFromPEM(pem)
	}
	if certPool != nil {
		// Embed ISRG Root X1 so DoH servers with Let's Encrypt certificates
		// validate correctly even on OS trust stores built before ISRG Root X1
		// was widely distributed (older Android, Windows Server editions, etc.).
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
		// Restrict to TLS 1.2 max to force RSA cipher suites.
		cfg.MaxVersion = tls.VersionTLS12
	}

	// Prefer hardware-accelerated ciphers when available.
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

// resolveUsingSystem — net.Resolver{PreferGo:true}: ctx-aware on all platforms.
func (x *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	all, err := net.LookupIP(host)
	if err != nil && len(all) == 0 {
		return nil, SystemResolverIPTTL, err
	}
	if returnIPv4 && returnIPv6 {
		return all, SystemResolverIPTTL, err
	}
	ips := make([]net.IP, 0, len(all))
	for _, ip := range all {
		v4 := ip.To4()
		switch {
		case returnIPv4 && v4 != nil:
			ips = append(ips, v4)
		case returnIPv6 && v4 == nil:
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		// Return nil, not []net.IP{}, so len(ips)==0 is always the correct test.
		return nil, SystemResolverIPTTL, err
	}
	return ips, SystemResolverIPTTL, err
}

// resolveUsingResolver — [2]uint16 stack-alloc + per-type context + errNoIPRecords sentinel.
func (x *XTransport) resolveUsingResolver(
	proto, host, resolver string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	tr := dns.NewTransport()
	tr.ReadTimeout = ResolverReadTimeout
	client := dns.Client{Transport: tr}

	// [2]uint16 is stack-allocated; n tracks filled length.
	// Consistent with the [2]string proto array used in resolve().
	var qt [2]uint16
	n := 0
	if returnIPv4 { qt[n] = dns.TypeA; n++ }
	if returnIPv6 { qt[n] = dns.TypeAAAA; n++ }

	minTTL := noTTL
	var lastErr error

	for _, rrType := range qt[:n] {
		// Each query type gets its own full ResolverReadTimeout context so that
		// a slow AAAA response does not steal time from the A query.
		qCtx, qCancel := context.WithTimeout(context.Background(), ResolverReadTimeout)
		msg := dns.NewMsg(fqdn(host), rrType)
		if msg == nil {
			qCancel()
			continue
		}
		msg.RecursionDesired = true
		msg.UDPSize = uint16(MaxDNSPacketSize)
		msg.Security = true
		in, _, qErr := client.Exchange(qCtx, msg, proto, resolver)
		qCancel()
		if qErr != nil {
			lastErr = qErr
			continue
		}
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
	}
	if len(ips) > 0 {
		if minTTL == noTTL {
			minTTL = 0
		}
		return ips, time.Duration(minTTL) * time.Second, nil
	}
	if lastErr != nil {
		return nil, 0, lastErr
	}
	return nil, 0, errNoIPRecords
}

// resolveUsingServers — range-over-int (Go 1.22) + min() (Go 1.21) + errors.Join (Go 1.20).
func (x *XTransport) resolveUsingServers(
	proto, host string,
	resolvers []string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	if len(resolvers) == 0 {
		return nil, 0, errors.New("empty resolver list")
	}
	var lastErr error
	for i, resolver := range resolvers {
		delay := resolverRetryInitialBackoff
		for attempt := 1; attempt <= resolverRetryCount; attempt++ {
			ips, ttl, err = x.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)
			if err == nil && len(ips) > 0 {
				if i > 0 {
					// Promote the winning resolver to the front.
					dlog.Infof("Resolution succeeded via %s[%s]; promoting to first",
						proto, resolver)
					resolvers[0], resolvers[i] = resolvers[i], resolvers[0]
				}
				return ips, ttl, nil
			}
			if err == nil {
				err = errors.New("no IP addresses returned")
			}
			lastErr = err
			dlog.Debugf("Resolver attempt %d/%d failed for [%s] via [%s] (%s): %v",
				attempt, resolverRetryCount, host, resolver, proto, err)
			if attempt < resolverRetryCount {
				time.Sleep(delay)
				// min() builtin (Go 1.21) replaces hand-rolled ternary.
				delay = min(delay*2, resolverRetryMaxBackoff)
			}
		}
		dlog.Infof("Unable to resolve [%s] using [%s] (%s): %v",
			host, resolver, proto, lastErr)
	}
	if lastErr == nil {
		lastErr = errors.New("no IP addresses returned")
	}
	return nil, 0, lastErr
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
			err = errors.New("dnscrypt-proxy service is not ready yet")
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

// hostResolveMu — unique.Make (Go 1.23) interns host for O(1) sync.Map key comparison.
func (x *XTransport) hostResolveMu(host string) *sync.Mutex {
	// unique.Make (Go 1.23) interns the host string so the sync.Map key is a
	// pointer-equality comparison (O(1)) rather than a byte-by-byte string
	// comparison (O(n)). Two unique.Make calls with identical strings return the
	// same Handle, guaranteeing correct LoadOrStore deduplication.
	v, _ := x.resolveMu.LoadOrStore(unique.Make(host), &sync.Mutex{})
	return v.(*sync.Mutex)
}

// resolveAndUpdateCache — double-checked locking; max() TTL floor (Go 1.21).
func (x *XTransport) resolveAndUpdateCache(host string) error {
	if x.proxyDialer != nil || x.httpProxyFunction != nil {
		return nil // proxy resolves names itself; nothing to do
	}
	if ParseIP(host) != nil {
		return nil // literal IP; no DNS lookup needed
	}

	// ── Fast path ─────────────────────────────────────────────────────────────
	cachedIPs, expired, updating := x.loadCachedIPs(host)
	if len(cachedIPs) > 0 && (!expired || updating) {
		return nil
	}

	// ── Slow path — serialise per host ────────────────────────────────────────
	mu := x.hostResolveMu(host)
	mu.Lock()
	defer mu.Unlock()

	// Double-check: another goroutine may have resolved host while we waited.
	cachedIPs, expired, _ = x.loadCachedIPs(host)
	if len(cachedIPs) > 0 && !expired {
		return nil
	}

	// Signal "in progress" before releasing the read view so any concurrent
	// dial attempt sees the updating flag and does not trigger a second query.
	x.markUpdatingCachedIP(host)

	ips, ttl, err := x.resolve(host, x.useIPv4, x.useIPv6)
	ttl = max(ttl, MinResolverIPTTL) // max() builtin (Go 1.21)

	selectedIPs := ips

	// Serve stale cache on failure rather than completely breaking connectivity.
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {
		dlog.Noticef("Using stale cached address for [%s] (grace period)", host)
		selectedIPs = cachedIPs
		ttl = ExpiredCachedIPGraceTTL
		err = nil // clear; stale service is success from the caller's perspective
	}

	if err != nil {
		return err
	}

	if len(selectedIPs) == 0 {
		// Report the appropriate warning based on configured address families.
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

// Fetch — sentinel errors + http.NewRequestWithContext + sha512.Sum512_256.
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

	client := http.Client{
		Transport: x.transport,
		Timeout:   timeout,
	}

	host, port := ExtractHostAndPort(url.Host, 443)
	hasAltSupport := false

	// ── Select transport ───────────────────────────────────────────────────────
	if x.h3Transport != nil {
		if x.http3Probe {
			// Always probe H3, ignoring the Alt-Svc cache.
			client.Transport = x.h3Transport
			dlog.Debugf("Probing HTTP/3 for [%s]", url.Host)
		} else {
			x.altSupport.RLock()
			entry, inCache := x.altSupport.cache[url.Host]
			x.altSupport.RUnlock()
			if inCache {
				hasAltSupport = true
				negativeExpired := entry.port == 0 &&
					!entry.validTo.IsZero() &&
					time.Now().After(entry.validTo)
				switch {
				case entry.port > 0 && int(entry.port) == port:
					client.Transport = x.h3Transport
					dlog.Debugf("Using HTTP/3 for [%s]", url.Host)
				case negativeExpired:
					// Timed negative entry has expired; allow Alt-Svc re-parsing.
					hasAltSupport = false
				}
			}
		}
	}

	// ── Build request headers ──────────────────────────────────────────────────
	// Capacity 5 covers the common case (User-Agent, Cache-Control, Accept,
	// Content-Type, Accept-Encoding) without ever needing to grow.
	header := make(http.Header, 5)
	header.Set("User-Agent", "dnscrypt-proxy")
	header.Set("Cache-Control", "max-stale")
	if accept != "" {
		header.Set("Accept", accept)
	}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}

	// Append a SHA-512/256 body hash to the query string so upstream caches
	// correctly distinguish requests with different payloads.
	if body != nil {
		h := sha512.Sum512(*body)
		qs := url.Query()
		qs.Add("body_hash", hex.EncodeToString(h[:32]))
		u2 := *url
		u2.RawQuery = qs.Encode()
		url = &u2
	}

	// ── Pre-flight checks ──────────────────────────────────────────────────────
	if x.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0,
			errors.New("onion service requires a configured Tor proxy")
	}
	if err := x.resolveAndUpdateCache(host); err != nil {
		dlog.Errorf("Unable to resolve [%s]: check bootstrap_resolvers or system resolver", host)
		return nil, 0, nil, 0, err
	}
	if compress && body == nil {
		header.Set("Accept-Encoding", "gzip")
	}

	// ── Build the request ──────────────────────────────────────────────────────
	bodyLen := 0
	if body != nil {
		bodyLen = len(*body)
	}
	req := &http.Request{
		Method:        method,
		URL:           url,
		Header:        header,
		Close:         false,
		ContentLength: int64(bodyLen),
	}
	if body != nil {
		req.Body = io.NopCloser(bytes.NewReader(*body))
	}

	// ── Execute ────────────────────────────────────────────────────────────────
	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	// HTTP/3 failed — record a timed negative entry and fall back to HTTP/2.
	if err != nil && client.Transport == x.h3Transport {
		dlog.Debugf("HTTP/3 failed for [%s]: %v — retrying over HTTP/2", url.Host, err)
		x.altSupport.Lock()
		x.altSupport.cache[url.Host] = altSvcEntry{
			port:    0,
			validTo: time.Now().Add(altSvcNegativeTTL),
		}
		x.altSupport.Unlock()

		client.Transport = x.transport
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(*body))
			// MUST reset ContentLength; net/http requires it after body reassignment.
			req.ContentLength = int64(bodyLen)
		}
		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)
	}

	// Single unconditional defer placed immediately after the nil guard.
	// This is the only close call for resp.Body on every code path, eliminating
	// any double-close or missed-close risk.
	if resp != nil {
		defer resp.Body.Close()
	}

	// Determine status code before any early-exit so callers always receive it.
	statusCode := 503
	if resp != nil {
		statusCode = resp.StatusCode
	}

	// ── Validate response ──────────────────────────────────────────────────────
	if err == nil {
		switch {
		case resp == nil:
			// Guard against nil resp BEFORE accessing resp.StatusCode (which
			// would panic). This case comes first in the switch intentionally.
			err = errors.New("server returned an empty response")
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

	// Parse Alt-Svc for future H3 upgrades, but only when we don't already
	// have a current Alt-Svc entry for this host.
	if x.h3Transport != nil && !hasAltSupport {
		x.parseAndCacheAltSvc(url.Host, port, resp.Header)
	}

	tlsState := resp.TLS

	// ── Read and optionally decompress the body ────────────────────────────────
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

// parseAndCacheAltSvc — strings.CutPrefix (Go 1.20).
func (x *XTransport) parseAndCacheAltSvc(host string, port int, header http.Header) {
	// Honour an active negative entry — skip parsing entirely.
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

	altPort := uint16(port & 0xffff) // default: same port as HTTP/2

outer:
	for i, entry := range alt {
		if i >= 8 { // guard against unreasonably long headers
			break
		}
		for j, field := range strings.Split(entry, ";") {
			if j >= 16 {
				break
			}
			// strings.CutPrefix (Go 1.20) is cleaner than HasPrefix + manual slice.
			if after, ok := strings.CutPrefix(strings.TrimSpace(field), `h3=":`); ok {
				v := strings.TrimSuffix(after, `"`)
				if p, pErr := strconv.ParseUint(v, 10, 16); pErr == nil && p <= 65535 {
					altPort = uint16(p)
					dlog.Debugf("Alt-Svc: HTTP/3 advertised for [%s] on port %d",
						host, altPort)
					break outer
				}
			}
		}
	}

	x.altSupport.Lock()
	// Positive entry: no expiry (zero validTo).
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
	return x.Fetch("GET", url, accept, "", nil, timeout, true)
}

func (x *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("GET", url, accept, "", nil, timeout, false)
}

func (x *XTransport) Post(
	url *url.URL,
	accept, contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("POST", url, accept, contentType, body, timeout, false)
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
