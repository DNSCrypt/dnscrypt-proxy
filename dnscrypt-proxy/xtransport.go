// Package main provides HTTP/HTTPS transport with DNS-over-HTTPS support.
// This implementation includes HTTP/2, HTTP/3, caching, and intelligent fallback.
//
// Go 1.26 Full Rewrite — improvements applied:
//   - netip.AddrFrom4/AddrFrom16 for zero-allocation IP→netip conversion
//   - uniqueNormalizedIPs fast-path for single-element slice
//   - resolveUsingResolver tracks minimum TTL across all RR answers
//   - A/AAAA errors tracked independently; partial success not masked
//   - markUpdatingCachedIP inserts placeholder on first-time resolution
//   - Per-host sync.Mutex (resolveMu) prevents duplicate concurrent resolutions
//   - HTTP/3 Alt-Svc negative cache carries expiry (altSvcNegativeTTL)
//   - Fetch resets ContentLength correctly on H3→H2 fallback
//   - Single unconditional defer resp.Body.Close() eliminates double-close risk
//   - buildH3DialFunc uses shared tlsClientConfig (no silent config discard)
//   - TLSHandshakeTimeout and MaxIdleConns exported as tunable constants
//   - altSvcEntry typed struct with validTo expiry field
//   - All public functions carry full godoc comments
//   - All public API signatures unchanged (drop-in replacement)
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

// hasAESGCMHardwareSupport reports whether the current CPU supports hardware-
// accelerated AES-GCM, used to order TLS cipher suites for best performance.
var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||
	(cpu.S390X.HasAES && cpu.S390X.HasAESGCM)

// ─────────────────────────────────────────── tuning constants ───────────────

const (
	// DefaultBootstrapResolver is the fallback DNS resolver used during startup
	// before the internal proxy resolver is ready.
	DefaultBootstrapResolver = "9.9.9.9:53"

	// DefaultKeepAlive is the TCP keep-alive probe interval for net.Dialer.
	DefaultKeepAlive = 5 * time.Second

	// DefaultIdleConnTimeout controls how long an idle HTTP/2 connection stays pooled.
	DefaultIdleConnTimeout = 90 * time.Second

	// DefaultTimeout is the end-to-end per-request deadline.
	DefaultTimeout = 30 * time.Second

	// ResolverReadTimeout limits how long a single DNS exchange may take.
	ResolverReadTimeout = 5 * time.Second

	// SystemResolverIPTTL is the synthetic TTL applied to OS-resolver results.
	SystemResolverIPTTL = 12 * time.Hour

	// MinResolverIPTTL is the floor below which advertised TTLs are raised.
	MinResolverIPTTL = 4 * time.Hour

	// ResolverIPTTLMaxJitter is the upper bound of random jitter added to cache TTLs.
	ResolverIPTTLMaxJitter = 15 * time.Minute

	// ExpiredCachedIPGraceTTL is how long a stale cache entry is kept when
	// re-resolution fails, to maintain connectivity during outages.
	ExpiredCachedIPGraceTTL = 15 * time.Minute

	// Resolver retry parameters use exponential back-off up to the max.
	resolverRetryCount          = 3
	resolverRetryInitialBackoff = 150 * time.Millisecond
	resolverRetryMaxBackoff     = 1 * time.Second

	// MaxIdleConns is the total connection pool size across all hosts.
	MaxIdleConns = 2000

	// MaxResponseHeaderBytes caps the size of HTTP response headers accepted.
	MaxResponseHeaderBytes = 4096

	// TLSHandshakeTimeout is the deadline for completing a TLS handshake.
	TLSHandshakeTimeout = 10 * time.Second

	// altSvcNegativeTTL is how long a failed HTTP/3 probe suppresses retries.
	// After this window the entry expires and the server is tried again.
	altSvcNegativeTTL = 10 * time.Minute
)

// ─────────────────────────────────────────────────────── types ──────────────

// CachedIPItem holds resolved IP addresses and freshness metadata.
type CachedIPItem struct {
	ips           []net.IP
	expiration    *time.Time // nil = never expires
	updatingUntil *time.Time // non-nil while a background re-resolution is running
}

// CachedIPs is a thread-safe hostname → IP cache.
type CachedIPs struct {
	sync.RWMutex
	cache map[string]*CachedIPItem
}

// altSvcEntry records an HTTP/3 Alt-Svc advertisement.
// port == 0 is a negative entry (HTTP/3 failed); validTo is non-zero for
// negative entries so they expire and allow retrying recovering servers.
type altSvcEntry struct {
	port    uint16
	validTo time.Time // zero = no expiry (positive entries never expire)
}

// AltSupport is a thread-safe cache of HTTP/3 Alt-Svc advertisements.
type AltSupport struct {
	sync.RWMutex
	cache map[string]altSvcEntry
}

// XTransport is the central HTTP(S) transport layer for dnscrypt-proxy.
// It owns an HTTP/2 and optionally an HTTP/3 transport, manages a local
// DNS-resolution cache, and exposes DoH / Oblivious-DoH query helpers.
type XTransport struct {
	transport       *http.Transport
	h3Transport     *http3.Transport
	tlsClientConfig *tls.Config // built once; shared by both transports

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

	// http3 enables the HTTP/3 transport for all outgoing requests.
	// The field is intentionally named http3 (not enableHTTP3) so that
	// config_loader.go and other callers compile without modification.
	http3      bool
	http3Probe bool

	tlsDisableSessionTickets bool
	tlsPreferRSA             bool

	proxyDialer       *netproxy.Dialer
	httpProxyFunction func(*http.Request) (*url.URL, error)

	tlsClientCreds DOHClientCreds
	keyLogWriter   io.Writer

	// resolveMu provides per-hostname serialisation so only one goroutine
	// resolves a given host at a time, preventing duplicate DNS queries.
	resolveMu sync.Map // map[string]*sync.Mutex
}

// NewXTransport returns an XTransport with safe production defaults.
func NewXTransport() *XTransport {
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
		panic("DefaultBootstrapResolver does not parse: " + err.Error())
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

// ──────────────────────────────────────────── IP helpers ────────────────────

// ParseIP parses an IP address string, stripping IPv6 bracket notation.
// Returns nil for invalid input.
func ParseIP(ipStr string) net.IP {
	ipStr = strings.TrimPrefix(ipStr, "[")
	ipStr = strings.TrimSuffix(ipStr, "]")
	return net.ParseIP(ipStr)
}

// netIPToNetipAddr converts net.IP to netip.Addr with zero allocation for the
// standard 4-byte and 16-byte forms. IPv4-mapped IPv6 addresses are unmapped
// so that 1.2.3.4 and ::ffff:1.2.3.4 deduplicate to the same key.
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

// uniqueNormalizedIPs deduplicates and deep-copies an IP slice.
// Order is preserved (first occurrence wins); nil entries are dropped.
// A fast-path avoids allocating the seen map for 0- or 1-element inputs.
func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	switch len(ips) {
	case 0:
		return nil
	case 1:
		if ips[0] == nil {
			return nil
		}
		return []net.IP{append(net.IP(nil), ips[0]...)}
	}
	seen := make(map[netip.Addr]struct{}, len(ips))
	unique := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		addr, ok := netIPToNetipAddr(ip)
		if !ok {
			unique = append(unique, append(net.IP(nil), ip...))
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		unique = append(unique, append(net.IP(nil), ip...))
	}
	return unique
}

// ─────────────────────────────────────────── IP cache ───────────────────────

// saveCachedIPs stores resolved IPs for host with the given TTL. A random
// jitter is added to spread re-resolution events. MinResolverIPTTL is enforced
// as a floor. Pass ttl < 0 for a non-expiring entry.
func (x *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {
	normalized := uniqueNormalizedIPs(ips)
	if len(normalized) == 0 {
		return
	}
	item := &CachedIPItem{ips: normalized}
	if ttl >= 0 {
		if ttl < MinResolverIPTTL {
			ttl = MinResolverIPTTL
		}
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
		dlog.Debugf("[%s] cached %d IPs (first: %s), valid for %v", host, len(normalized), normalized[0], ttl)
	}
}

// saveCachedIP is a convenience wrapper for a single IP address.
func (x *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip == nil {
		return
	}
	x.saveCachedIPs(host, []net.IP{ip}, ttl)
}

// markUpdatingCachedIP records that a background re-resolution is in progress.
// If no entry exists yet a placeholder is inserted so concurrent callers see
// "updating" rather than triggering another resolution.
func (x *XTransport) markUpdatingCachedIP(host string) {
	until := time.Now().Add(x.timeout)
	x.cachedIPs.Lock()
	item, ok := x.cachedIPs.cache[host]
	if ok {
		item.updatingUntil = &until
		x.cachedIPs.cache[host] = item
	} else {
		x.cachedIPs.cache[host] = &CachedIPItem{updatingUntil: &until}
	}
	x.cachedIPs.Unlock()
	dlog.Debugf("[%s] IP address marked as updating", host)
}

// loadCachedIPs returns a deep-copied snapshot of cached IPs and freshness flags.
func (x *XTransport) loadCachedIPs(host string) (ips []net.IP, expired, updating bool) {
	x.cachedIPs.RLock()
	item, ok := x.cachedIPs.cache[host]
	if !ok {
		x.cachedIPs.RUnlock()
		dlog.Debugf("[%s] IP address not found in the cache", host)
		return nil, false, false
	}
	if len(item.ips) > 0 {
		ips = make([]net.IP, 0, len(item.ips))
		for _, ip := range item.ips {
			if ip != nil {
				ips = append(ips, append(net.IP(nil), ip...))
			}
		}
	}
	expiration := item.expiration
	updatingUntil := item.updatingUntil
	x.cachedIPs.RUnlock()

	if expiration != nil && time.Until(*expiration) < 0 {
		expired = true
		if updatingUntil != nil && time.Until(*updatingUntil) > 0 {
			updating = true
			dlog.Debugf("[%s] cached IPs are being updated", host)
		} else {
			dlog.Debugf("[%s] cached IPs expired, not being updated yet", host)
		}
	}
	return ips, expired, updating
}

// ───────────────────────────────── transport construction ───────────────────

// rebuildTransport (re)initialises the HTTP/2 and HTTP/3 transports. Must be
// called once before the first Fetch, and again whenever TLS or proxy config
// changes.
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
		IdleConnTimeout:        DefaultIdleConnTimeout,
		TLSHandshakeTimeout:    TLSHandshakeTimeout,
		ResponseHeaderTimeout:  x.timeout,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: MaxResponseHeaderBytes,
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
	}

	x.transport = transport

	if x.http3 {
		x.h3Transport = &http3.Transport{
			DisableCompression: true,
			TLSClientConfig:    x.tlsClientConfig,
			Dial:               x.buildH3DialFunc(),
		}
	}
}

// buildDialContext returns a DialContext that consults the internal IP cache
// before dialling, trying each address in order. Falls back to raw hostname
// (OS resolver) when the cache is empty.
func (x *XTransport) buildDialContext() func(context.Context, string, string) (net.Conn, error) {
	timeout := x.timeout
	return func(ctx context.Context, network, addrStr string) (net.Conn, error) {
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

		endpoint := func(ip net.IP) string {
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					return v4.String() + ":" + strconv.Itoa(port)
				}
				return "[" + ip.String() + "]:" + strconv.Itoa(port)
			}
			if parsed := ParseIP(host); parsed != nil && parsed.To4() == nil {
				return "[" + parsed.String() + "]:" + strconv.Itoa(port)
			}
			return host + ":" + strconv.Itoa(port)
		}

		cachedIPs, _, _ := x.loadCachedIPs(host)
		targets := make([]string, 0, max(len(cachedIPs), 1))
		for _, ip := range cachedIPs {
			targets = append(targets, endpoint(ip))
		}
		if len(targets) == 0 {
			dlog.Debugf("[%s] IP not in cache, falling back to hostname dial", host)
			targets = append(targets, endpoint(nil))
		}

		var lastErr error
		for i, target := range targets {
			var conn net.Conn
			var err error
			if x.proxyDialer == nil {
				d := &net.Dialer{
					Timeout:   timeout,
					KeepAlive: x.keepAlive,
					DualStack: true,
				}
				conn, err = d.DialContext(ctx, network, target)
			} else {
				conn, err = (*x.proxyDialer).Dial(network, target)
			}
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if i < len(targets)-1 {
				dlog.Debugf("Dial attempt [%s] failed: %v", target, err)
			}
		}
		return nil, lastErr
	}
}

// buildH3DialFunc returns the QUIC dial function used by the HTTP/3 transport.
// It mirrors buildDialContext's cache-first approach over UDP sockets and
// clones the shared TLS config per-connection to set ServerName race-free.
func (x *XTransport) buildH3DialFunc() func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addrStr string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		dlog.Debugf("H3 dial: [%v]", addrStr)
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

		type udpTarget struct{ addr, network string }

		udpEndpoint := func(ip net.IP) udpTarget {
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					return udpTarget{v4.String() + ":" + strconv.Itoa(port), "udp4"}
				}
				return udpTarget{"[" + ip.String() + "]:" + strconv.Itoa(port), "udp6"}
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
			return udpTarget{addr + ":" + strconv.Itoa(port), nw}
		}

		cachedIPs, _, _ := x.loadCachedIPs(host)
		targets := make([]udpTarget, 0, max(len(cachedIPs), 1))
		for _, ip := range cachedIPs {
			targets = append(targets, udpEndpoint(ip))
		}
		if len(targets) == 0 {
			dlog.Debugf("[%s] IP not in cache for H3 dial", host)
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
			// Clone to set ServerName per-connection without a data race.
			tlsCfg := x.tlsClientConfig.Clone()
			tlsCfg.ServerName = host
			conn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
			if err != nil {
				_ = udpConn.Close()
				lastErr = err
				if i < len(targets)-1 {
					dlog.Debugf("H3: dial [%s]/%s failed: %v", t.addr, t.network, err)
				}
				continue
			}
			return conn, nil
		}
		return nil, lastErr
	}
}

// buildTLSConfig constructs a *tls.Config reflecting all user preferences.
// The result is stored on XTransport and shared between HTTP/2 and HTTP/3
// transports; callers that need per-connection mutation should Clone() it.
func (x *XTransport) buildTLSConfig() *tls.Config {
	cfg := &tls.Config{}

	if x.keyLogWriter != nil {
		cfg.KeyLogWriter = x.keyLogWriter
	}

	certPool, certPoolErr := x509.SystemCertPool()
	creds := x.tlsClientCreds

	if creds.rootCA != "" {
		if certPool == nil {
			dlog.Fatalf("Additional CAs not supported on this platform: %v", certPoolErr)
		}
		pem, err := os.ReadFile(creds.rootCA)
		if err != nil {
			dlog.Fatalf("Unable to read rootCA file [%s]: %v", creds.rootCA, err)
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
			dlog.Fatalf("Unable to use certificate [%v] (key: [%v]): %v",
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

// isrgRootX1PEM is the Let's Encrypt ISRG Root X1 certificate in PEM form.
// Embedded so DoH servers using Let's Encrypt TLS always validate, even on
// OS trust stores that predate its inclusion.
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

// ──────────────────────────────────── DNS resolution ────────────────────────

// resolveUsingSystem delegates to the OS resolver with address-family filtering.
func (x *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	ipa, err := net.LookupIP(host)
	if returnIPv4 && returnIPv6 {
		return ipa, SystemResolverIPTTL, err
	}
	ips := make([]net.IP, 0, len(ipa))
	for _, ip := range ipa {
		v4 := ip.To4()
		if returnIPv4 && v4 != nil {
			ips = append(ips, v4)
		} else if returnIPv6 && v4 == nil {
			ips = append(ips, ip)
		}
	}
	return ips, SystemResolverIPTTL, err
}

// resolveUsingResolver sends A and/or AAAA queries to a single DNS resolver.
// On partial success (e.g. A ok, AAAA NXDOMAIN) it returns whatever IPs were
// found with the minimum observed TTL and clears the error. Each query type's
// failure is tracked independently so A results are never masked by AAAA errors.
func (x *XTransport) resolveUsingResolver(
	proto, host, resolver string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	tr := dns.NewTransport()
	tr.ReadTimeout = ResolverReadTimeout
	client := dns.Client{Transport: tr}

	queryTypes := make([]uint16, 0, 2)
	if returnIPv4 {
		queryTypes = append(queryTypes, dns.TypeA)
	}
	if returnIPv6 {
		queryTypes = append(queryTypes, dns.TypeAAAA)
	}

	ctx, cancel := context.WithTimeout(context.Background(), ResolverReadTimeout)
	defer cancel()

	var minTTL uint32 = ^uint32(0)
	var lastErr error

	for _, rrType := range queryTypes {
		msg := dns.NewMsg(fqdn(host), rrType)
		if msg == nil {
			continue
		}
		msg.RecursionDesired = true
		msg.UDPSize = uint16(MaxDNSPacketSize)
		msg.Security = true

		in, _, qErr := client.Exchange(ctx, msg, proto, resolver)
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
		if minTTL == ^uint32(0) {
			minTTL = 0
		}
		return ips, time.Duration(minTTL) * time.Second, nil
	}
	if lastErr != nil {
		return nil, 0, lastErr
	}
	return nil, 0, errors.New("no records returned")
}

// resolveUsingServers tries each resolver in order with exponential back-off.
// On first success the winning resolver is promoted to index 0 (self-healing
// affinity) so subsequent calls prefer the fastest responder.
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
					dlog.Infof("Resolution succeeded with resolver %s[%s]", proto, resolver)
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
				delay = min(delay*2, resolverRetryMaxBackoff)
			}
		}
		dlog.Infof("Unable to resolve [%s] using [%s] (%s): %v", host, resolver, proto, lastErr)
	}
	if lastErr == nil {
		lastErr = errors.New("no IP addresses returned")
	}
	return nil, 0, lastErr
}

// resolve picks the best available resolution strategy in priority order:
//  1. Internal resolvers (when ignoreSystemDNS && internalResolverReady)
//  2. OS system resolver (when ignoreSystemDNS is false)
//  3. Bootstrap resolvers (fallback after any primary failure)
//  4. OS system resolver as last resort (when ignoreSystemDNS is true)
func (x *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) (ips []net.IP, ttl time.Duration, err error) {
	protos := []string{"udp", "tcp"}
	if x.mainProto == "tcp" {
		protos = []string{"tcp", "udp"}
	}

	if x.ignoreSystemDNS {
		if x.internalResolverReady {
			for _, proto := range protos {
				ips, ttl, err = x.resolveUsingServers(proto, host, x.internalResolvers, returnIPv4, returnIPv6)
				if err == nil {
					return ips, ttl, nil
				}
			}
		} else {
			err = errors.New("dnscrypt-proxy service is not usable yet")
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
		ips, ttl, err = x.resolveUsingServers(proto, host, x.bootstrapResolvers, returnIPv4, returnIPv6)
		if err == nil {
			return ips, ttl, nil
		}
	}

	if x.ignoreSystemDNS {
		dlog.Noticef("Bootstrap resolvers failed — falling back to system resolver for [%s]", host)
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)
	}
	return ips, ttl, err
}

// hostResolveMu returns the per-host mutex used to serialise concurrent
// resolutions for the same hostname, creating it if necessary.
func (x *XTransport) hostResolveMu(host string) *sync.Mutex {
	v, _ := x.resolveMu.LoadOrStore(host, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// resolveAndUpdateCache resolves host if the cache is empty or expired and
// stores the result. Concurrent callers for the same host serialise on a
// per-host mutex to prevent duplicate DNS queries. No-op when a proxy handles
// name resolution or host is an IP literal.
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

	// Re-check after acquiring the lock; another goroutine may have resolved.
	cachedIPs, expired, _ = x.loadCachedIPs(host)
	if len(cachedIPs) > 0 && !expired {
		return nil
	}

	x.markUpdatingCachedIP(host)

	ips, ttl, err := x.resolve(host, x.useIPv4, x.useIPv6)
	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}

	selectedIPs := ips
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {
		dlog.Noticef("Using stale cached address for [%v] (grace period)", host)
		selectedIPs = cachedIPs
		ttl = ExpiredCachedIPGraceTTL
		err = nil
	}

	if err != nil {
		return err
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

// ─────────────────────────────────────────── HTTP API ───────────────────────

// Fetch performs a single HTTP request. When body is non-nil it is sent as the
// request payload. When compress is true the request advertises gzip encoding
// and the response is transparently decompressed.
//
// Returns (responseBody, statusCode, tlsState, rtt, error).
// Non-2xx responses are returned as errors.
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

	if x.h3Transport != nil {
		if x.http3Probe {
			client.Transport = x.h3Transport
			dlog.Debugf("Probing HTTP/3 for [%s]", url.Host)
		} else {
			x.altSupport.RLock()
			entry, inCache := x.altSupport.cache[url.Host]
			x.altSupport.RUnlock()
			if inCache {
				hasAltSupport = true
				negativeExpired := entry.port == 0 && !entry.validTo.IsZero() && time.Now().After(entry.validTo)
				if entry.port > 0 && int(entry.port) == port {
					client.Transport = x.h3Transport
					dlog.Debugf("Using HTTP/3 for [%s]", url.Host)
				} else if negativeExpired {
					// Expired negative entry — allow Alt-Svc re-parsing.
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
		h := sha512.Sum512(*body)
		qs := url.Query()
		qs.Add("body_hash", hex.EncodeToString(h[:32]))
		u2 := *url
		u2.RawQuery = qs.Encode()
		url = &u2
	}

	if x.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0, errors.New("onion service is not reachable without Tor")
	}

	if err := x.resolveAndUpdateCache(host); err != nil {
		dlog.Errorf("Unable to resolve [%v]: ensure system resolver works or set bootstrap_resolvers", host)
		return nil, 0, nil, 0, err
	}

	if compress && body == nil {
		header.Set("Accept-Encoding", "gzip")
	}

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

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	// HTTP/3 failed — record a timed negative cache entry and retry over HTTP/2.
	if err != nil && client.Transport == x.h3Transport {
		dlog.Debugf("HTTP/3 failed for [%s]: %v — falling back to HTTP/2", url.Host, err)
		x.altSupport.Lock()
		x.altSupport.cache[url.Host] = altSvcEntry{port: 0, validTo: time.Now().Add(altSvcNegativeTTL)}
		x.altSupport.Unlock()

		client.Transport = x.transport
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(*body))
			req.ContentLength = int64(bodyLen) // must be reset for HTTP/2
		}
		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)
	}

	// Single unconditional defer prevents double-close on any code path.
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
			err = errors.New("webserver returned an empty response")
		case resp.StatusCode < 200 || resp.StatusCode > 299:
			err = errors.New(resp.Status)
		}
	} else {
		dlog.Debugf("HTTP client error: %v — closing idle connections", err)
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

// parseAndCacheAltSvc inspects the Alt-Svc header and updates the altSupport
// cache with the HTTP/3 port for host. Negative entries carry an expiry so
// servers that recover are re-discovered after altSvcNegativeTTL.
func (x *XTransport) parseAndCacheAltSvc(host string, port int, header http.Header) {
	x.altSupport.RLock()
	existing, inCache := x.altSupport.cache[host]
	x.altSupport.RUnlock()
	if inCache && existing.port == 0 && (existing.validTo.IsZero() || time.Now().Before(existing.validTo)) {
		dlog.Debugf("Alt-Svc: skipping [%s] — negative cache still valid", host)
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
		for j, field := range strings.Split(entry, ";") {
			if j >= 16 {
				break
			}
			if after, ok := strings.CutPrefix(strings.TrimSpace(field), `h3=":"`); ok {
				v := strings.TrimSuffix(after, `"`)
				if p, parseErr := strconv.ParseUint(v, 10, 16); parseErr == nil && p <= 65535 {
					altPort = uint16(p)
					dlog.Debugf("HTTP/3 advertised for [%s] on port %d", host, altPort)
					break outer
				}
			}
		}
	}

	x.altSupport.Lock()
	x.altSupport.cache[host] = altSvcEntry{port: altPort}
	dlog.Debugf("Cached altPort %d for [%s]", altPort, host)
	x.altSupport.Unlock()
}

// ──────────────────────────── public query helpers ──────────────────────────

// GetWithCompression performs a GET with transparent gzip decompression.
func (x *XTransport) GetWithCompression(url *url.URL, accept string, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("GET", url, accept, "", nil, timeout, true)
}

// Get performs a plain GET request.
func (x *XTransport) Get(url *url.URL, accept string, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("GET", url, accept, "", nil, timeout, false)
}

// Post performs a POST request.
func (x *XTransport) Post(url *url.URL, accept, contentType string, body *[]byte, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("POST", url, accept, contentType, body, timeout, false)
}

// dohLikeQuery dispatches a GET or POST DNS-over-HTTPS-style query.
// GET encodes the payload as base64url per RFC 8484 §4.1.
func (x *XTransport) dohLikeQuery(dataType string, useGet bool, url *url.URL, body []byte, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if useGet {
		qs := url.Query()
		qs.Add("dns", base64.RawURLEncoding.EncodeToString(body))
		u2 := *url
		u2.RawQuery = qs.Encode()
		return x.Get(&u2, dataType, timeout)
	}
	return x.Post(url, dataType, dataType, &body, timeout)
}

// DoHQuery sends a DNS-over-HTTPS query (RFC 8484).
func (x *XTransport) DoHQuery(useGet bool, url *url.URL, body []byte, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/dns-message", useGet, url, body, timeout)
}

// ObliviousDoHQuery sends an Oblivious DNS-over-HTTPS query (RFC 9230).
func (x *XTransport) ObliviousDoHQuery(useGet bool, url *url.URL, body []byte, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}
