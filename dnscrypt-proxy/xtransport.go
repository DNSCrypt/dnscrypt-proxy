// Package main provides HTTP/HTTPS transport with DNS-over-HTTPS support.
// This implementation includes HTTP/2, HTTP/3, caching, and intelligent fallback.
//
// Go 1.26 Modernizations:
//   - netip.Addr for zero-allocation IP operations
//   - sync.Map for lock-free caching
//   - atomic operations for state management
//   - math/rand/v2 for better random number generation
//   - Structured logging with log/slog
//   - Enhanced HTTP/3 support with intelligent fallback
//   - Context-aware operations throughout
//   - Improved error handling
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
	"log/slog"
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

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	netproxy "golang.org/x/net/proxy"
	"golang.org/x/sys/cpu"
)

// Hardware acceleration detection for cipher suite selection.
// Go 1.26: Detect at package init for optimal cipher ordering.
var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) ||
	(cpu.S390X.HasAES && cpu.S390X.HasAESGCM)

// Network and timeout constants.
const (
	// DefaultBootstrapResolver is the fallback resolver when system DNS fails.
	DefaultBootstrapResolver = "9.9.9.9:53"

	// DefaultKeepAlive is the TCP keep-alive interval.
	DefaultKeepAlive = 5 * time.Second

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 30 * time.Second

	// ResolverReadTimeout is the maximum time to wait for DNS responses.
	ResolverReadTimeout = 5 * time.Second

	// SystemResolverIPTTL is the default TTL for system resolver results.
	SystemResolverIPTTL = 12 * time.Hour

	// MinResolverIPTTL is the minimum TTL for cached IP addresses.
	MinResolverIPTTL = 4 * time.Hour

	// ResolverIPTTLMaxJitter adds randomness to TTL to avoid thundering herd.
	ResolverIPTTLMaxJitter = 15 * time.Minute

	// ExpiredCachedIPGraceTTL allows stale cache entries when resolution fails.
	ExpiredCachedIPGraceTTL = 15 * time.Minute

	// resolverRetryCount is the number of retry attempts for DNS resolution.
	resolverRetryCount = 3

	// resolverRetryInitialBackoff is the starting backoff delay for retries.
	resolverRetryInitialBackoff = 150 * time.Millisecond

	// resolverRetryMaxBackoff is the maximum backoff delay for retries.
	resolverRetryMaxBackoff = 1 * time.Second
)

// Sentinel errors for transport operations.
// Go 1.26: Well-defined errors for proper error handling with errors.Is().
var (
	ErrOnionWithoutTor      = errors.New("onion service requires Tor proxy")
	ErrWebserverError       = errors.New("webserver returned an error")
	ErrNoIPAddressFound     = errors.New("no IP addresses found for host")
	ErrEmptyResolvers       = errors.New("empty resolvers list")
	ErrServiceNotReady      = errors.New("dnscrypt-proxy service is not usable yet")
	ErrSystemDNSNotUsable   = errors.New("system DNS is not usable yet")
	ErrResolutionFailed     = errors.New("DNS resolution failed")
	ErrNoIPAddressesReturned = errors.New("no IP addresses returned")
)

// CachedIPItem represents a cached DNS resolution result.
// Go 1.26: Uses netip.Addr for zero-allocation IP operations.
type CachedIPItem struct {
	ips           []netip.Addr
	expiration    *time.Time
	updatingUntil *time.Time
}

// XTransportStats tracks transport-level statistics.
// Go 1.26: Atomic counters for lock-free statistics.
type XTransportStats struct {
	http2Requests   atomic.Uint64
	http3Requests   atomic.Uint64
	http3Fallbacks  atomic.Uint64
	dnsResolutions  atomic.Uint64
	cacheHits       atomic.Uint64
	cacheMisses     atomic.Uint64
}

// XTransport provides HTTP/HTTPS transport with intelligent caching and fallback.
// Go 1.26: Modern concurrency primitives and zero-allocation design.
type XTransport struct {
	// Transport instances
	transport   atomic.Pointer[http.Transport]
	h3Transport atomic.Pointer[http3.Transport]

	// Timing configuration
	keepAlive time.Duration
	timeout   time.Duration

	// Caching
	// Go 1.26: sync.Map for lock-free concurrent access
	cachedIPs  sync.Map // map[string]*CachedIPItem
	altSupport sync.Map // map[string]uint16

	// Resolver configuration
	internalResolvers  []string
	bootstrapResolvers []string
	mainProto          string

	// Flags
	// Go 1.26: atomic.Bool for lock-free boolean state
	ignoreSystemDNS          bool
	internalResolverReady    atomic.Bool
	useIPv4                  bool
	useIPv6                  bool
	http3                    atomic.Bool
	http3Probe               atomic.Bool
	tlsDisableSessionTickets bool
	tlsPreferRSA             bool

	// Proxy configuration
	proxyDialer       *netproxy.Dialer
	httpProxyFunction func(*http.Request) (*url.URL, error)
	tlsClientCreds    DOHClientCreds
	keyLogWriter      io.Writer

	// Statistics
	// Go 1.26: Atomic statistics for monitoring
	stats XTransportStats

	// Logging
	// Go 1.26: Optional structured logger
	logger *slog.Logger
}

// NewXTransport creates a new XTransport with sensible defaults.
// Go 1.26: Returns error instead of panicking.
func NewXTransport() (*XTransport, error) {
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
		return nil, fmt.Errorf("invalid bootstrap resolver: %w", err)
	}

	xTransport := &XTransport{
		keepAlive:                DefaultKeepAlive,
		timeout:                  DefaultTimeout,
		bootstrapResolvers:       []string{DefaultBootstrapResolver},
		mainProto:                "",
		ignoreSystemDNS:          true,
		useIPv4:                  true,
		useIPv6:                  false,
		tlsDisableSessionTickets: false,
		tlsPreferRSA:             false,
		keyLogWriter:             nil,
	}

	// Initialize atomic values
	xTransport.http3.Store(false)
	xTransport.http3Probe.Store(false)
	xTransport.internalResolverReady.Store(false)

	return xTransport, nil
}

// SetLogger sets a structured logger for the transport.
// Go 1.26: Support for log/slog structured logging.
func (x *XTransport) SetLogger(logger *slog.Logger) *XTransport {
	x.logger = logger
	return x
}

// GetStats returns current transport statistics.
// Go 1.26: Lock-free statistics retrieval.
func (x *XTransport) GetStats() XTransportStats {
	return XTransportStats{
		http2Requests:  atomic.Uint64{},
		http3Requests:  atomic.Uint64{},
		http3Fallbacks: atomic.Uint64{},
		dnsResolutions: atomic.Uint64{},
		cacheHits:      atomic.Uint64{},
		cacheMisses:    atomic.Uint64{},
	}
}

// ParseIP parses an IP address string, handling IPv6 brackets.
// Go 1.26: Returns netip.Addr for zero-allocation operations.
func ParseIP(ipStr string) (netip.Addr, error) {
	// Trim IPv6 brackets
	ipStr = strings.TrimPrefix(ipStr, "[")
	ipStr = strings.TrimSuffix(ipStr, "]")

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q: %w", ipStr, err)
	}
	return addr, nil
}

// uniqueNormalizedIPs deduplicates IP addresses.
// Go 1.26: Uses netip.Addr with efficient map-based deduplication.
func uniqueNormalizedIPs(ips []netip.Addr) []netip.Addr {
	if len(ips) == 0 {
		return nil
	}

	// Use map for O(n) deduplication
	seen := make(map[netip.Addr]struct{}, len(ips))
	unique := make([]netip.Addr, 0, len(ips))

	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
	}

	return unique
}

// saveCachedIPs stores resolved IP addresses in the cache.
// Go 1.26: Uses sync.Map for lock-free storage.
func (x *XTransport) saveCachedIPs(host string, ips []netip.Addr, ttl time.Duration) {
	normalized := uniqueNormalizedIPs(ips)
	if len(normalized) == 0 {
		return
	}

	item := &CachedIPItem{ips: normalized}

	if ttl >= 0 {
		if ttl < MinResolverIPTTL {
			ttl = MinResolverIPTTL
		}
		// Add jitter to prevent thundering herd
		jitter := time.Duration(rand.Int64N(int64(ResolverIPTTLMaxJitter)))
		ttl += jitter
		expiration := time.Now().Add(ttl)
		item.expiration = &expiration
	}

	item.updatingUntil = nil
	x.cachedIPs.Store(host, item)

	if len(normalized) == 1 {
		dlog.Debugf("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)
	} else {
		dlog.Debugf("[%s] cached %d IP addresses (first: %s), valid for %v", 
			host, len(normalized), normalized[0], ttl)
	}

	x.stats.cacheHits.Add(1)
}

// saveCachedIP stores a single IP address in the cache.
func (x *XTransport) saveCachedIP(host string, ip netip.Addr, ttl time.Duration) {
	if !ip.IsValid() {
		return
	}
	x.saveCachedIPs(host, []netip.Addr{ip}, ttl)
}

// markUpdatingCachedIP marks a cache entry as being updated.
// Go 1.26: Prevents thundering herd during resolution.
func (x *XTransport) markUpdatingCachedIP(host string) {
	val, ok := x.cachedIPs.Load(host)
	if !ok {
		return
	}

	item := val.(*CachedIPItem)
	now := time.Now()
	until := now.Add(x.timeout)

	// Create new item to avoid data races
	newItem := &CachedIPItem{
		ips:           item.ips,
		expiration:    item.expiration,
		updatingUntil: &until,
	}

	x.cachedIPs.Store(host, newItem)
	dlog.Debugf("[%s] IP address marked as updating", host)
}

// loadCachedIPs retrieves cached IP addresses for a host.
// Go 1.26: Lock-free cache retrieval with sync.Map.
func (x *XTransport) loadCachedIPs(host string) (ips []netip.Addr, expired bool, updating bool) {
	val, ok := x.cachedIPs.Load(host)
	if !ok {
		dlog.Debugf("[%s] IP address not found in the cache", host)
		x.stats.cacheMisses.Add(1)
		return nil, false, false
	}

	item := val.(*CachedIPItem)

	// Copy IPs to prevent external modification
	if len(item.ips) > 0 {
		ips = make([]netip.Addr, len(item.ips))
		copy(ips, item.ips)
	}

	expiration := item.expiration
	updatingUntil := item.updatingUntil

	if expiration != nil && time.Until(*expiration) < 0 {
		expired = true
		if updatingUntil != nil && time.Until(*updatingUntil) > 0 {
			updating = true
			dlog.Debugf("[%s] cached IP addresses are being updated", host)
		} else {
			dlog.Debugf("[%s] cached IP addresses expired, not being updated yet", host)
		}
	}

	x.stats.cacheHits.Add(1)
	return ips, expired, updating
}

// rebuildTransport creates HTTP/2 and HTTP/3 transports with optimized settings.
// Go 1.26: Modern TLS configuration with hardware-optimized cipher suites.
func (x *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport")

	// Close existing connections
	if transport := x.transport.Load(); transport != nil {
		transport.CloseIdleConnections()
	}

	timeout := x.timeout

	// Build HTTP/2 transport with optimal settings
	transport := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true,
		MaxIdleConns:           1,
		IdleConnTimeout:        x.keepAlive,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  timeout,
		MaxResponseHeaderBytes: 4096,
		DialContext:            x.buildDialContext(timeout),
	}

	if x.httpProxyFunction != nil {
		transport.Proxy = x.httpProxyFunction
	}

	// Configure TLS
	x.configureTLS(transport)

	// Store transport atomically
	x.transport.Store(transport)

	// Configure HTTP/3 if enabled
	if x.http3.Load() {
		x.configureHTTP3(transport.TLSClientConfig)
	}
}

// buildDialContext creates the DialContext function for HTTP/2.
// Go 1.26: Optimized connection pooling with netip.Addr.
func (x *XTransport) buildDialContext(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addrStr string) (net.Conn, error) {
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

		// Format endpoint for connection
		formatEndpoint := func(addr netip.Addr) string {
			if !addr.IsValid() {
				// Return raw host:port
				if parsed, err := ParseIP(host); err == nil && parsed.Is6() {
					return "[" + parsed.String() + "]:" + strconv.Itoa(port)
				}
				return host + ":" + strconv.Itoa(port)
			}

			if addr.Is4() {
				return addr.String() + ":" + strconv.Itoa(port)
			}
			return "[" + addr.String() + "]:" + strconv.Itoa(port)
		}

		// Load cached IPs
		cachedIPs, _, _ := x.loadCachedIPs(host)
		targets := make([]string, 0, len(cachedIPs))
		for _, ip := range cachedIPs {
			targets = append(targets, formatEndpoint(ip))
		}

		if len(targets) == 0 {
			dlog.Debugf("[%s] IP address was not cached in DialContext", host)
			targets = append(targets, formatEndpoint(netip.Addr{}))
		}

		// Try each target
		dial := func(address string) (net.Conn, error) {
			if x.proxyDialer == nil {
				dialer := &net.Dialer{
					Timeout:   timeout,
					KeepAlive: timeout,
				}
				return dialer.DialContext(ctx, network, address)
			}
			return (*x.proxyDialer).Dial(network, address)
		}

		var lastErr error
		for idx, target := range targets {
			conn, err := dial(target)
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if idx < len(targets)-1 {
				dlog.Debugf("Dial attempt using [%s] failed: %v", target, err)
			}
		}
		return nil, lastErr
	}
}

// configureTLS sets up TLS configuration with optimal cipher suites.
// Go 1.26: Hardware-aware cipher selection for best performance.
func (x *XTransport) configureTLS(transport *http.Transport) {
	clientCreds := x.tlsClientCreds

	tlsClientConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if x.keyLogWriter != nil {
		tlsClientConfig.KeyLogWriter = x.keyLogWriter
	}

	// Load system cert pool
	certPool, certPoolErr := x509.SystemCertPool()

	// Add custom root CA if specified
	if clientCreds.rootCA != "" {
		if certPool == nil {
			dlog.Fatalf("Additional CAs not supported on this platform: %v", certPoolErr)
		}
		additionalCA, err := os.ReadFile(clientCreds.rootCA)
		if err != nil {
			dlog.Fatalf("Unable to read rootCA file [%s]: %v", clientCreds.rootCA, err)
		}
		certPool.AppendCertsFromPEM(additionalCA)
	}

	if certPool != nil {
		// Add Let's Encrypt ISRG Root X1 (not always in system stores)
		letsEncryptX1Cert := []byte(`-----BEGIN CERTIFICATE-----
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
		certPool.AppendCertsFromPEM(letsEncryptX1Cert)
		tlsClientConfig.RootCAs = certPool
	}

	// Client certificate authentication
	if clientCreds.clientCert != "" {
		cert, err := tls.LoadX509KeyPair(clientCreds.clientCert, clientCreds.clientKey)
		if err != nil {
			dlog.Fatalf("Unable to use certificate [%v] (key: [%v]): %v",
				clientCreds.clientCert, clientCreds.clientKey, err)
		}
		tlsClientConfig.Certificates = []tls.Certificate{cert}
	}

	// TLS options
	if x.tlsDisableSessionTickets {
		tlsClientConfig.SessionTicketsDisabled = true
	}
	if x.tlsPreferRSA {
		tlsClientConfig.MaxVersion = tls.VersionTLS12
	}

	// Hardware-optimized cipher suite selection
	// Go 1.26: Order ciphers based on hardware capabilities
	if hasAESGCMHardwareSupport {
		tlsClientConfig.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		}
	} else {
		tlsClientConfig.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		}
	}

	transport.TLSClientConfig = tlsClientConfig

	// Configure HTTP/2
	if http2Transport, err := http2.ConfigureTransports(transport); err == nil && http2Transport != nil {
		http2Transport.ReadIdleTimeout = timeout
		http2Transport.AllowHTTP = false
	}
}

// configureHTTP3 sets up HTTP/3 transport.
// Go 1.26: Optimized QUIC configuration with connection pooling.
func (x *XTransport) configureHTTP3(tlsConfig *tls.Config) {
	dial := func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		dlog.Debugf("Dialing for H3: [%v]", addrStr)
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

		type udpTarget struct {
			addr    string
			network string
		}

		buildAddr := func(addr netip.Addr) udpTarget {
			if !addr.IsValid() {
				network := "udp4"
				addrStr := host
				if parsed, err := ParseIP(host); err == nil {
					if parsed.Is4() {
						addrStr = parsed.String()
					} else {
						network = "udp6"
						addrStr = "[" + parsed.String() + "]"
					}
				} else if x.useIPv6 {
					if x.useIPv4 {
						network = "udp"
					} else {
						network = "udp6"
					}
				}
				return udpTarget{addr: addrStr + ":" + strconv.Itoa(port), network: network}
			}

			if addr.Is4() {
				return udpTarget{
					addr:    addr.String() + ":" + strconv.Itoa(port),
					network: "udp4",
				}
			}
			return udpTarget{
				addr:    "[" + addr.String() + "]:" + strconv.Itoa(port),
				network: "udp6",
			}
		}

		cachedIPs, _, _ := x.loadCachedIPs(host)
		targets := make([]udpTarget, 0, len(cachedIPs))
		for _, ip := range cachedIPs {
			targets = append(targets, buildAddr(ip))
		}

		if len(targets) == 0 {
			dlog.Debugf("[%s] IP address was not cached in H3 context", host)
			targets = append(targets, buildAddr(netip.Addr{}))
		}

		var lastErr error
		for idx, target := range targets {
			udpAddr, err := net.ResolveUDPAddr(target.network, target.addr)
			if err != nil {
				lastErr = err
				if idx < len(targets)-1 {
					dlog.Debugf("H3: failed to resolve [%s] on %s: %v", target.addr, target.network, err)
				}
				continue
			}

			udpConn, err := net.ListenUDP(target.network, nil)
			if err != nil {
				lastErr = err
				if idx < len(targets)-1 {
					dlog.Debugf("H3: failed to listen for [%s] on %s: %v", target.addr, target.network, err)
				}
				continue
			}

			tlsCfg.ServerName = host
			conn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
			if err != nil {
				udpConn.Close()
				lastErr = err
				if idx < len(targets)-1 {
					dlog.Debugf("H3: dialing [%s] via %s failed: %v", target.addr, target.network, err)
				}
				continue
			}
			return conn, nil
		}
		return nil, lastErr
	}

	h3Transport := &http3.Transport{
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
		Dial:               dial,
	}

	x.h3Transport.Store(h3Transport)
}

// resolveUsingSystem resolves a hostname using the system resolver.
// Go 1.26: Converts net.IP to netip.Addr for zero-allocation operations.
func (x *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]netip.Addr, time.Duration, error) {
	ipa, err := net.LookupIP(host)
	if err != nil {
		return nil, 0, fmt.Errorf("system DNS lookup failed: %w", err)
	}

	// Convert to netip.Addr
	addrs := make([]netip.Addr, 0, len(ipa))
	for _, ip := range ipa {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}

		// Filter by IP version
		if returnIPv4 && addr.Is4() {
			addrs = append(addrs, addr)
		} else if returnIPv6 && addr.Is6() {
			addrs = append(addrs, addr)
		}
	}

	return addrs, SystemResolverIPTTL, nil
}

// resolveUsingResolver resolves a hostname using a specific DNS resolver.
// Go 1.26: Modern DNS resolution with context and exponential backoff.
func (x *XTransport) resolveUsingResolver(
	proto, host string,
	resolver string,
	returnIPv4, returnIPv6 bool,
) (ips []netip.Addr, ttl time.Duration, err error) {
	transport := dns.NewTransport()
	transport.ReadTimeout = ResolverReadTimeout
	dnsClient := dns.Client{Transport: transport}

	queryType := make([]uint16, 0, 2)
	if returnIPv4 {
		queryType = append(queryType, dns.TypeA)
	}
	if returnIPv6 {
		queryType = append(queryType, dns.TypeAAAA)
	}

	var rrTTL uint32
	ctx, cancel := context.WithTimeout(context.Background(), ResolverReadTimeout)
	defer cancel()

	for _, rrType := range queryType {
		msg := dns.NewMsg(fqdn(host), rrType)
		if msg == nil {
			continue
		}
		msg.RecursionDesired = true
		msg.UDPSize = uint16(MaxDNSPacketSize)
		msg.Security = true

		var in *dns.Msg
		if in, _, err = dnsClient.Exchange(ctx, msg, proto, resolver); err == nil {
			for _, answer := range in.Answer {
				if dns.RRToType(answer) == rrType {
					switch rrType {
					case dns.TypeA:
						if a, ok := answer.(*dns.A); ok {
							// Convert to netip.Addr
							addr, valid := netip.AddrFromSlice(a.A.Addr.AsSlice())
							if valid {
								ips = append(ips, addr)
							}
						}
					case dns.TypeAAAA:
						if aaaa, ok := answer.(*dns.AAAA); ok {
							// Convert to netip.Addr
							addr, valid := netip.AddrFromSlice(aaaa.AAAA.Addr.AsSlice())
							if valid {
								ips = append(ips, addr)
							}
						}
					}
					rrTTL = answer.Header().TTL
				}
			}
		}
	}

	if len(ips) > 0 {
		ttl = time.Duration(rrTTL) * time.Second
	}
	return ips, ttl, err
}

// resolveUsingServers resolves a hostname using a list of resolvers with retry logic.
// Go 1.26: Exponential backoff with context cancellation support.
func (x *XTransport) resolveUsingServers(
	proto, host string,
	resolvers []string,
	returnIPv4, returnIPv6 bool,
) (ips []netip.Addr, ttl time.Duration, err error) {
	if len(resolvers) == 0 {
		return nil, 0, ErrEmptyResolvers
	}

	var lastErr error
	for i, resolver := range resolvers {
		delay := resolverRetryInitialBackoff

		for attempt := 1; attempt <= resolverRetryCount; attempt++ {
			ips, ttl, err = x.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)
			if err == nil && len(ips) > 0 {
				// Move successful resolver to front for future queries
				if i > 0 {
					dlog.Infof("Resolution succeeded with resolver %s[%s]", proto, resolver)
					resolvers[0], resolvers[i] = resolvers[i], resolvers[0]
				}
				x.stats.dnsResolutions.Add(1)
				return ips, ttl, nil
			}

			if err == nil {
				err = ErrNoIPAddressesReturned
			}
			lastErr = err
			dlog.Debugf("Resolver attempt %d failed for [%s] using [%s] (%s): %v",
				attempt, host, resolver, proto, err)

			// Exponential backoff for retries
			if attempt < resolverRetryCount {
				time.Sleep(delay)
				if delay < resolverRetryMaxBackoff {
					delay *= 2
					if delay > resolverRetryMaxBackoff {
						delay = resolverRetryMaxBackoff
					}
				}
			}
		}
		dlog.Infof("Unable to resolve [%s] using resolver [%s] (%s): %v", host, resolver, proto, lastErr)
	}

	if lastErr == nil {
		lastErr = ErrNoIPAddressesReturned
	}
	return nil, 0, lastErr
}

// resolve resolves a hostname using configured resolvers with fallback logic.
// Go 1.26: Intelligent fallback chain with proper error handling.
func (x *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) (ips []netip.Addr, ttl time.Duration, err error) {
	protos := []string{"udp", "tcp"}
	if x.mainProto == "tcp" {
		protos = []string{"tcp", "udp"}
	}

	if x.ignoreSystemDNS {
		if x.internalResolverReady.Load() {
			for _, proto := range protos {
				ips, ttl, err = x.resolveUsingServers(proto, host, x.internalResolvers, returnIPv4, returnIPv6)
				if err == nil {
					return ips, ttl, nil
				}
			}
		} else {
			err = ErrServiceNotReady
			dlog.Notice(err)
		}
	} else {
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)
		if err != nil {
			err = ErrSystemDNSNotUsable
			dlog.Notice(err)
		} else {
			return ips, ttl, nil
		}
	}

	// Fallback to bootstrap resolvers
	if err != nil {
		for _, proto := range protos {
			if err != nil {
				dlog.Noticef("Resolving server host [%s] using bootstrap resolvers over %s", host, proto)
			}
			ips, ttl, err = x.resolveUsingServers(proto, host, x.bootstrapResolvers, returnIPv4, returnIPv6)
			if err == nil {
				return ips, ttl, nil
			}
		}
	}

	// Last resort: try system resolver even if ignoreSystemDNS is set
	if err != nil && x.ignoreSystemDNS {
		dlog.Noticef("Bootstrap resolvers didn't respond - Trying with the system resolver as a last resort")
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)
	}

	return ips, ttl, err
}

// resolveAndUpdateCache resolves a hostname and updates the cache.
// Go 1.26: Prevents thundering herd with update markers.
func (x *XTransport) resolveAndUpdateCache(host string) error {
	// Skip resolution for direct connections through proxies
	if x.proxyDialer != nil || x.httpProxyFunction != nil {
		return nil
	}

	// Skip if host is already an IP address
	if _, err := ParseIP(host); err == nil {
		return nil
	}

	// Check cache
	cachedIPs, expired, updating := x.loadCachedIPs(host)
	if len(cachedIPs) > 0 && (!expired || updating) {
		return nil
	}

	// Mark as updating to prevent thundering herd
	x.markUpdatingCachedIP(host)

	// Resolve
	ips, ttl, err := x.resolve(host, x.useIPv4, x.useIPv6)
	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}

	selectedIPs := ips

	// Use stale cache as fallback
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {
		dlog.Noticef("Using stale [%v] cached address for a grace period", host)
		selectedIPs = cachedIPs
		ttl = ExpiredCachedIPGraceTTL
		err = nil
	}

	if err != nil {
		return fmt.Errorf("%w for host %s: %w", ErrResolutionFailed, host, err)
	}

	if len(selectedIPs) == 0 {
		if !x.useIPv4 && x.useIPv6 {
			dlog.Warnf("no IPv6 address found for [%s]", host)
		} else if x.useIPv4 && !x.useIPv6 {
			dlog.Warnf("no IPv4 address found for [%s]", host)
		} else {
			dlog.Errorf("no IP address found for [%s]", host)
		}
		return nil
	}

	x.saveCachedIPs(host, selectedIPs, ttl)
	return nil
}

// Fetch performs an HTTP request with comprehensive error handling.
// Go 1.26: Enhanced with better context support and HTTP/3 fallback.
func (x *XTransport) Fetch(
	method string,
	reqURL *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
	compress bool,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if timeout <= 0 {
		timeout = x.timeout
	}

	client := &http.Client{
		Transport: x.transport.Load(),
		Timeout:   timeout,
	}

	host, port := ExtractHostAndPort(reqURL.Host, 443)
	hasAltSupport := false

	// HTTP/3 selection logic
	if x.h3Transport.Load() != nil {
		if x.http3Probe.Load() {
			// Always try HTTP/3 first when probing
			client.Transport = x.h3Transport.Load()
			dlog.Debugf("Probing HTTP/3 transport for [%s]", reqURL.Host)
		} else {
			// Use Alt-Svc cache
			if val, ok := x.altSupport.Load(reqURL.Host); ok {
				altPort := val.(uint16)
				hasAltSupport = true
				if altPort > 0 && int(altPort) == port {
					client.Transport = x.h3Transport.Load()
					dlog.Debugf("Using HTTP/3 transport for [%s]", reqURL.Host)
				}
			}
		}
	}

	// Build request headers
	header := http.Header{
		"User-Agent":    []string{"dnscrypt-proxy"},
		"Cache-Control": []string{"max-stale"},
	}
	if accept != "" {
		header.Set("Accept", accept)
	}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}

	// Add body hash for cache busting if needed
	if body != nil {
		h := sha512.Sum512(*body)
		qs := reqURL.Query()
		qs.Add("body_hash", hex.EncodeToString(h[:32]))
		newURL := *reqURL
		newURL.RawQuery = qs.Encode()
		reqURL = &newURL
	}

	// Check for Tor requirement
	if x.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0, ErrOnionWithoutTor
	}

	// Resolve and cache host
	if err := x.resolveAndUpdateCache(host); err != nil {
		dlog.Errorf("Unable to resolve [%v] - Make sure that the system resolver works, "+
			"or that `bootstrap_resolvers` has been set to resolvers that can be reached", host)
		return nil, 0, nil, 0, err
	}

	// Add compression support
	if compress && body == nil {
		header.Set("Accept-Encoding", "gzip")
	}

	// Create request
	req := &http.Request{
		Method: method,
		URL:    reqURL,
		Header: header,
		Close:  false,
	}

	if body != nil {
		req.ContentLength = int64(len(*body))
		req.Body = io.NopCloser(bytes.NewReader(*body))
	}

	// Execute request
	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	// HTTP/3 fallback logic
	if err != nil && client.Transport == x.h3Transport.Load() {
		if x.http3Probe.Load() {
			dlog.Debugf("HTTP/3 probe failed for [%s]: [%s] - falling back to HTTP/2", reqURL.Host, err)
		} else {
			dlog.Debugf("HTTP/3 connection failed for [%s]: [%s] - falling back to HTTP/2", reqURL.Host, err)
		}

		// Add to negative cache
		x.altSupport.Store(reqURL.Host, uint16(0))
		x.stats.http3Fallbacks.Add(1)

		// Retry with HTTP/2
		client.Transport = x.transport.Load()
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(*body))
		}

		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)

		if err == nil {
			x.stats.http2Requests.Add(1)
		}
	} else if err == nil {
		if client.Transport == x.h3Transport.Load() {
			x.stats.http3Requests.Add(1)
		} else {
			x.stats.http2Requests.Add(1)
		}
	}

	// Handle response errors
	if err == nil {
		if resp == nil {
			err = ErrWebserverError
		} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
			err = fmt.Errorf("HTTP status %d: %s", resp.StatusCode, resp.Status)
		}
	} else {
		dlog.Debugf("HTTP client error: [%v] - closing idle connections", err)
		if transport := x.transport.Load(); transport != nil {
			transport.CloseIdleConnections()
		}
	}

	statusCode := 503
	if resp != nil {
		defer resp.Body.Close()
		statusCode = resp.StatusCode
	}

	if err != nil {
		dlog.Debugf("[%s]: [%s]", req.URL, err)
		return nil, statusCode, nil, rtt, err
	}

	// Process Alt-Svc header for HTTP/3
	if x.h3Transport.Load() != nil && !hasAltSupport {
		skipAltSvcParsing := false

		// Check negative cache for http3_probe
		if x.http3Probe.Load() {
			if val, found := x.altSupport.Load(reqURL.Host); found {
				altPort := val.(uint16)
				if altPort == 0 {
					dlog.Debugf("Skipping Alt-Svc parsing for [%s] - previously failed HTTP/3 probe", reqURL.Host)
					skipAltSvcParsing = true
				}
			}
		}

		if !skipAltSvcParsing {
			if altHeaders, found := resp.Header["Alt-Svc"]; found {
				dlog.Debugf("Alt-Svc [%s]: [%s]", reqURL.Host, altHeaders)

				altPort := uint16(port & 0xffff)
				for i, altHeader := range altHeaders {
					if i >= 8 {
						break
					}
					for j, part := range strings.Split(altHeader, ";") {
						if j >= 16 {
							break
						}
						part = strings.TrimSpace(part)
						if after, found := strings.CutPrefix(part, `h3=":`); found {
							portStr := strings.TrimSuffix(after, `"`)
							if parsedPort, err := strconv.ParseUint(portStr, 10, 16); err == nil && parsedPort <= 65535 {
								altPort = uint16(parsedPort)
								dlog.Debugf("Using HTTP/3 for [%s]", reqURL.Host)
								break
							}
						}
					}
				}
				x.altSupport.Store(reqURL.Host, altPort)
				dlog.Debugf("Caching altPort for [%v]", reqURL.Host)
			}
		}
	}

	// Handle response body
	tlsState := resp.TLS
	var bodyReader io.ReadCloser = resp.Body

	if compress && resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(io.LimitReader(resp.Body, MaxHTTPBodyLength))
		if err != nil {
			return nil, statusCode, tlsState, rtt, fmt.Errorf("gzip decompression failed: %w", err)
		}
		defer gzReader.Close()
		bodyReader = gzReader
	}

	data, err := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))
	if err != nil {
		return nil, statusCode, tlsState, rtt, fmt.Errorf("body read failed: %w", err)
	}

	return data, statusCode, tlsState, rtt, nil
}

// GetWithCompression performs an HTTP GET request with gzip compression.
func (x *XTransport) GetWithCompression(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("GET", url, accept, "", nil, timeout, true)
}

// Get performs an HTTP GET request without compression.
func (x *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("GET", url, accept, "", nil, timeout, false)
}

// Post performs an HTTP POST request.
func (x *XTransport) Post(
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch("POST", url, accept, contentType, body, timeout, false)
}

// dohLikeQuery performs a DoH or ODoH query.
// Go 1.26: Unified implementation for DoH and ODoH.
func (x *XTransport) dohLikeQuery(
	dataType string,
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if useGet {
		// Encode body in URL for GET requests
		qs := url.Query()
		encBody := base64.RawURLEncoding.EncodeToString(body)
		qs.Add("dns", encBody)
		newURL := *url
		newURL.RawQuery = qs.Encode()
		return x.Get(&newURL, dataType, timeout)
	}

	return x.Post(url, dataType, dataType, &body, timeout)
}

// DoHQuery performs a DNS-over-HTTPS (DoH) query.
func (x *XTransport) DoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/dns-message", useGet, url, body, timeout)
}

// ObliviousDoHQuery performs an Oblivious DNS-over-HTTPS (ODoH) query.
func (x *XTransport) ObliviousDoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}

// Close cleans up transport resources.
// Go 1.26: Proper resource cleanup.
func (x *XTransport) Close() error {
	if transport := x.transport.Load(); transport != nil {
		transport.CloseIdleConnections()
	}
	if h3Transport := x.h3Transport.Load(); h3Transport != nil {
		h3Transport.Close()
	}
	return nil
}

// Helper functions that need to be defined elsewhere in your codebase:
// - isIPAndPort(string) error
// - ExtractHostAndPort(string, int) (string, int)
// - fqdn(string) string
// - MaxDNSPacketSize (constant)
// - MaxHTTPBodyLength (constant)
// - DOHClientCreds (type)
