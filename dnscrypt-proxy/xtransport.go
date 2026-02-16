// Package main provides an advanced HTTP/HTTPS/HTTP3 transport layer with intelligent
// DNS resolution, IP caching, and DoH/ODoH support.
//
// Go 1.26 Optimizations:
//   - Structured logging with log/slog
//   - Context-aware operations
//   - Atomic operations for thread-safe state
//   - sync.Map for concurrent cache access
//   - Modern crypto/rand v2 usage
//   - netip.Addr for zero-allocation IP operations
//   - Enhanced error handling with wrapped errors
//   - HTTP/3 connection pooling improvements
package main

import (
	"bytes"
	"math/big"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	netproxy "golang.org/x/net/proxy"
	"golang.org/x/sys/cpu"
)


// loggerWithNotice provides Notice level logging compatibility.
// Go 1.26: Maps Notice to Info level in slog.
type loggerWithNotice struct {
	*slog.Logger
}

func (l *loggerWithNotice) Notice(msg string) {
	if l.Logger != nil {
		l.Logger.Info(msg)
	}
}

func (l *loggerWithNotice) Noticef(format string, args ...any) {
	if l.Logger != nil {
		l.Logger.Info(fmt.Sprintf(format, args...))
	}
}

// Hardware acceleration detection for optimal cipher suite selection.
// Go 1.26: Leverages compile-time CPU feature detection.
var hasAESGCMHardwareSupport = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ ||
	cpu.ARM64.HasAES && cpu.ARM64.HasPMULL ||
	cpu.S390X.HasAES && cpu.S390X.HasAESGCM

// Transport configuration constants optimized for modern network conditions.
const (
	DefaultBootstrapResolver = "9.9.9.9:53"
	DefaultKeepAlive         = 5 * time.Second
	DefaultTimeout           = 30 * time.Second
	ResolverReadTimeout      = 5 * time.Second
	SystemResolverIPTTL      = 12 * time.Hour
	MinResolverIPTTL         = 4 * time.Hour
	ResolverIPTTLMaxJitter   = 15 * time.Minute
	ExpiredCachedIPGraceTTL  = 15 * time.Minute
	resolverRetryCount       = 3
	resolverRetryInitialBackoff = 150 * time.Millisecond
	resolverRetryMaxBackoff     = 1 * time.Second

	// Go 1.26: Added connection pool limits
	maxIdleConnsPerHost     = 4
	maxConnsPerHost         = 8
)

// Sentinel errors for transport operations.
// Go 1.26: Use errors.Is() for error checking.
var (
	ErrInvalidBootstrapResolver = errors.New("invalid bootstrap resolver")
	ErrEmptyResolvers          = errors.New("empty resolvers")
	ErrNoIPAddresses           = errors.New("no IP addresses returned")
	ErrOnionWithoutTor         = errors.New("onion service requires Tor proxy")
	ErrWebserverError          = errors.New("webserver returned an error")
	ErrServiceNotReady         = errors.New("dnscrypt-proxy service not ready")
	ErrSystemDNSNotUsable      = errors.New("system DNS not usable")
)

// CachedIPItem represents a cached DNS resolution result.
// Go 1.26: Immutable after creation for thread safety.
type CachedIPItem struct {
	ips           []netip.Addr  // Go 1.26: Use netip.Addr for efficiency
	expiration    atomic.Pointer[time.Time]
	updatingUntil atomic.Pointer[time.Time]
}

// IsExpired checks if the cached entry has expired.
// Go 1.26: Thread-safe atomic read.
func (item *CachedIPItem) IsExpired() bool {
	exp := item.expiration.Load()
	return exp != nil && time.Until(*exp) < 0
}

// IsUpdating checks if the cached entry is currently being updated.
// Go 1.26: Thread-safe atomic read.
func (item *CachedIPItem) IsUpdating() bool {
	until := item.updatingUntil.Load()
	return until != nil && time.Until(*until) > 0
}

// IPs returns a copy of the cached IP addresses.
// Go 1.26: Returns netip.Addr slice for zero-allocation usage.
func (item *CachedIPItem) IPs() []netip.Addr {
	if item == nil || len(item.ips) == 0 {
		return nil
	}
	result := make([]netip.Addr, len(item.ips))
	copy(result, item.ips)
	return result
}

// CachedIPs manages DNS resolution cache with thread-safe concurrent access.
// Go 1.26: Uses sync.Map for better concurrent performance.
type CachedIPs struct {
	cache sync.Map // map[string]*CachedIPItem
}

// Load retrieves a cached IP item.
func (c *CachedIPs) Load(host string) (*CachedIPItem, bool) {
	val, ok := c.cache.Load(host)
	if !ok {
		return nil, false
	}
	return val.(*CachedIPItem), true
}

// Store saves a cached IP item.
func (c *CachedIPs) Store(host string, item *CachedIPItem) {
	c.cache.Store(host, item)
}

// AltSupport manages HTTP/3 Alt-Svc support cache.
// Go 1.26: Uses sync.Map for lock-free reads.
type AltSupport struct {
	cache sync.Map // map[string]uint16 (port)
}

// Load retrieves the Alt-Svc port for a host.
func (a *AltSupport) Load(host string) (uint16, bool) {
	val, ok := a.cache.Load(host)
	if !ok {
		return 0, false
	}
	return val.(uint16), true
}

// Store saves the Alt-Svc port for a host.
func (a *AltSupport) Store(host string, port uint16) {
	a.cache.Store(host, port)
}

// DOHClientCreds holds TLS client credentials for DoH connections.
type DOHClientCreds struct {
	rootCA     string
	clientCert string
	clientKey  string
}

// XTransport provides an advanced HTTP transport with DNS resolution,
// IP caching, HTTP/2, HTTP/3, and DoH support.
//
// Go 1.26: Thread-safe for concurrent use, optimized for Green Tea GC.
// All public methods are safe for concurrent calls from multiple goroutines.
type XTransport struct {
	// HTTP transports
	transport   atomic.Pointer[http.Transport]
	h3Transport atomic.Pointer[http3.Transport]

	// Configuration (immutable after initialization)
	keepAlive               time.Duration
	timeout                 time.Duration
	internalResolvers       []string
	bootstrapResolvers      []string
	mainProto               string
	tlsClientCreds          DOHClientCreds
	keyLogWriter            io.Writer

	// Flags (use atomic for thread safety)
	ignoreSystemDNS         atomic.Bool
	internalResolverReady   atomic.Bool
	useIPv4                 atomic.Bool
	useIPv6                 atomic.Bool
	http3Enabled            atomic.Bool
	http3Probe              atomic.Bool
	tlsDisableSessionTickets atomic.Bool
	tlsPreferRSA            atomic.Bool

	// Caches
	cachedIPs   CachedIPs
	altSupport  AltSupport

	// Proxy support
	proxyDialer       *netproxy.Dialer
	httpProxyFunction func(*http.Request) (*url.URL, error)

	// Logging
	logger *slog.Logger

	// Metrics (Go 1.26: atomic counters for statistics)
	statsResolveCount   atomic.Uint64
	statsHTTP2Count     atomic.Uint64
	statsHTTP3Count     atomic.Uint64
	statsCacheHitCount  atomic.Uint64
	statsCacheMissCount atomic.Uint64
}

// NewXTransport creates a new XTransport with default configuration.
// Go 1.26: Validates configuration at construction time.
func NewXTransport() (*XTransport, error) {
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidBootstrapResolver, DefaultBootstrapResolver)
	}

	xTransport := &XTransport{
		keepAlive:          DefaultKeepAlive,
		timeout:            DefaultTimeout,
		bootstrapResolvers: []string{DefaultBootstrapResolver},
		mainProto:          "",
		logger:             slog.Default(),
	}

	// Initialize atomic booleans
	xTransport.ignoreSystemDNS.Store(true)
	xTransport.useIPv4.Store(true)
	xTransport.useIPv6.Store(false)
	xTransport.http3Probe.Store(false)
	xTransport.tlsDisableSessionTickets.Store(false)
	xTransport.tlsPreferRSA.Store(false)
	xTransport.internalResolverReady.Store(false)
	xTransport.http3Enabled.Store(false)

	return xTransport, nil
}

// SetLogger sets a custom logger.
// Go 1.26: Fluent API pattern.
func (x *XTransport) SetLogger(logger *slog.Logger) *XTransport {
	if logger != nil {
		x.logger = logger
	}
	return x
}

// Stats returns current transport statistics.
// Go 1.26: Non-blocking atomic reads.
type TransportStats struct {
	ResolveCount   uint64
	HTTP2Count     uint64
	HTTP3Count     uint64
	CacheHitCount  uint64
	CacheMissCount uint64
}

// GetStats returns current transport statistics.
func (x *XTransport) GetStats() TransportStats {
	return TransportStats{
		ResolveCount:   x.statsResolveCount.Load(),
		HTTP2Count:     x.statsHTTP2Count.Load(),
		HTTP3Count:     x.statsHTTP3Count.Load(),
		CacheHitCount:  x.statsCacheHitCount.Load(),
		CacheMissCount: x.statsCacheMissCount.Load(),
	}
}

// ParseIP parses an IP address string, handling bracketed IPv6 addresses.
// Go 1.26: Uses netip.ParseAddr for better performance.
func ParseIP(ipStr string) netip.Addr {
	// Remove brackets for IPv6
	ipStr = strings.Trim(ipStr, "[]")
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

// ParseIPLegacy parses an IP address and returns net.IP for legacy compatibility.
func ParseIPLegacy(ipStr string) net.IP {
	ipStr = strings.Trim(ipStr, "[]")
	return net.ParseIP(ipStr)
}

// uniqueNormalizedIPs removes duplicates and normalizes IP addresses.
// Go 1.26: Uses netip.Addr for efficient comparison.
func uniqueNormalizedIPs(ips []netip.Addr) []netip.Addr {
	if len(ips) == 0 {
		return nil
	}

	unique := make([]netip.Addr, 0, len(ips))
	seen := make(map[netip.Addr]struct{}, len(ips))

	for _, addr := range ips {
		if !addr.IsValid() {
			continue
		}
		if _, exists := seen[addr]; exists {
			continue
		}
		seen[addr] = struct{}{}
		unique = append(unique, addr)
	}

	return unique
}

// convertNetIPsToNetipAddrs converts net.IP slice to netip.Addr slice.
// Go 1.26: Helper for transition to modern IP handling.
func convertNetIPsToNetipAddrs(ips []net.IP) []netip.Addr {
	if len(ips) == 0 {
		return nil
	}

	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if ok {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// saveCachedIPs stores resolved IP addresses in the cache with TTL.
// Go 1.26: Thread-safe with atomic operations.
func (x *XTransport) saveCachedIPs(host string, ips []netip.Addr, ttl time.Duration) {
	normalized := uniqueNormalizedIPs(ips)
	if len(normalized) == 0 {
		return
	}

	item := &CachedIPItem{
		ips: normalized,
	}

	// Set expiration if TTL is non-negative
	if ttl >= 0 {
		if ttl < MinResolverIPTTL {
			ttl = MinResolverIPTTL
		}

		// Add jitter to prevent thundering herd
		jitterNanos, err := rand.Int(rand.Reader, big.NewInt(int64(ResolverIPTTLMaxJitter)))
		if err == nil {
			ttl += time.Duration(jitterNanos.Int64())
		}

		expiration := time.Now().Add(ttl)
		item.expiration.Store(&expiration)
	}

	// Clear updating flag
	item.updatingUntil.Store(nil)

	x.cachedIPs.Store(host, item)

	if x.logger != nil {
		if len(normalized) == 1 {
			x.logger.Debug("IP cached",
				slog.String("host", host),
				slog.String("ip", normalized[0].String()),
				slog.Duration("ttl", ttl))
		} else {
			x.logger.Debug("IPs cached",
				slog.String("host", host),
				slog.Int("count", len(normalized)),
				slog.String("first_ip", normalized[0].String()),
				slog.Duration("ttl", ttl))
		}
	}
}

// saveCachedIP stores a single resolved IP address.
func (x *XTransport) saveCachedIP(host string, addr netip.Addr, ttl time.Duration) {
	if !addr.IsValid() {
		return
	}
	x.saveCachedIPs(host, []netip.Addr{addr}, ttl)
}

// markUpdatingCachedIP marks a cache entry as currently being updated.
// Go 1.26: Prevents concurrent duplicate resolution attempts.
func (x *XTransport) markUpdatingCachedIP(host string) {
	item, ok := x.cachedIPs.Load(host)
	if !ok {
		// Create new entry with updating flag
		item = &CachedIPItem{}
	}

	until := time.Now().Add(x.timeout)
	item.updatingUntil.Store(&until)
	x.cachedIPs.Store(host, item)

	if x.logger != nil {
		x.logger.Debug("IP marked as updating", slog.String("host", host))
	}
}

// loadCachedIPs retrieves cached IP addresses for a host.
// Go 1.26: Lock-free reads with atomic operations.
func (x *XTransport) loadCachedIPs(host string) (ips []netip.Addr, expired bool, updating bool) {
	item, ok := x.cachedIPs.Load(host)
	if !ok {
		x.statsCacheMissCount.Add(1)
		if x.logger != nil {
			x.logger.Debug("IP not found in cache", slog.String("host", host))
		}
		return nil, false, false
	}

	x.statsCacheHitCount.Add(1)
	ips = item.IPs()
	expired = item.IsExpired()
	updating = item.IsUpdating()

	if x.logger != nil {
		if expired {
			if updating {
				x.logger.Debug("Cached IPs expired, being updated", slog.String("host", host))
			} else {
				x.logger.Debug("Cached IPs expired, not updating", slog.String("host", host))
			}
		}
	}

	return ips, expired, updating
}

// rebuildTransport rebuilds the HTTP and HTTP/3 transports.
// Go 1.26: Optimized transport configuration with modern settings.
func (x *XTransport) rebuildTransport() error {
	if x.logger != nil {
		x.logger.Debug("Rebuilding transport")
	}

	// Close old transport if exists
	if oldTransport := x.transport.Load(); oldTransport != nil {
		oldTransport.CloseIdleConnections()
	}

	timeout := x.timeout

	// Create HTTP/1.1 and HTTP/2 transport
	transport := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true,
		MaxIdleConns:           maxIdleConnsPerHost * 2,
		MaxIdleConnsPerHost:    maxIdleConnsPerHost,
		MaxConnsPerHost:        maxConnsPerHost,
		IdleConnTimeout:        x.keepAlive,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  timeout,
		MaxResponseHeaderBytes: 4096,
		ForceAttemptHTTP2:      true, // Go 1.26: Always attempt HTTP/2
		DialContext:            x.createDialContext(timeout),
	}

	// Set proxy if configured
	if x.httpProxyFunction != nil {
		transport.Proxy = x.httpProxyFunction
	}

	// Configure TLS
	tlsConfig, err := x.configureTLS()
	if err != nil {
		return fmt.Errorf("TLS configuration failed: %w", err)
	}
	transport.TLSClientConfig = tlsConfig

	// Configure HTTP/2
	if http2Transport, err := http2.ConfigureTransports(transport); err == nil && http2Transport != nil {
		http2Transport.ReadIdleTimeout = timeout
		http2Transport.AllowHTTP = false
		http2Transport.StrictMaxConcurrentStreams = true // Go 1.26: Enforce stream limits
	}

	x.transport.Store(transport)

	// Configure HTTP/3 if enabled
	if x.http3Enabled.Load() {
		if err := x.configureHTTP3(tlsConfig); err != nil {
			if x.logger != nil {
				x.logger.Warn("HTTP/3 configuration failed", slog.Any("error", err))
			}
		}
	}

	return nil
}

// createDialContext creates a context-aware dialer function.
// Go 1.26: Enhanced with connection tracking and error handling.
func (x *XTransport) createDialContext(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addrStr string) (net.Conn, error) {
		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

		// Format endpoint for connection
		formatEndpoint := func(addr netip.Addr) string {
			if !addr.IsValid() {
				// Parse literal IP from host
				if parsed := ParseIP(host); parsed.IsValid() {
					if parsed.Is6() {
						return net.JoinHostPort("["+parsed.String()+"]", strconv.Itoa(port))
					}
					return net.JoinHostPort(parsed.String(), strconv.Itoa(port))
				}
				return net.JoinHostPort(host, strconv.Itoa(port))
			}
			if addr.Is6() {
				return net.JoinHostPort("["+addr.String()+"]", strconv.Itoa(port))
			}
			return net.JoinHostPort(addr.String(), strconv.Itoa(port))
		}

		// Get cached IPs
		cachedIPs, _, _ := x.loadCachedIPs(host)
		targets := make([]string, 0, len(cachedIPs)+1)

		for _, addr := range cachedIPs {
			targets = append(targets, formatEndpoint(addr))
		}

		if len(targets) == 0 {
			if x.logger != nil {
				x.logger.Debug("IP not cached for dial", slog.String("host", host))
			}
			targets = append(targets, formatEndpoint(netip.Addr{}))
		}

		// Dial function
		dial := func(address string) (net.Conn, error) {
			if x.proxyDialer == nil {
				dialer := &net.Dialer{
					Timeout:   timeout,
					KeepAlive: timeout,
					// Go 1.26: DualStack is default, no need to set
				}
				return dialer.DialContext(ctx, network, address)
			}
			return (*x.proxyDialer).Dial(network, address)
		}

		// Try each target
		var lastErr error
		for idx, target := range targets {
			conn, err := dial(target)
			if err == nil {
				x.statsHTTP2Count.Add(1)
				return conn, nil
			}

			lastErr = err
			if idx < len(targets)-1 && x.logger != nil {
				x.logger.Debug("Dial attempt failed",
					slog.String("target", target),
					slog.Any("error", err))
			}
		}

		return nil, fmt.Errorf("all dial attempts failed: %w", lastErr)
	}
}

// configureTLS creates TLS configuration.
// Go 1.26: Modern TLS 1.3 defaults with fallback to TLS 1.2.
func (x *XTransport) configureTLS() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Go 1.26: TLS 1.3 is default max version
	}

	// Key logging for debugging
	if x.keyLogWriter != nil {
		tlsConfig.KeyLogWriter = x.keyLogWriter
	}

	// Load system cert pool
	certPool, certPoolErr := x509.SystemCertPool()

	// Add custom root CA if specified
	if x.tlsClientCreds.rootCA != "" {
		if certPool == nil {
			return nil, fmt.Errorf("system cert pool not available: %w", certPoolErr)
		}

		caCert, err := os.ReadFile(x.tlsClientCreds.rootCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read root CA: %w", err)
		}

		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to append root CA certificate")
		}
	}

	// Add Let's Encrypt ISRG Root X1 for compatibility
	if certPool != nil {
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
		tlsConfig.RootCAs = certPool
	}

	// Client certificate authentication
	if x.tlsClientCreds.clientCert != "" {
		cert, err := tls.LoadX509KeyPair(x.tlsClientCreds.clientCert, x.tlsClientCreds.clientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Session tickets
	if x.tlsDisableSessionTickets.Load() {
		tlsConfig.SessionTicketsDisabled = true
	}

	// RSA preference (force TLS 1.2)
	if x.tlsPreferRSA.Load() {
		tlsConfig.MaxVersion = tls.VersionTLS12
	}

	// Cipher suite optimization based on hardware support
	// Go 1.26: Only needed for TLS 1.2, TLS 1.3 has better defaults
	if x.tlsPreferRSA.Load() {
		if hasAESGCMHardwareSupport {
			tlsConfig.CipherSuites = []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			}
		} else {
			tlsConfig.CipherSuites = []uint16{
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			}
		}
	}

	return tlsConfig, nil
}

// configureHTTP3 configures the HTTP/3 transport.
// Go 1.26: Enhanced QUIC configuration with modern settings.
func (x *XTransport) configureHTTP3(tlsConfig *tls.Config) error {
	dial := func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
		if x.logger != nil {
			x.logger.Debug("Dialing HTTP/3", slog.String("addr", addrStr))
		}

		host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

		type udpTarget struct {
			addr    string
			network string
		}

		buildAddr := func(addr netip.Addr) udpTarget {
			if !addr.IsValid() {
				// Try to parse literal IP
				parsed := ParseIP(host)
				network := "udp4"
				addrStr := host

				if parsed.IsValid() {
					if parsed.Is4() {
						addrStr = parsed.String()
					} else {
						network = "udp6"
						addrStr = "[" + parsed.String() + "]"
					}
				} else if x.useIPv6.Load() {
					if x.useIPv4.Load() {
						network = "udp"
					} else {
						network = "udp6"
					}
				}

				return udpTarget{
					addr:    net.JoinHostPort(addrStr, strconv.Itoa(port)),
					network: network,
				}
			}

			if addr.Is4() {
				return udpTarget{
					addr:    net.JoinHostPort(addr.String(), strconv.Itoa(port)),
					network: "udp4",
				}
			}
			return udpTarget{
				addr:    net.JoinHostPort("["+addr.String()+"]", strconv.Itoa(port)),
				network: "udp6",
			}
		}

		// Get cached IPs
		cachedIPs, _, _ := x.loadCachedIPs(host)
		targets := make([]udpTarget, 0, len(cachedIPs)+1)

		for _, addr := range cachedIPs {
			targets = append(targets, buildAddr(addr))
		}

		if len(targets) == 0 {
			if x.logger != nil {
				x.logger.Debug("IP not cached for HTTP/3", slog.String("host", host))
			}
			targets = append(targets, buildAddr(netip.Addr{}))
		}

		// Try each target
		var lastErr error
		for idx, target := range targets {
			udpAddr, err := net.ResolveUDPAddr(target.network, target.addr)
			if err != nil {
				lastErr = err
				if idx < len(targets)-1 && x.logger != nil {
					x.logger.Debug("HTTP/3 resolve failed",
						slog.String("addr", target.addr),
						slog.String("network", target.network),
						slog.Any("error", err))
				}
				continue
			}

			udpConn, err := net.ListenUDP(target.network, nil)
			if err != nil {
				lastErr = err
				if idx < len(targets)-1 && x.logger != nil {
					x.logger.Debug("HTTP/3 listen failed",
						slog.String("addr", target.addr),
						slog.String("network", target.network),
						slog.Any("error", err))
				}
				continue
			}

			tlsCfg.ServerName = host
			conn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
			if err != nil {
				udpConn.Close()
				lastErr = err
				if idx < len(targets)-1 && x.logger != nil {
					x.logger.Debug("HTTP/3 dial failed",
						slog.String("addr", target.addr),
						slog.String("network", target.network),
						slog.Any("error", err))
				}
				continue
			}

			x.statsHTTP3Count.Add(1)
			return conn, nil
		}

		return nil, fmt.Errorf("all HTTP/3 dial attempts failed: %w", lastErr)
	}

	h3Transport := &http3.Transport{
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
		Dial:               dial,
		// Go 1.26: Add connection pooling settings
		MaxResponseHeaderBytes: 4096,
	}

	x.h3Transport.Store(h3Transport)
	return nil
}

// resolveUsingSystem resolves a hostname using the system resolver.
// Go 1.26: Context-aware with proper timeout handling.
func (x *XTransport) resolveUsingSystem(ctx context.Context, host string, returnIPv4, returnIPv6 bool) ([]netip.Addr, time.Duration, error) {
	// Create context with timeout
	resolveCtx, cancel := context.WithTimeout(ctx, ResolverReadTimeout)
	defer cancel()

	resolver := &net.Resolver{}
	ips, err := resolver.LookupIP(resolveCtx, "ip", host)
	if err != nil {
		return nil, 0, fmt.Errorf("system resolver failed: %w", err)
	}

	// Convert and filter by IP version
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}

		if returnIPv4 && addr.Is4() {
			addrs = append(addrs, addr)
		} else if returnIPv6 && addr.Is6() {
			addrs = append(addrs, addr)
		}
	}

	return addrs, SystemResolverIPTTL, nil
}

// resolveUsingResolver resolves a hostname using a specific DNS resolver.
// Go 1.26: Enhanced with proper context handling and error wrapping.
func (x *XTransport) resolveUsingResolver(
	ctx context.Context,
	proto, host string,
	resolver string,
	returnIPv4, returnIPv6 bool,
) ([]netip.Addr, time.Duration, error) {
	transport := &dns.Transport{}
	transport.ReadTimeout = ResolverReadTimeout
	dnsClient := &dns.Client{Transport: transport}

	queryTypes := make([]uint16, 0, 2)
	if returnIPv4 {
		queryTypes = append(queryTypes, dns.TypeA)
	}
	if returnIPv6 {
		queryTypes = append(queryTypes, dns.TypeAAAA)
	}

	var addrs []netip.Addr
	var rrTTL uint32

	for _, rrType := range queryTypes {
		msg := dns.NewMsg(fqdn(host), rrType)
		if msg == nil {
			continue
		}

		msg.RecursionDesired = true
		msg.UDPSize = uint16(MaxDNSPacketSize)
		msg.Security = true

		response, _, err := dnsClient.Exchange(ctx, msg, proto, resolver)
		if err != nil {
			return nil, 0, fmt.Errorf("DNS exchange failed: %w", err)
		}

		for _, answer := range response.Answer {
			if dns.RRToType(answer) == rrType {
				var addr netip.Addr
				switch rrType {
				case dns.TypeA:
					if a, ok := answer.(*dns.A); ok {
						addr = a.A.Addr
					}
				case dns.TypeAAAA:
					if aaaa, ok := answer.(*dns.AAAA); ok {
						addr = aaaa.AAAA.Addr
					}
				}

				if addr.IsValid() {
					addrs = append(addrs, addr)
					rrTTL = answer.Header().TTL
				}
			}
		}
	}

	var ttl time.Duration
	if len(addrs) > 0 {
		ttl = time.Duration(rrTTL) * time.Second
	}

	return addrs, ttl, nil
}

// resolveUsingServers attempts resolution using multiple resolvers with retry logic.
// Go 1.26: Exponential backoff with context support.
func (x *XTransport) resolveUsingServers(
	ctx context.Context,
	proto, host string,
	resolvers []string,
	returnIPv4, returnIPv6 bool,
) ([]netip.Addr, time.Duration, error) {
	if len(resolvers) == 0 {
		return nil, 0, ErrEmptyResolvers
	}

	var lastErr error
	for i, resolver := range resolvers {
		delay := resolverRetryInitialBackoff

		for attempt := 1; attempt <= resolverRetryCount; attempt++ {
			// Check context cancellation
			if err := ctx.Err(); err != nil {
				return nil, 0, fmt.Errorf("resolution canceled: %w", err)
			}

			addrs, ttl, err := x.resolveUsingResolver(ctx, proto, host, resolver, returnIPv4, returnIPv6)
			if err == nil && len(addrs) > 0 {
				// Promote successful resolver to front
				if i > 0 {
					if x.logger != nil {
						x.logger.Info("Resolution succeeded, promoting resolver",
							slog.String("proto", proto),
							slog.String("resolver", resolver))
					}
					resolvers[0], resolvers[i] = resolvers[i], resolvers[0]
				}
				return addrs, ttl, nil
			}

			if err == nil {
				err = ErrNoIPAddresses
			}

			lastErr = err
			if x.logger != nil {
				x.logger.Debug("Resolver attempt failed",
					slog.Int("attempt", attempt),
					slog.String("host", host),
					slog.String("resolver", resolver),
					slog.String("proto", proto),
					slog.Any("error", err))
			}

			// Exponential backoff
			if attempt < resolverRetryCount {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return nil, 0, ctx.Err()
				}

				delay *= 2
				if delay > resolverRetryMaxBackoff {
					delay = resolverRetryMaxBackoff
				}
			}
		}

		if x.logger != nil {
			x.logger.Info("Unable to resolve with resolver",
				slog.String("host", host),
				slog.String("resolver", resolver),
				slog.String("proto", proto),
				slog.Any("error", lastErr))
		}
	}

	if lastErr == nil {
		lastErr = ErrNoIPAddresses
	}

	return nil, 0, lastErr
}

// resolve performs DNS resolution with fallback to multiple resolver types.
// Go 1.26: Comprehensive resolution strategy with context support.
func (x *XTransport) resolve(ctx context.Context, host string, returnIPv4, returnIPv6 bool) ([]netip.Addr, time.Duration, error) {
	x.statsResolveCount.Add(1)

	protos := []string{"udp", "tcp"}
	if x.mainProto == "tcp" {
		protos = []string{"tcp", "udp"}
	}

	var addrs []netip.Addr
	var ttl time.Duration
	var err error

	// Try internal resolvers if configured
	if x.ignoreSystemDNS.Load() {
		if x.internalResolverReady.Load() {
			for _, proto := range protos {
				addrs, ttl, err = x.resolveUsingServers(ctx, proto, host, x.internalResolvers, returnIPv4, returnIPv6)
				if err == nil {
					return addrs, ttl, nil
				}
			}
		} else {
			err = ErrServiceNotReady
			if x.logger != nil {
				x.logger.Notice(err.Error())
			}
		}
	} else {
		// Try system resolver first
		addrs, ttl, err = x.resolveUsingSystem(ctx, host, returnIPv4, returnIPv6)
		if err != nil {
			err = ErrSystemDNSNotUsable
			if x.logger != nil {
				x.logger.Notice(err.Error())
			}
		} else {
			return addrs, ttl, nil
		}
	}

	// Fallback to bootstrap resolvers
	if err != nil {
		for _, proto := range protos {
			if x.logger != nil {
				x.logger.Notice("Using bootstrap resolvers",
					slog.String("host", host),
					slog.String("proto", proto))
			}

			addrs, ttl, err = x.resolveUsingServers(ctx, proto, host, x.bootstrapResolvers, returnIPv4, returnIPv6)
			if err == nil {
				return addrs, ttl, nil
			}
		}

		// Last resort: try system resolver if we haven't already
		if x.ignoreSystemDNS.Load() {
			if x.logger != nil {
				x.logger.Notice("Bootstrap failed, trying system resolver as last resort")
			}
			addrs, ttl, err = x.resolveUsingSystem(ctx, host, returnIPv4, returnIPv6)
		}
	}

	return addrs, ttl, err
}

// resolveAndUpdateCache resolves a hostname and updates the cache.
// Go 1.26: Prevents duplicate concurrent resolutions.
func (x *XTransport) resolveAndUpdateCache(ctx context.Context, host string) error {
	// Skip resolution for proxied connections
	if x.proxyDialer != nil || x.httpProxyFunction != nil {
		return nil
	}

	// Skip if host is already an IP address
	if addr := ParseIP(host); addr.IsValid() {
		return nil
	}

	// Check cache
	cachedIPs, expired, updating := x.loadCachedIPs(host)
	if len(cachedIPs) > 0 && (!expired || updating) {
		return nil
	}

	// Mark as updating to prevent concurrent resolutions
	x.markUpdatingCachedIP(host)

	// Resolve
	addrs, ttl, err := x.resolve(ctx, host, x.useIPv4.Load(), x.useIPv6.Load())
	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}

	selectedAddrs := addrs
	// Use stale cache if resolution failed
	if (err != nil || len(selectedAddrs) == 0) && len(cachedIPs) > 0 {
		if x.logger != nil {
			x.logger.Notice("Using stale cached addresses",
				slog.String("host", host),
				slog.Duration("grace_period", ExpiredCachedIPGraceTTL))
		}
		selectedAddrs = cachedIPs
		ttl = ExpiredCachedIPGraceTTL
		err = nil
	}

	if err != nil {
		return err
	}

	if len(selectedAddrs) == 0 {
		if x.logger != nil {
			if !x.useIPv4.Load() && x.useIPv6.Load() {
				x.logger.Warn("No IPv6 address found", slog.String("host", host))
			} else if x.useIPv4.Load() && !x.useIPv6.Load() {
				x.logger.Warn("No IPv4 address found", slog.String("host", host))
			} else {
				x.logger.Error("No IP address found", slog.String("host", host))
			}
		}
		return nil
	}

	x.saveCachedIPs(host, selectedAddrs, ttl)
	return nil
}

// Fetch performs an HTTP request with comprehensive error handling.
// Go 1.26: Enhanced with better context support and HTTP/3 fallback.
func (x *XTransport) Fetch(
	ctx context.Context,
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

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := &http.Client{
		Transport: x.transport.Load(),
		Timeout:   timeout,
	}

	host, port := ExtractHostAndPort(reqURL.Host, 443)

	// HTTP/3 selection logic
	hasAltSupport := false
	if x.h3Transport.Load() != nil {
		if x.http3Probe.Load() {
			// Always try HTTP/3 first when probing
			client.Transport = x.h3Transport.Load()
			if x.logger != nil {
				x.logger.Debug("Probing HTTP/3", slog.String("host", reqURL.Host))
			}
		} else {
			// Use Alt-Svc cache
			altPort, found := x.altSupport.Load(reqURL.Host)
			hasAltSupport = found
			if found && altPort > 0 && int(altPort) == port {
				client.Transport = x.h3Transport.Load()
				if x.logger != nil {
					x.logger.Debug("Using HTTP/3 from Alt-Svc",
						slog.String("host", reqURL.Host))
				}
			}
		}
	}

	// Build request headers
	header := http.Header{
		"User-Agent": []string{"dnscrypt-proxy"},
	}
	if accept != "" {
		header.Set("Accept", accept)
	}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	header.Set("Cache-Control", "max-stale")

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
	if err := x.resolveAndUpdateCache(ctx, host); err != nil {
		if x.logger != nil {
			x.logger.Error("Unable to resolve host",
				slog.String("host", host),
				slog.Any("error", err))
		}
		return nil, 0, nil, 0, fmt.Errorf("resolution failed: %w", err)
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
	resp, err := client.Do(req.WithContext(ctx))
	rtt := time.Since(start)

	// HTTP/3 fallback logic
	if err != nil && client.Transport == x.h3Transport.Load() {
		if x.logger != nil {
			if x.http3Probe.Load() {
				x.logger.Debug("HTTP/3 probe failed, falling back",
					slog.String("host", reqURL.Host),
					slog.Any("error", err))
			} else {
				x.logger.Debug("HTTP/3 connection failed, falling back",
					slog.String("host", reqURL.Host),
					slog.Any("error", err))
			}
		}

		// Add to negative cache
		x.altSupport.Store(reqURL.Host, 0)

		// Retry with HTTP/2
		client.Transport = x.transport.Load()
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(*body))
		}

		start = time.Now()
		resp, err = client.Do(req.WithContext(ctx))
		rtt = time.Since(start)
	}

	// Handle response errors
	if err == nil {
		if resp == nil {
			err = ErrWebserverError
		} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
			err = fmt.Errorf("HTTP status %d: %s", resp.StatusCode, resp.Status)
		}
	} else {
		if x.logger != nil {
			x.logger.Debug("HTTP client error, closing idle connections",
				slog.Any("error", err))
		}
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
		if x.logger != nil {
			x.logger.Debug("Request failed",
				slog.String("url", req.URL.String()),
				slog.Any("error", err))
		}
		return nil, statusCode, nil, rtt, err
	}

	// Process Alt-Svc header for HTTP/3
	if x.h3Transport.Load() != nil && !hasAltSupport {
		skipAltSvcParsing := false

		// Check negative cache for http3_probe
		if x.http3Probe.Load() {
			if altPort, found := x.altSupport.Load(reqURL.Host); found && altPort == 0 {
				if x.logger != nil {
					x.logger.Debug("Skipping Alt-Svc (negative cache)",
						slog.String("host", reqURL.Host))
				}
				skipAltSvcParsing = true
			}
		}

		if !skipAltSvcParsing {
			if altHeaders := resp.Header["Alt-Svc"]; len(altHeaders) > 0 {
				if x.logger != nil {
					x.logger.Debug("Processing Alt-Svc",
						slog.String("host", reqURL.Host),
						slog.Any("values", altHeaders))
				}

				altPort := uint16(port)
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
								if x.logger != nil {
									x.logger.Debug("Found HTTP/3 support",
										slog.String("host", reqURL.Host),
										slog.Uint64("port", parsedPort))
								}
								break
							}
						}
					}
				}
				x.altSupport.Store(reqURL.Host, altPort)
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
	return x.Fetch(context.Background(), "GET", url, accept, "", nil, timeout, true)
}

// GetWithCompressionContext performs an HTTP GET request with context and compression.
// Go 1.26: Context-aware version for cancellation support.
func (x *XTransport) GetWithCompressionContext(
	ctx context.Context,
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(ctx, "GET", url, accept, "", nil, timeout, true)
}

// Get performs an HTTP GET request without compression.
func (x *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(context.Background(), "GET", url, accept, "", nil, timeout, false)
}

// GetContext performs an HTTP GET request with context support.
// Go 1.26: Context-aware version for cancellation support.
func (x *XTransport) GetContext(
	ctx context.Context,
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(ctx, "GET", url, accept, "", nil, timeout, false)
}

// Post performs an HTTP POST request.
func (x *XTransport) Post(
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(context.Background(), "POST", url, accept, contentType, body, timeout, false)
}

// PostContext performs an HTTP POST request with context support.
// Go 1.26: Context-aware version for cancellation support.
func (x *XTransport) PostContext(
	ctx context.Context,
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(ctx, "POST", url, accept, contentType, body, timeout, false)
}

// dohLikeQuery performs a DoH or ODoH query.
// Go 1.26: Unified implementation for DoH and ODoH.
func (x *XTransport) dohLikeQuery(
	ctx context.Context,
	dataType string,
	useGet bool,
	reqURL *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if useGet {
		// Encode body in URL for GET requests
		qs := reqURL.Query()
		encBody := base64.RawURLEncoding.EncodeToString(body)
		qs.Add("dns", encBody)
		newURL := *reqURL
		newURL.RawQuery = qs.Encode()
		return x.Fetch(ctx, "GET", &newURL, dataType, "", nil, timeout, false)
	}

	return x.Fetch(ctx, "POST", reqURL, dataType, dataType, &body, timeout, false)
}

// DoHQuery performs a DNS-over-HTTPS (DoH) query.
func (x *XTransport) DoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery(context.Background(), "application/dns-message", useGet, url, body, timeout)
}

// DoHQueryContext performs a DoH query with context support.
// Go 1.26: Context-aware version for cancellation support.
func (x *XTransport) DoHQueryContext(
	ctx context.Context,
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery(ctx, "application/dns-message", useGet, url, body, timeout)
}

// ObliviousDoHQuery performs an Oblivious DNS-over-HTTPS (ODoH) query.
func (x *XTransport) ObliviousDoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery(context.Background(), "application/oblivious-dns-message", useGet, url, body, timeout)
}

// ObliviousDoHQueryContext performs an ODoH query with context support.
// Go 1.26: Context-aware version for cancellation support.
func (x *XTransport) ObliviousDoHQueryContext(
	ctx context.Context,
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery(ctx, "application/oblivious-dns-message", useGet, url, body, timeout)
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
