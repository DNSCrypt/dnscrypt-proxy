// Package main implements an extended HTTP transport with DNS bootstrapping,
// IP caching, and optional HTTP/3 support.
//
// Modernized for Go 1.26:
//   - Structured logging via log/slog
//   - crypto/rand-based jitter (avoid math/rand global)
//   - Cleaner time handling in cache (avoid *time.Time where possible)
//   - Context-aware Fetch methods
//   - Better transport rebuild lifecycle management
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	crand "crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	netproxy "golang.org/x/net/proxy"
	"golang.org/x/sys/cpu"
)

var hasAESGCMHardwareSupport = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ ||
	cpu.ARM64.HasAES && cpu.ARM64.HasPMULL ||
	cpu.S390X.HasAES && cpu.S390X.HasAESGCM

const (
	DefaultBootstrapResolver    = "9.9.9.9:53"
	DefaultKeepAlive            = 5 * time.Second
	DefaultTimeout              = 30 * time.Second
	ResolverReadTimeout         = 5 * time.Second
	SystemResolverIPTTL         = 12 * time.Hour
	MinResolverIPTTL            = 4 * time.Hour
	ResolverIPTTLMaxJitter      = 15 * time.Minute
	ExpiredCachedIPGraceTTL     = 15 * time.Minute
	resolverRetryCount          = 3
	resolverRetryInitialBackoff = 150 * time.Millisecond
	resolverRetryMaxBackoff     = 1 * time.Second
)

// CachedIPItem holds cached IPs and their validity window.
type CachedIPItem struct {
	ips           []net.IP
	expiresAt     time.Time
	hasExpiresAt  bool
	updatingUntil time.Time
	hasUpdating   bool
}

type CachedIPs struct {
	mu    sync.RWMutex
	cache map[string]*CachedIPItem
}

type AltSupport struct {
	mu    sync.RWMutex
	cache map[string]uint16
}

type XTransport struct {
	transport   *http.Transport
	h3Transport *http3.Transport

	keepAlive time.Duration
	timeout   time.Duration

	cachedIPs  CachedIPs
	altSupport AltSupport

	internalResolvers  []string
	bootstrapResolvers []string
	mainProto          string

	ignoreSystemDNS       bool
	internalResolverReady bool
	useIPv4               bool
	useIPv6               bool

	http3      bool
	http3Probe bool

	tlsDisableSessionTickets bool
	tlsPreferRSA             bool

	proxyDialer       *netproxy.Dialer
	httpProxyFunction func(*http.Request) (*url.URL, error)
	tlsClientCreds    DOHClientCreds
	keyLogWriter      io.Writer

	logger *slog.Logger
}

func NewXTransport() *XTransport {
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
		panic("DefaultBootstrapResolver does not parse")
	}
	xt := &XTransport{
		cachedIPs:          CachedIPs{cache: make(map[string]*CachedIPItem)},
		altSupport:         AltSupport{cache: make(map[string]uint16)},
		keepAlive:          DefaultKeepAlive,
		timeout:            DefaultTimeout,
		bootstrapResolvers: []string{DefaultBootstrapResolver},
		ignoreSystemDNS:    true,
		useIPv4:            true,
		useIPv6:            false,
		http3Probe:         false,
		logger:             slog.Default(),
	}
	xt.rebuildTransport()
	return xt
}

func (x *XTransport) SetLogger(l *slog.Logger) *XTransport {
	if l != nil {
		x.logger = l
	}
	return x
}

func ParseIP(ipStr string) net.IP {
	return net.ParseIP(strings.TrimRight(strings.TrimLeft(ipStr, "["), "]"))
}

func uniqueNormalizedIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	unique := make([]net.IP, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		copyIP := append(net.IP(nil), ip...)
		key := copyIP.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, copyIP)
	}
	return unique
}

func cryptoJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0
	}
	n := binary.LittleEndian.Uint64(b[:])
	return time.Duration(n % uint64(max))
}

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
		ttl += cryptoJitter(ResolverIPTTLMaxJitter)
		item.expiresAt = time.Now().Add(ttl)
		item.hasExpiresAt = true
	}

	x.cachedIPs.mu.Lock()
	item.hasUpdating = false
	x.cachedIPs.cache[host] = item
	x.cachedIPs.mu.Unlock()

	if x.logger != nil {
		x.logger.Debug("Cached IPs",
			slog.String("host", host),
			slog.Int("count", len(normalized)),
			slog.Duration("ttl", ttl))
	}
}

func (x *XTransport) markUpdatingCachedIP(host string) {
	x.cachedIPs.mu.Lock()
	item, ok := x.cachedIPs.cache[host]
	if ok {
		item.updatingUntil = time.Now().Add(x.timeout)
		item.hasUpdating = true
		x.cachedIPs.cache[host] = item
		if x.logger != nil {
			x.logger.Debug("Marked cached IP as updating", slog.String("host", host))
		}
	}
	x.cachedIPs.mu.Unlock()
}

func (x *XTransport) loadCachedIPs(host string) (ips []net.IP, expired bool, updating bool) {
	x.cachedIPs.mu.RLock()
	item, ok := x.cachedIPs.cache[host]
	if !ok {
		x.cachedIPs.mu.RUnlock()
		return nil, false, false
	}
	if len(item.ips) > 0 {
		ips = make([]net.IP, 0, len(item.ips))
		for _, ip := range item.ips {
			if ip == nil {
				continue
			}
			ips = append(ips, append(net.IP(nil), ip...))
		}
	}
	expiresAt, hasExpires := item.expiresAt, item.hasExpiresAt
	updatingUntil, hasUpdating := item.updatingUntil, item.hasUpdating
	x.cachedIPs.mu.RUnlock()

	if hasExpires && time.Until(expiresAt) < 0 {
		expired = true
		if hasUpdating && time.Until(updatingUntil) > 0 {
			updating = true
		}
	}
	return ips, expired, updating
}

func (x *XTransport) rebuildTransport() {
	if x.logger != nil {
		x.logger.Debug("Rebuilding transport")
	}
	if x.transport != nil {
		x.transport.CloseIdleConnections()
	}

	timeout := x.timeout
	tr := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true,
		MaxIdleConns:           1,
		IdleConnTimeout:        x.keepAlive,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  timeout,
		MaxResponseHeaderBytes: 4096,
		DialContext: func(ctx context.Context, network, addrStr string) (net.Conn, error) {
			host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
			formatEndpoint := func(ip net.IP) string {
				if ip != nil {
					if ipv4 := ip.To4(); ipv4 != nil {
						return ipv4.String() + ":" + strconv.Itoa(port)
					}
					return "[" + ip.String() + "]:" + strconv.Itoa(port)
				}
				if parsed := ParseIP(host); parsed != nil && parsed.To4() == nil {
					return "[" + parsed.String() + "]:" + strconv.Itoa(port)
				}
				return host + ":" + strconv.Itoa(port)
			}

			cachedIPs, _, _ := x.loadCachedIPs(host)
			targets := make([]string, 0, len(cachedIPs)+1)
			for _, ip := range cachedIPs {
				targets = append(targets, formatEndpoint(ip))
			}
			if len(targets) == 0 {
				targets = append(targets, formatEndpoint(nil))
			}

			dial := func(address string) (net.Conn, error) {
				if x.proxyDialer == nil {
					d := &net.Dialer{Timeout: timeout, KeepAlive: timeout}
					return d.DialContext(ctx, network, address)
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
				if x.logger != nil && idx < len(targets)-1 {
					x.logger.Debug("Dial failed", slog.String("target", target), slog.Any("error", err))
				}
			}
			return nil, lastErr
		},
	}
	if x.httpProxyFunction != nil {
		tr.Proxy = x.httpProxyFunction
	}

	// TLS configuration (keep behavior compatible; rely on Go 1.26 defaults where possible).
	clientCreds := x.tlsClientCreds
	tlsCfg := tls.Config{}

	certPool, certPoolErr := x509.SystemCertPool()
	if x.keyLogWriter != nil {
		tlsCfg.KeyLogWriter = x.keyLogWriter
	}

	if clientCreds.rootCA != "" {
		if certPool == nil {
			return
		}
		pem, err := os.ReadFile(clientCreds.rootCA)
		if err != nil {
			if x.logger != nil {
				x.logger.Error("Unable to read rootCA file",
					slog.String("path", clientCreds.rootCA),
					slog.Any("error", err))
			}
			return
		}
		certPool.AppendCertsFromPEM(pem)
		_ = certPoolErr
	}
	if certPool != nil {
		tlsCfg.RootCAs = certPool
	}

	if clientCreds.clientCert != "" {
		cert, err := tls.LoadX509KeyPair(clientCreds.clientCert, clientCreds.clientKey)
		if err != nil {
			if x.logger != nil {
				x.logger.Error("Unable to load client certificate",
					slog.String("cert", clientCreds.clientCert),
					slog.String("key", clientCreds.clientKey),
					slog.Any("error", err))
			}
			return
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if x.tlsDisableSessionTickets {
		tlsCfg.SessionTicketsDisabled = true
	}
	if x.tlsPreferRSA {
		tlsCfg.MaxVersion = tls.VersionTLS12
	}

	// Keep custom TLS 1.2 cipher suites ordering (if needed for legacy servers).
	if tlsCfg.MaxVersion == tls.VersionTLS12 {
		if hasAESGCMHardwareSupport {
			tlsCfg.CipherSuites = []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			}
		} else {
			tlsCfg.CipherSuites = []uint16{
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			}
		}
	}

	tr.TLSClientConfig = &tlsCfg
	if h2, _ := http2.ConfigureTransports(tr); h2 != nil {
		h2.ReadIdleTimeout = timeout
		h2.AllowHTTP = false
		// Go 1.26 adds HTTP2Config.StrictMaxConcurrentRequests; keep defaults unless you need custom pool logic.
	}

	x.transport = tr

	if x.http3 {
		dial := func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)

			type udpTarget struct {
				addr    string
				network string
			}
			buildAddr := func(ip net.IP) udpTarget {
				if ip != nil {
					if ipv4 := ip.To4(); ipv4 != nil {
						return udpTarget{addr: ipv4.String() + ":" + strconv.Itoa(port), network: "udp4"}
					}
					return udpTarget{addr: "[" + ip.String() + "]:" + strconv.Itoa(port), network: "udp6"}
				}
				network := "udp4"
				addr := host
				if parsed := ParseIP(host); parsed != nil {
					if parsed.To4() != nil {
						addr = parsed.String()
					} else {
						network = "udp6"
						addr = "[" + parsed.String() + "]"
					}
				} else if x.useIPv6 {
					if x.useIPv4 {
						network = "udp"
					} else {
						network = "udp6"
					}
				}
				return udpTarget{addr: addr + ":" + strconv.Itoa(port), network: network}
			}

			cachedIPs, _, _ := x.loadCachedIPs(host)
			targets := make([]udpTarget, 0, len(cachedIPs)+1)
			for _, ip := range cachedIPs {
				targets = append(targets, buildAddr(ip))
			}
			if len(targets) == 0 {
				targets = append(targets, buildAddr(nil))
			}

			var lastErr error
			for idx, target := range targets {
				udpAddr, err := net.ResolveUDPAddr(target.network, target.addr)
				if err != nil {
					lastErr = err
					if x.logger != nil && idx < len(targets)-1 {
						x.logger.Debug("H3 resolve failed", slog.String("addr", target.addr), slog.Any("error", err))
					}
					continue
				}
				udpConn, err := net.ListenUDP(target.network, nil)
				if err != nil {
					lastErr = err
					if x.logger != nil && idx < len(targets)-1 {
						x.logger.Debug("H3 listen failed", slog.String("network", target.network), slog.Any("error", err))
					}
					continue
				}
				tlsCfg.ServerName = host
				conn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
				if err != nil {
					_ = udpConn.Close()
					lastErr = err
					if x.logger != nil && idx < len(targets)-1 {
						x.logger.Debug("H3 dial failed", slog.String("addr", target.addr), slog.Any("error", err))
					}
					continue
				}
				return conn, nil
			}
			return nil, lastErr
		}
		x.h3Transport = &http3.Transport{DisableCompression: true, TLSClientConfig: &tlsCfg, Dial: dial}
	}
}

func (x *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	ipa, err := net.LookupIP(host)
	if returnIPv4 && returnIPv6 {
		return ipa, SystemResolverIPTTL, err
	}
	ips := make([]net.IP, 0, len(ipa))
	for _, ip := range ipa {
		ipv4 := ip.To4()
		if returnIPv4 && ipv4 != nil {
			ips = append(ips, ipv4)
		}
		if returnIPv6 && ipv4 == nil {
			ips = append(ips, ip)
		}
	}
	return ips, SystemResolverIPTTL, err
}

func (x *XTransport) resolveUsingResolver(proto, host, resolver string, returnIPv4, returnIPv6 bool) (ips []net.IP, ttl time.Duration, err error) {
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

		in, _, exErr := dnsClient.Exchange(ctx, msg, proto, resolver)
		if exErr != nil {
			err = exErr
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
			rrTTL = answer.Header().TTL
		}
	}
	if len(ips) > 0 {
		ttl = time.Duration(rrTTL) * time.Second
	}
	return ips, ttl, err
}

func (x *XTransport) resolveUsingServers(proto, host string, resolvers []string, returnIPv4, returnIPv6 bool) (ips []net.IP, ttl time.Duration, err error) {
	if len(resolvers) == 0 {
		return nil, 0, errors.New("empty resolvers")
	}
	var lastErr error
	for i, resolver := range resolvers {
		delay := resolverRetryInitialBackoff
		for attempt := 1; attempt <= resolverRetryCount; attempt++ {
			ips, ttl, err = x.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)
			if err == nil && len(ips) > 0 {
				if i > 0 {
					resolvers[0], resolvers[i] = resolvers[i], resolvers[0]
				}
				return ips, ttl, nil
			}
			if err == nil {
				err = errors.New("no IP addresses returned")
			}
			lastErr = err
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
		if x.logger != nil {
			x.logger.Info("Resolver failed",
				slog.String("host", host),
				slog.String("resolver", resolver),
				slog.String("proto", proto),
				slog.Any("error", lastErr))
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no IP addresses returned")
	}
	return nil, 0, lastErr
}

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
					break
				}
			}
		} else {
			err = errors.New("dnscrypt-proxy service is not usable yet")
		}
	} else {
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)
		if err != nil {
			err = errors.New("system DNS is not usable yet")
		}
	}

	if err != nil {
		for _, proto := range protos {
			ips, ttl, err = x.resolveUsingServers(proto, host, x.bootstrapResolvers, returnIPv4, returnIPv6)
			if err == nil {
				break
			}
		}
	}

	if err != nil && x.ignoreSystemDNS {
		ips, ttl, err = x.resolveUsingSystem(host, returnIPv4, returnIPv6)
	}

	return ips, ttl, err
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

	x.markUpdatingCachedIP(host)

	ips, ttl, err := x.resolve(host, x.useIPv4, x.useIPv6)
	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}
	selectedIPs := ips
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {
		selectedIPs = cachedIPs
		ttl = ExpiredCachedIPGraceTTL
		err = nil
	}
	if err != nil {
		return err
	}
	if len(selectedIPs) == 0 {
		return nil
	}

	x.saveCachedIPs(host, selectedIPs, ttl)
	return nil
}

// Fetch executes an HTTP request using the configured transport.
// Modernized: context-aware, supports optional gzip responses, and HTTP/3 fallback.
func (x *XTransport) Fetch(ctx context.Context, method string, u *url.URL, accept, contentType string, body *[]byte, timeout time.Duration, compress bool) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = x.timeout
	}

	client := http.Client{Transport: x.transport, Timeout: timeout}

	host, port := ExtractHostAndPort(u.Host, 443)
	hasAltSupport := false

	if x.h3Transport != nil {
		if x.http3Probe {
			client.Transport = x.h3Transport
		} else {
			x.altSupport.mu.RLock()
			altPort, ok := x.altSupport.cache[u.Host]
			x.altSupport.mu.RUnlock()
			hasAltSupport = ok
			if ok && altPort > 0 && int(altPort) == port {
				client.Transport = x.h3Transport
			}
		}
	}

	header := http.Header{}
	header.Set("User-Agent", "dnscrypt-proxy")
	if accept != "" {
		header.Set("Accept", accept)
	}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	header.Set("Cache-Control", "max-stale")

	u2 := *u
	if body != nil {
		h := sha512.Sum512(*body)
		qs := u2.Query()
		qs.Add("body_hash", hex.EncodeToString(h[:32]))
		u2.RawQuery = qs.Encode()
	}

	if x.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0, errors.New("onion service is not reachable without Tor")
	}
	if err := x.resolveAndUpdateCache(host); err != nil {
		return nil, 0, nil, 0, err
	}
	if compress && body == nil {
		header.Set("Accept-Encoding", "gzip")
	}

	req, err := http.NewRequestWithContext(ctx, method, u2.String(), nil)
	if err != nil {
		return nil, 0, nil, 0, err
	}
	req.Header = header

	if body != nil {
		req.ContentLength = int64(len(*body))
		req.Body = io.NopCloser(bytes.NewReader(*body))
	}

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	if err != nil && client.Transport == x.h3Transport {
		// Negative cache and retry over HTTP/2
		x.altSupport.mu.Lock()
		x.altSupport.cache[u.Host] = 0
		x.altSupport.mu.Unlock()

		client.Transport = x.transport
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(*body))
		}
		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)
	}

	statusCode := 503
	if resp != nil {
		defer resp.Body.Close()
		statusCode = resp.StatusCode
	}
	if err != nil {
		return nil, statusCode, nil, rtt, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, statusCode, resp.TLS, rtt, fmt.Errorf("http status: %s", resp.Status)
	}

	if x.h3Transport != nil && !hasAltSupport {
		if alt := resp.Header.Values("Alt-Svc"); len(alt) > 0 {
			altPort := uint16(port & 0xffff)
			for i, xalt := range alt {
				if i >= 8 {
					break
				}
				parts := strings.Split(xalt, ";")
				for j, v := range parts {
					if j >= 16 {
						break
					}
					v = strings.TrimSpace(v)
					if after, ok := strings.CutPrefix(v, "h3=\":"); ok {
						vv := strings.TrimSuffix(after, "\"")
						if p, perr := strconv.ParseUint(vv, 10, 16); perr == nil && p <= 65535 {
							altPort = uint16(p)
							break
						}
					}
				}
			}
			x.altSupport.mu.Lock()
			x.altSupport.cache[u.Host] = altPort
			x.altSupport.mu.Unlock()
		}
	}

	var bodyReader io.ReadCloser = resp.Body
	if compress && resp.Header.Get("Content-Encoding") == "gzip" {
		zr, zerr := gzip.NewReader(io.LimitReader(resp.Body, MaxHTTPBodyLength))
		if zerr != nil {
			return nil, statusCode, resp.TLS, rtt, zerr
		}
		defer zr.Close()
		bodyReader = zr
	}

	bin, rerr := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))
	if rerr != nil {
		return nil, statusCode, resp.TLS, rtt, rerr
	}
	return bin, statusCode, resp.TLS, rtt, nil
}

func (x *XTransport) GetWithCompression(ctx context.Context, u *url.URL, accept string, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(ctx, http.MethodGet, u, accept, "", nil, timeout, true)
}

func (x *XTransport) Get(ctx context.Context, u *url.URL, accept string, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(ctx, http.MethodGet, u, accept, "", nil, timeout, false)
}

func (x *XTransport) Post(ctx context.Context, u *url.URL, accept, contentType string, body *[]byte, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.Fetch(ctx, http.MethodPost, u, accept, contentType, body, timeout, false)
}

func (x *XTransport) dohLikeQuery(ctx context.Context, dataType string, useGet bool, u *url.URL, body []byte, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if useGet {
		qs := u.Query()
		qs.Add("dns", base64.RawURLEncoding.EncodeToString(body))
		u2 := *u
		u2.RawQuery = qs.Encode()
		return x.Get(ctx, &u2, dataType, timeout)
	}
	return x.Post(ctx, u, dataType, dataType, &body, timeout)
}

func (x *XTransport) DoHQuery(ctx context.Context, useGet bool, u *url.URL, body []byte, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery(ctx, "application/dns-message", useGet, u, body, timeout)
}

func (x *XTransport) ObliviousDoHQuery(ctx context.Context, useGet bool, u *url.URL, body []byte, timeout time.Duration) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return x.dohLikeQuery(ctx, "application/oblivious-dns-message", useGet, u, body, timeout)
}
