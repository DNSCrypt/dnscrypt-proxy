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
	"io"
	"math/rand"
	"net"
	"net/http"
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
	"golang.org/x/sync/singleflight"
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

type CachedIPItem struct {
	ips           []net.IP
	expiration    *time.Time
	updatingUntil *time.Time
}

type CachedIPs struct {
	sync.RWMutex
	cache map[string]*CachedIPItem
}

type AltSupport struct {
	sync.RWMutex
	cache map[string]uint16
}

type XTransport struct {
	transport   *http.Transport
	h3Transport *http3.Transport

	// Reused clients (avoid per-request allocations)
	httpClient *http.Client
	h3Client   *http.Client

	keepAlive  time.Duration
	timeout    time.Duration
	cachedIPs  CachedIPs
	altSupport AltSupport

	internalResolvers        []string
	bootstrapResolvers       []string
	mainProto                string
	ignoreSystemDNS          bool
	internalResolverReady    bool
	useIPv4                  bool
	useIPv6                  bool
	http3                    bool
	http3Probe               bool
	tlsDisableSessionTickets bool
	tlsPreferRSA             bool
	proxyDialer              *netproxy.Dialer
	httpProxyFunction        func(*http.Request) (*url.URL, error)
	tlsClientCreds           DOHClientCreds
	keyLogWriter             io.Writer

	// Hot-path pools / coalescing
	gzipPool     sync.Pool
	resolveGroup singleflight.Group

	// QUIC UDP socket reuse (min churn, lower tail latency)
	quicMu   sync.Mutex
	quicUDP4 *net.UDPConn
	quicUDP6 *net.UDPConn
	quicTr4  *quic.Transport
	quicTr6  *quic.Transport
}


func NewXTransport() *XTransport {
	if err := isIPAndPort(DefaultBootstrapResolver); err != nil {
		panic("DefaultBootstrapResolver does not parse")
	}
	xTransport := XTransport{
		cachedIPs:                CachedIPs{cache: make(map[string]*CachedIPItem)},
		altSupport:               AltSupport{cache: make(map[string]uint16)},
		keepAlive:                DefaultKeepAlive,
		timeout:                  DefaultTimeout,
		bootstrapResolvers:       []string{DefaultBootstrapResolver},
		mainProto:                "",
		ignoreSystemDNS:          true,
		useIPv4:                  true,
		useIPv6:                  false,
		http3Probe:               false,
		tlsDisableSessionTickets: false,
		tlsPreferRSA:             false,
		keyLogWriter:             nil,
	}
	
	xTransport.gzipPool.New = func() any { return new(gzip.Reader) }

return &xTransport
}

func ParseIP(ipStr string) net.IP {
	return net.ParseIP(strings.TrimRight(strings.TrimLeft(ipStr, "["), "]"))
}

// If ttl < 0, never expire
// Otherwise, ttl is set to max(ttl, MinResolverIPTTL)
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

func (xTransport *XTransport) saveCachedIPs(host string, ips []net.IP, ttl time.Duration) {
	normalized := uniqueNormalizedIPs(ips)
	if len(normalized) == 0 {
		return
	}
	item := &CachedIPItem{ips: normalized}
	if ttl >= 0 {
		if ttl < MinResolverIPTTL {
			ttl = MinResolverIPTTL
		}
		ttl += time.Duration(rand.Int63n(int64(ResolverIPTTLMaxJitter)))
		expiration := time.Now().Add(ttl)
		item.expiration = &expiration
	}
	xTransport.cachedIPs.Lock()
	item.updatingUntil = nil
	xTransport.cachedIPs.cache[host] = item
	xTransport.cachedIPs.Unlock()
	if len(normalized) == 1 {
		dlog.Debugf("[%s] cached IP [%s], valid for %v", host, normalized[0], ttl)
	} else {
		dlog.Debugf("[%s] cached %d IP addresses (first: %s), valid for %v", host, len(normalized), normalized[0], ttl)
	}
}

func (xTransport *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	if ip == nil {
		return
	}
	xTransport.saveCachedIPs(host, []net.IP{ip}, ttl)
}

// Mark an entry as being updated
func (xTransport *XTransport) markUpdatingCachedIP(host string) {
	xTransport.cachedIPs.Lock()
	item, ok := xTransport.cachedIPs.cache[host]
	if ok {
		now := time.Now()
		until := now.Add(xTransport.timeout)
		item.updatingUntil = &until
		xTransport.cachedIPs.cache[host] = item
		dlog.Debugf("[%s] IP address marked as updating", host)
	}
	xTransport.cachedIPs.Unlock()
}

func (xTransport *XTransport) loadCachedIPs(host string) (ips []net.IP, expired bool, updating bool) {
	ips = nil
	xTransport.cachedIPs.RLock()
	item, ok := xTransport.cachedIPs.cache[host]
	if !ok {
		xTransport.cachedIPs.RUnlock()
		dlog.Debugf("[%s] IP address not found in the cache", host)
		return nil, false, false
	}
	// Return cached slices directly (treated as immutable) to avoid allocations on the dial hot-path.
	ips = item.ips
	expiration := item.expiration
	updatingUntil := item.updatingUntil
	xTransport.cachedIPs.RUnlock()
	if expiration != nil && time.Until(*expiration) < 0 {
		expired = true
		if updatingUntil != nil && time.Until(*updatingUntil) > 0 {
			updating = true
			dlog.Debugf("[%s] cached IP addresses are being updated", host)
		} else {
			dlog.Debugf("[%s] cached IP addresses expired, not being updated yet", host)
		}
	}
	return ips, expired, updating
}

func (xTransport *XTransport) getGzipReader(r io.Reader) (*gzip.Reader, error) {
	gr := xTransport.gzipPool.Get().(*gzip.Reader)
	if err := gr.Reset(r); err != nil {
		xTransport.gzipPool.Put(gr)
		return nil, err
	}
	return gr, nil
}

func (xTransport *XTransport) putGzipReader(gr *gzip.Reader) {
	_ = gr.Close()
	xTransport.gzipPool.Put(gr)
}

func (xTransport *XTransport) getQUICTransport(network string) (*quic.Transport, error) {
	xTransport.quicMu.Lock()
	defer xTransport.quicMu.Unlock()

	const sockBuf = 4 << 20 // 4 MiB
	switch network {
	case "udp4":
		if xTransport.quicTr4 != nil {
			return xTransport.quicTr4, nil
		}
		c, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return nil, err
		}
		_ = c.SetReadBuffer(sockBuf)
		_ = c.SetWriteBuffer(sockBuf)
		xTransport.quicUDP4 = c
		xTransport.quicTr4 = &quic.Transport{Conn: c}
		return xTransport.quicTr4, nil
	case "udp6":
		if xTransport.quicTr6 != nil {
			return xTransport.quicTr6, nil
		}
		c, err := net.ListenUDP("udp6", nil)
		if err != nil {
			return nil, err
		}
		_ = c.SetReadBuffer(sockBuf)
		_ = c.SetWriteBuffer(sockBuf)
		xTransport.quicUDP6 = c
		xTransport.quicTr6 = &quic.Transport{Conn: c}
		return xTransport.quicTr6, nil
	default:
		return nil, errors.New("unsupported quic network: " + network)
	}
}


func (xTransport *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport")
	if xTransport.transport != nil {
		xTransport.transport.CloseIdleConnections()
	}

	if xTransport.h3Transport != nil {
		xTransport.h3Transport.Close()
		xTransport.h3Transport = nil
	}
	xTransport.quicMu.Lock()
	if xTransport.quicTr4 != nil {
		_ = xTransport.quicTr4.Close()
		xTransport.quicTr4 = nil
	}
	if xTransport.quicTr6 != nil {
		_ = xTransport.quicTr6.Close()
		xTransport.quicTr6 = nil
	}
	if xTransport.quicUDP4 != nil {
		_ = xTransport.quicUDP4.Close()
		xTransport.quicUDP4 = nil
	}
	if xTransport.quicUDP6 != nil {
		_ = xTransport.quicUDP6.Close()
		xTransport.quicUDP6 = nil
	}
	xTransport.quicMu.Unlock()
	timeout := xTransport.timeout
	transport := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true,
		MaxIdleConns:           1000,
		MaxConnsPerHost:        100,
		IdleConnTimeout:        xTransport.keepAlive,
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

			cachedIPs, _, _ := xTransport.loadCachedIPs(host)
			targets := make([]string, 0, len(cachedIPs))
			for _, ip := range cachedIPs {
				targets = append(targets, formatEndpoint(ip))
			}
			if len(targets) == 0 {
				dlog.Debugf("[%s] IP address was not cached in DialContext", host)
				targets = append(targets, formatEndpoint(nil))
			}

			dial := func(address string) (net.Conn, error) {
				if xTransport.proxyDialer == nil {
					dialer := &net.Dialer{Timeout: timeout, KeepAlive: xTransport.keepAlive, DualStack: true}
					return dialer.DialContext(ctx, network, address)
				}
				return (*xTransport.proxyDialer).Dial(network, address)
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
		},
	}
	if xTransport.httpProxyFunction != nil {
		transport.Proxy = xTransport.httpProxyFunction
	}

	clientCreds := xTransport.tlsClientCreds

	tlsClientConfig := tls.Config{}
	certPool, certPoolErr := x509.SystemCertPool()

	if xTransport.keyLogWriter != nil {
		tlsClientConfig.KeyLogWriter = xTransport.keyLogWriter
	}

	if clientCreds.rootCA != "" {
		if certPool == nil {
			dlog.Fatalf("Additional CAs not supported on this platform: %v", certPoolErr)
		}
		additionalCaCert, err := os.ReadFile(clientCreds.rootCA)
		if err != nil {
			dlog.Fatalf("Unable to read rootCA file [%s]: %v", clientCreds.rootCA, err)
		}
		certPool.AppendCertsFromPEM(additionalCaCert)
	}

	if certPool != nil {
		// Some operating systems don't include Let's Encrypt ISRG Root X1 certificate yet
		letsEncryptX1Cert := []byte(`-----BEGIN CERTIFICATE-----
 MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygch77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6UA5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sWT8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyHB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UCB5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUvKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWnOlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTnjh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbwqHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CIrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkqhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZLubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KKNFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7UrTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdCjNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVcoyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPAmRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57demyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
 -----END CERTIFICATE-----`)
		certPool.AppendCertsFromPEM(letsEncryptX1Cert)
		tlsClientConfig.RootCAs = certPool
	}

	if clientCreds.clientCert != "" {
		cert, err := tls.LoadX509KeyPair(clientCreds.clientCert, clientCreds.clientKey)
		if err != nil {
			dlog.Fatalf(
				"Unable to use certificate [%v] (key: [%v]): %v",
				clientCreds.clientCert,
				clientCreds.clientKey,
				err,
			)
		}
		tlsClientConfig.Certificates = []tls.Certificate{cert}
	}

	if xTransport.tlsDisableSessionTickets {
		tlsClientConfig.SessionTicketsDisabled = true
	} else {
		tlsClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(4096)
	}
	if xTransport.tlsPreferRSA {
		tlsClientConfig.MaxVersion = tls.VersionTLS13
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
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			}
		}
	}
	transport.TLSClientConfig = &tlsClientConfig
	if http2Transport, _ := http2.ConfigureTransports(transport); http2Transport != nil {
		http2Transport.ReadIdleTimeout = timeout
		http2Transport.AllowHTTP = false
	}
	xTransport.transport = transport
	xTransport.httpClient = &http.Client{Transport: xTransport.transport}
	if xTransport.http3 {
		dial := func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			dlog.Debugf("Dialing for H3: [%v]", addrStr)
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
				} else if xTransport.useIPv6 {
					if xTransport.useIPv4 {
						network = "udp"
					} else {
						network = "udp6"
					}
				}
				return udpTarget{addr: addr + ":" + strconv.Itoa(port), network: network}
			}

			cachedIPs, _, _ := xTransport.loadCachedIPs(host)
			targets := make([]udpTarget, 0, len(cachedIPs))
			for _, ip := range cachedIPs {
				targets = append(targets, buildAddr(ip))
			}
			if len(targets) == 0 {
				dlog.Debugf("[%s] IP address was not cached in H3 context", host)
				targets = append(targets, buildAddr(nil))
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
				tr, err := xTransport.getQUICTransport(target.network)
				if err != nil {
					lastErr = err
					if idx < len(targets)-1 {
						dlog.Debugf("H3: failed to listen for [%s] on %s: %v", target.addr, target.network, err)
					}
					continue
				}
				tlsCfg.ServerName = host
				if cfg != nil && cfg.KeepAlivePeriod == 0 {
					cfg.KeepAlivePeriod = 15 * time.Second
				}
				conn, err := tr.DialEarly(ctx, udpAddr, tlsCfg, cfg)
				if err != nil {
					/* transport-owned socket */
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
		h3Transport := &http3.Transport{DisableCompression: true, TLSClientConfig: &tlsClientConfig, Dial: dial}
		xTransport.h3Transport = h3Transport
	xTransport.h3Client = &http.Client{Transport: xTransport.h3Transport}
	}
}

func (xTransport *XTransport) resolveUsingSystem(host string, returnIPv4, returnIPv6 bool) ([]net.IP, time.Duration, error) {
	ipa, err := net.LookupIP(host)
	if returnIPv4 && returnIPv6 {
		return ipa, SystemResolverIPTTL, err
	}
	ips := make([]net.IP, 0)
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

func (xTransport *XTransport) resolveUsingResolver(
	proto, host string,
	resolver string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
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
						ips = append(ips, answer.(*dns.A).A.Addr.AsSlice())
					case dns.TypeAAAA:
						ips = append(ips, answer.(*dns.AAAA).AAAA.Addr.AsSlice())
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

func (xTransport *XTransport) resolveUsingServers(
	proto, host string,
	resolvers []string,
	returnIPv4, returnIPv6 bool,
) (ips []net.IP, ttl time.Duration, err error) {
	if len(resolvers) == 0 {
		return nil, 0, errors.New("Empty resolvers")
	}
	var lastErr error
	for i, resolver := range resolvers {
		delay := resolverRetryInitialBackoff
		for attempt := 1; attempt <= resolverRetryCount; attempt++ {
			ips, ttl, err = xTransport.resolveUsingResolver(proto, host, resolver, returnIPv4, returnIPv6)
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
			dlog.Debugf("Resolver attempt %d failed for [%s] using [%s] (%s): %v", attempt, host, resolver, proto, err)
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
		lastErr = errors.New("no IP addresses returned")
	}
	return nil, 0, lastErr
}

func (xTransport *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) (ips []net.IP, ttl time.Duration, err error) {
	protos := []string{"udp", "tcp"}
	if xTransport.mainProto == "tcp" {
		protos = []string{"tcp", "udp"}
	}
	if xTransport.ignoreSystemDNS {
		if xTransport.internalResolverReady {
			for _, proto := range protos {
				ips, ttl, err = xTransport.resolveUsingServers(proto, host, xTransport.internalResolvers, returnIPv4, returnIPv6)
				if err == nil {
					break
				}
			}
		} else {
			err = errors.New("dnscrypt-proxy service is not usable yet")
			dlog.Notice(err)
		}
	} else {
		ips, ttl, err = xTransport.resolveUsingSystem(host, returnIPv4, returnIPv6)
		if err != nil {
			err = errors.New("System DNS is not usable yet")
			dlog.Notice(err)
		}
	}
	if err != nil {
		for _, proto := range protos {
			if err != nil {
				dlog.Noticef(
					"Resolving server host [%s] using bootstrap resolvers over %s",
					host,
					proto,
				)
			}
			ips, ttl, err = xTransport.resolveUsingServers(proto, host, xTransport.bootstrapResolvers, returnIPv4, returnIPv6)
			if err == nil {
				break
			}
		}
	}
	if err != nil && xTransport.ignoreSystemDNS {
		dlog.Noticef("Bootstrap resolvers didn't respond - Trying with the system resolver as a last resort")
		ips, ttl, err = xTransport.resolveUsingSystem(host, returnIPv4, returnIPv6)
	}
	return ips, ttl, err
}

// If a name is not present in the cache, resolve the name and update the cache
func (xTransport *XTransport) resolveAndUpdateCache(host string) error {
	if xTransport.proxyDialer != nil || xTransport.httpProxyFunction != nil {
		return nil
	}
	if ParseIP(host) != nil {
		return nil
	}

	cachedIPs, expired, updating := xTransport.loadCachedIPs(host)
	if len(cachedIPs) > 0 {
		// Never block the request path when stale data exists; refresh in background.
		if expired && !updating {
			xTransport.markUpdatingCachedIP(host)
			go func(stale []net.IP) {
				_ = xTransport.resolveAndUpdateCacheBlocking(host, stale)
			}(cachedIPs)
		}
		return nil
	}

	_, err, _ := xTransport.resolveGroup.Do(host, func() (any, error) {
		return nil, xTransport.resolveAndUpdateCacheBlocking(host, nil)
	})
	return err
}

func (xTransport *XTransport) resolveAndUpdateCacheBlocking(host string, cachedIPs []net.IP) error {
	ips, ttl, err := xTransport.resolve(host, xTransport.useIPv4, xTransport.useIPv6)
	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}

	selectedIPs := ips
	if (err != nil || len(selectedIPs) == 0) && len(cachedIPs) > 0 {
		dlog.Noticef("Using stale [%v] cached address for a grace period", host)
		selectedIPs = cachedIPs
		ttl = ExpiredCachedIPGraceTTL
		err = nil
	}
	if err != nil {
		return err
	}

	if len(selectedIPs) == 0 {
		if !xTransport.useIPv4 && xTransport.useIPv6 {
			dlog.Warnf("no IPv6 address found for [%s]", host)
		} else if xTransport.useIPv4 && !xTransport.useIPv6 {
			dlog.Warnf("no IPv4 address found for [%s]", host)
		} else {
			dlog.Errorf("no IP address found for [%s]", host)
		}
		return nil
	}

	xTransport.saveCachedIPs(host, selectedIPs, ttl)
	return nil
}


func (xTransport *XTransport) Fetch(
	method string,
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
	compress bool,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if timeout <= 0 {
		timeout = xTransport.timeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	host, port := ExtractHostAndPort(url.Host, 443)
	hasAltSupport := false

	client := xTransport.httpClient
	if client == nil {
		client = &http.Client{Transport: xTransport.transport}
	}

	if xTransport.h3Transport != nil {
		if xTransport.http3Probe {
			if xTransport.h3Client != nil {
				client = xTransport.h3Client
			}
			dlog.Debugf("Probing HTTP/3 transport for [%s]", url.Host)
		} else {
			xTransport.altSupport.RLock()
			var altPort uint16
			altPort, hasAltSupport = xTransport.altSupport.cache[url.Host]
			xTransport.altSupport.RUnlock()
			if hasAltSupport && altPort > 0 {
				if int(altPort) == port {
					if xTransport.h3Client != nil {
						client = xTransport.h3Client
					}
					dlog.Debugf("Using HTTP/3 transport for [%s]", url.Host)
				}
			}
		}
	}

	header := map[string][]string{"User-Agent": {"dnscrypt-proxy"}}
	if len(accept) > 0 {
		header["Accept"] = []string{accept}
	}
	if len(contentType) > 0 {
		header["Content-Type"] = []string{contentType}
	}
	header["Cache-Control"] = []string{"max-stale"}

	if body != nil {
		h := sha512.Sum512(*body)
		qs := url.Query()
		qs.Add("body_hash", hex.EncodeToString(h[:32]))
		url2 := *url
		url2.RawQuery = qs.Encode()
		url = &url2
	}

	if xTransport.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, nil, 0, errors.New("Onion service is not reachable without Tor")
	}

	if err := xTransport.resolveAndUpdateCache(host); err != nil {
		dlog.Errorf(
			"Unable to resolve [%v] - Make sure that the system resolver works, or that `bootstrap_resolvers` has been set to resolvers that can be reached",
			host,
		)
		return nil, 0, nil, 0, err
	}

	if compress && body == nil {
		header["Accept-Encoding"] = []string{"gzip"}
	}

	req := &http.Request{
		Method: method,
		URL:    url,
		Header: header,
		Close:  false,
	}
	req = req.WithContext(ctx)

	if body != nil {
		req.ContentLength = int64(len(*body))
		req.Body = io.NopCloser(bytes.NewReader(*body))
	}

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	// Handle HTTP/3 error case - fallback to HTTP/2 when HTTP/3 fails
	if err != nil && xTransport.h3Client != nil && client == xTransport.h3Client {
		if xTransport.http3Probe {
			dlog.Debugf("HTTP/3 probe failed for [%s]: [%s] - falling back to HTTP/2", url.Host, err)
		} else {
			dlog.Debugf("HTTP/3 connection failed for [%s]: [%s] - falling back to HTTP/2", url.Host, err)
		}

		// Add server to negative cache when HTTP/3 fails
		xTransport.altSupport.Lock()
		xTransport.altSupport.cache[url.Host] = 0
		xTransport.altSupport.Unlock()

		// Retry with HTTP/2
		client = xTransport.httpClient
		if client == nil {
			client = &http.Client{Transport: xTransport.transport}
		}
		start = time.Now()
		resp, err = client.Do(req)
		rtt = time.Since(start)
	}

	if err == nil {
		if resp == nil {
			err = errors.New("Webserver returned an error")
		} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
			err = errors.New(resp.Status)
		}
	} else {
		dlog.Debugf("HTTP client error: [%v] - closing idle connections", err)
		if xTransport.transport != nil {
			xTransport.transport.CloseIdleConnections()
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

	if xTransport.h3Transport != nil && !hasAltSupport {
		skipAltSvcParsing := false
		if xTransport.http3Probe {
			xTransport.altSupport.RLock()
			altPort, inCache := xTransport.altSupport.cache[url.Host]
			xTransport.altSupport.RUnlock()
			if inCache && altPort == 0 {
				dlog.Debugf("Skipping Alt-Svc parsing for [%s] - previously failed HTTP/3 probe", url.Host)
				skipAltSvcParsing = true
			}
		}
		if !skipAltSvcParsing {
			if alt, found := resp.Header["Alt-Svc"]; found {
				dlog.Debugf("Alt-Svc [%s]: [%s]", url.Host, alt)
				altPort := uint16(port & 0xffff)
				for i, xalt := range alt {
					for j, v := range strings.Split(xalt, ";") {
						if i >= 8 || j >= 16 {
							break
						}
						v = strings.TrimSpace(v)
						if strings.HasPrefix(v, "h3=\":") {
							v = strings.TrimPrefix(v, "h3=\":")
							v = strings.TrimSuffix(v, "\"")
							if xAltPort, err := strconv.ParseUint(v, 10, 16); err == nil && xAltPort <= 65535 {
								altPort = uint16(xAltPort)
								dlog.Debugf("Using HTTP/3 for [%s]", url.Host)
								break
							}
						}
					}
				}
				xTransport.altSupport.Lock()
				xTransport.altSupport.cache[url.Host] = altPort
				dlog.Debugf("Caching altPort for [%v]", url.Host)
				xTransport.altSupport.Unlock()
			}
		}
	}

	tlsState := resp.TLS
	var bodyReader io.Reader = resp.Body
	var gr *gzip.Reader

	if compress && resp.Header.Get("Content-Encoding") == "gzip" {
		limited := io.LimitReader(resp.Body, MaxHTTPBodyLength)
		gr, err = xTransport.getGzipReader(limited)
		if err != nil {
			return nil, statusCode, tlsState, rtt, err
		}
		defer xTransport.putGzipReader(gr)
		bodyReader = gr
	}

	bin, err := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))
	if err != nil {
		return nil, statusCode, tlsState, rtt, err
	}
	return bin, statusCode, tlsState, rtt, nil
}


func (xTransport *XTransport) GetWithCompression(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.Fetch("GET", url, accept, "", nil, timeout, true)
}

func (xTransport *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.Fetch("GET", url, accept, "", nil, timeout, false)
}

func (xTransport *XTransport) Post(
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.Fetch("POST", url, accept, contentType, body, timeout, false)
}

func (xTransport *XTransport) dohLikeQuery(
	dataType string,
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	if useGet {
		qs := url.Query()
		encBody := base64.RawURLEncoding.EncodeToString(body)
		qs.Add("dns", encBody)
		url2 := *url
		url2.RawQuery = qs.Encode()
		return xTransport.Get(&url2, dataType, timeout)
	}
	return xTransport.Post(url, dataType, dataType, &body, timeout)
}

func (xTransport *XTransport) DoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.dohLikeQuery("application/dns-message", useGet, url, body, timeout)
}

func (xTransport *XTransport) ObliviousDoHQuery(
	useGet bool,
	url *url.URL,
	body []byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.dohLikeQuery("application/oblivious-dns-message", useGet, url, body, timeout)
}
