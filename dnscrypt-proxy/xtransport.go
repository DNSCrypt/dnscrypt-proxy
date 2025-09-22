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

	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	netproxy "golang.org/x/net/proxy"
)

const (
	DefaultBootstrapResolver = "9.9.9.9:53"
	DefaultKeepAlive         = 5 * time.Second
	DefaultTimeout           = 30 * time.Second
	ResolverReadTimeout      = 5 * time.Second
	SystemResolverIPTTL      = 12 * time.Hour
	MinResolverIPTTL         = 4 * time.Hour
	ResolverIPTTLMaxJitter   = 15 * time.Minute
	ExpiredCachedIPGraceTTL  = 15 * time.Minute
)

type CachedIPItem struct {
	ip            net.IP
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
	transport                *http.Transport
	h3Transport              *http3.Transport
	keepAlive                time.Duration
	timeout                  time.Duration
	cachedIPs                CachedIPs
	altSupport               AltSupport
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
	tlsCipherSuite           []uint16
	proxyDialer              *netproxy.Dialer
	httpProxyFunction        func(*http.Request) (*url.URL, error)
	tlsClientCreds           DOHClientCreds
	keyLogWriter             io.Writer
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
		tlsCipherSuite:           nil,
		keyLogWriter:             nil,
	}
	return &xTransport
}

func ParseIP(ipStr string) net.IP {
	return net.ParseIP(strings.TrimRight(strings.TrimLeft(ipStr, "["), "]"))
}

// If ttl < 0, never expire
// Otherwise, ttl is set to max(ttl, MinResolverIPTTL)
func (xTransport *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	item := &CachedIPItem{ip: ip, expiration: nil, updatingUntil: nil}
	if ttl >= 0 {
		if ttl < MinResolverIPTTL {
			ttl = MinResolverIPTTL
		}
		ttl += time.Duration(rand.Int63n(int64(ResolverIPTTLMaxJitter)))
		expiration := time.Now().Add(ttl)
		item.expiration = &expiration
	}
	xTransport.cachedIPs.Lock()
	xTransport.cachedIPs.cache[host] = item
	xTransport.cachedIPs.Unlock()
	dlog.Debugf("[%s] IP address [%s] stored to the cache, valid for %v", host, ip, ttl)
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
		dlog.Debugf("[%s] IP addresss marked as updating", host)
	}
	xTransport.cachedIPs.Unlock()
}

func (xTransport *XTransport) loadCachedIP(host string) (ip net.IP, expired bool, updating bool) {
	ip, expired, updating = nil, false, false
	xTransport.cachedIPs.RLock()
	item, ok := xTransport.cachedIPs.cache[host]
	xTransport.cachedIPs.RUnlock()
	if !ok {
		dlog.Debugf("[%s] IP address not found in the cache", host)
		return ip, expired, updating
	}
	ip = item.ip
	expiration := item.expiration
	if expiration != nil && time.Until(*expiration) < 0 {
		expired = true
		if item.updatingUntil != nil && time.Until(*item.updatingUntil) > 0 {
			updating = true
			dlog.Debugf("[%s] IP address is being updated", host)
		} else {
			dlog.Debugf("[%s] IP address expired, not being updated yet", host)
		}
	}
	return ip, expired, updating
}

func (xTransport *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport")
	if xTransport.transport != nil {
		xTransport.transport.CloseIdleConnections()
	}
	timeout := xTransport.timeout
	transport := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true,
		MaxIdleConns:           1,
		IdleConnTimeout:        xTransport.keepAlive,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  timeout,
		MaxResponseHeaderBytes: 4096,
		DialContext: func(ctx context.Context, network, addrStr string) (net.Conn, error) {
			host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
			ipOnly := host
			// resolveAndUpdateCache() is always called in `Fetch()` before the `Dial()`
			// method is used, so that a cached entry must be present at this point.
			cachedIP, _, _ := xTransport.loadCachedIP(host)
			if cachedIP != nil {
				if ipv4 := cachedIP.To4(); ipv4 != nil {
					ipOnly = ipv4.String()
				} else {
					ipOnly = "[" + cachedIP.String() + "]"
				}
			} else {
				dlog.Debugf("[%s] IP address was not cached in DialContext", host)
			}
			addrStr = ipOnly + ":" + strconv.Itoa(port)
			if xTransport.proxyDialer == nil {
				dialer := &net.Dialer{Timeout: timeout, KeepAlive: timeout, DualStack: true}
				return dialer.DialContext(ctx, network, addrStr)
			}
			return (*xTransport.proxyDialer).Dial(network, addrStr)
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
			dlog.Fatal(err)
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

	overrideCipherSuite := len(xTransport.tlsCipherSuite) > 0
	if xTransport.tlsDisableSessionTickets || overrideCipherSuite {
		tlsClientConfig.SessionTicketsDisabled = xTransport.tlsDisableSessionTickets
		if !xTransport.tlsDisableSessionTickets {
			tlsClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(10)
		}
		if overrideCipherSuite {
			tlsClientConfig.PreferServerCipherSuites = false
			tlsClientConfig.CipherSuites = xTransport.tlsCipherSuite

			// Go doesn't allow changing the cipher suite with TLS 1.3
			// So, check if the requested set of ciphers matches the TLS 1.3 suite.
			// If it doesn't, downgrade to TLS 1.2
			compatibleSuitesCount := 0
			for _, suite := range tls.CipherSuites() {
				if suite.Insecure {
					continue
				}
				for _, supportedVersion := range suite.SupportedVersions {
					if supportedVersion == tls.VersionTLS12 {
						for _, expectedSuiteID := range xTransport.tlsCipherSuite {
							if expectedSuiteID == suite.ID {
								compatibleSuitesCount += 1
								break
							}
						}
					}
				}
			}
			if compatibleSuitesCount != len(tls.CipherSuites()) {
				dlog.Notice("Explicit cipher suite configured - downgrading to TLS 1.2")
				tlsClientConfig.MaxVersion = tls.VersionTLS12
			}
		}
	}
	transport.TLSClientConfig = &tlsClientConfig
	if http2Transport, err := http2.ConfigureTransports(transport); err != nil {
		http2Transport.ReadIdleTimeout = timeout
		http2Transport.AllowHTTP = false
	}
	xTransport.transport = transport
	if xTransport.http3 {
		dial := func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			dlog.Debugf("Dialing for H3: [%v]", addrStr)
			host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
			ipOnly := host
			cachedIP, _, _ := xTransport.loadCachedIP(host)
			network := "udp4"
			if cachedIP != nil {
				if ipv4 := cachedIP.To4(); ipv4 != nil {
					ipOnly = ipv4.String()
				} else {
					ipOnly = "[" + cachedIP.String() + "]"
					network = "udp6"
				}
			} else {
				dlog.Debugf("[%s] IP address was not cached in H3 context", host)
				if xTransport.useIPv6 {
					if xTransport.useIPv4 {
						network = "udp"
					} else {
						network = "udp6"
					}
				}
			}
			addrStr = ipOnly + ":" + strconv.Itoa(port)
			udpAddr, err := net.ResolveUDPAddr(network, addrStr)
			if err != nil {
				return nil, err
			}
			udpConn, err := net.ListenUDP(network, nil)
			if err != nil {
				return nil, err
			}
			tlsCfg.ServerName = host
			conn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
			if err != nil {
				udpConn.Close()
				return nil, err
			}
			return conn, nil
		}
		h3Transport := &http3.Transport{DisableCompression: true, TLSClientConfig: &tlsClientConfig, Dial: dial}
		xTransport.h3Transport = h3Transport
	}
}

func (xTransport *XTransport) resolveUsingSystem(host string, forceType uint16) ([]net.IP, time.Duration, error) {
	ipa, err := net.LookupIP(host)
	queryIPv4 := xTransport.useIPv4
	queryIPv6 := xTransport.useIPv6
	if forceType == dns.TypeNone && queryIPv4 && queryIPv6 {
		return ipa, SystemResolverIPTTL, err
	}
	switch forceType {
	case dns.TypeA:
		queryIPv4 = true
		queryIPv6 = false
	case dns.TypeAAAA:
		queryIPv4 = false
		queryIPv6 = true
	}
	ips := make([]net.IP, 0)
	for _, ip := range ipa {
		ipv4 := ip.To4()
		if queryIPv4 && ipv4 != nil {
			ips = append(ips, ipv4)
		}
		if queryIPv6 && ipv4 == nil {
			ips = append(ips, ip)
		}
	}
	return ips, SystemResolverIPTTL, err
}

func (xTransport *XTransport) resolveUsingResolver(
	proto, host string,
	resolver string,
	forceType uint16,
) (ips []net.IP, ttl time.Duration, err error) {
	dnsClient := dns.Client{Net: proto, ReadTimeout: ResolverReadTimeout}
	queryType := make([]uint16, 0, 2)
	switch forceType {
	case dns.TypeA:
		queryType = append(queryType, dns.TypeA)
	case dns.TypeAAAA:
		queryType = append(queryType, dns.TypeAAAA)
	default:
		if xTransport.useIPv4 {
			queryType = append(queryType, dns.TypeA)
		}
		if xTransport.useIPv6 {
			queryType = append(queryType, dns.TypeAAAA)
		}
	}
	var rrTTL uint32
	for _, rrType := range queryType {
		msg := dns.Msg{}
		msg.SetQuestion(dns.Fqdn(host), rrType)
		msg.SetEdns0(uint16(MaxDNSPacketSize), true)
		var in *dns.Msg
		if in, _, err = dnsClient.Exchange(&msg, resolver); err == nil {
			for _, answer := range in.Answer {
				if answer.Header().Rrtype == rrType {
					switch rrType {
					case dns.TypeA:
						ips = append(ips, answer.(*dns.A).A)
					case dns.TypeAAAA:
						ips = append(ips, answer.(*dns.AAAA).AAAA)
					}
					rrTTL = answer.Header().Ttl
				}
			}
		}
	}
	if len(ips) > 0 {
		ttl = time.Duration(rrTTL) * time.Second
	}
	return ips, ttl, err
}

func (xTransport *XTransport) resolveUsingResolvers(
	proto, host string,
	resolvers []string,
	forceType uint16,
) (ips []net.IP, ttl time.Duration, err error) {
	err = errors.New("Empty resolvers")
	for i, resolver := range resolvers {
		ips, ttl, err = xTransport.resolveUsingResolver(proto, host, resolver, forceType)
		if err == nil {
			if i > 0 {
				dlog.Infof("Resolution succeeded with resolver %s[%s]", proto, resolver)
				resolvers[0], resolvers[i] = resolvers[i], resolvers[0]
			}
			break
		}
		dlog.Infof("Unable to resolve [%s] using resolver [%s] (%s): %v", host, resolver, proto, err)
	}
	return ips, ttl, err
}

func (xTransport *XTransport) resolveEncrypted(host string, forceType uint16) ([]net.IP, time.Duration, error) {
	return xTransport.resolveUsingResolvers(xTransport.mainProto, host, xTransport.internalResolvers, forceType)
}

func (xTransport *XTransport) resolve(host string, forceType uint16) (ips []net.IP, ttl time.Duration, err error) {
	protos := []string{"udp", "tcp"}
	if xTransport.mainProto == "tcp" {
		protos = []string{"tcp", "udp"}
	}
	if xTransport.ignoreSystemDNS {
		if xTransport.internalResolverReady {
			for _, proto := range protos {
				ips, ttl, err = xTransport.resolveUsingResolvers(proto, host, xTransport.internalResolvers, forceType)
				if err == nil {
					break
				}
			}
		} else {
			err = errors.New("dnscrypt-proxy service is not usable yet")
			dlog.Notice(err)
		}
	} else {
		ips, ttl, err = xTransport.resolveUsingSystem(host, forceType)
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
			ips, ttl, err = xTransport.resolveUsingResolvers(proto, host, xTransport.bootstrapResolvers, forceType)
			if err == nil {
				break
			}
		}
	}
	if err != nil && xTransport.ignoreSystemDNS {
		dlog.Noticef("Bootstrap resolvers didn't respond - Trying with the system resolver as a last resort")
		ips, ttl, err = xTransport.resolveUsingSystem(host, forceType)
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
	cachedIP, expired, updating := xTransport.loadCachedIP(host)
	if cachedIP != nil && (!expired || updating) {
		return nil
	}
	xTransport.markUpdatingCachedIP(host)

	var foundIP net.IP
	ips, ttl, err := xTransport.resolve(host, dns.TypeNone)
	if len(ips) > 0 {
		foundIP = ips[rand.Intn(len(ips))]
	}
	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}
	if err != nil {
		if cachedIP != nil {
			dlog.Noticef("Using stale [%v] cached address for a grace period", host)
			foundIP = cachedIP
			ttl = ExpiredCachedIPGraceTTL
		} else {
			return err
		}
	}
	if foundIP == nil {
		if !xTransport.useIPv4 && xTransport.useIPv6 {
			dlog.Warnf("no IPv6 address found for [%s]", host)
		} else if xTransport.useIPv4 && !xTransport.useIPv6 {
			dlog.Warnf("no IPv4 address found for [%s]", host)
		} else {
			dlog.Errorf("no IP address found for [%s]", host)
		}
	}
	xTransport.saveCachedIP(host, foundIP, ttl)
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
	client := http.Client{
		Transport: xTransport.transport,
		Timeout:   timeout,
	}
	host, port := ExtractHostAndPort(url.Host, 443)
	hasAltSupport := false

	if xTransport.h3Transport != nil {
		if xTransport.http3Probe {
			// Always try HTTP/3 first when http3_probe is enabled,
			// without checking for Alt-Svc
			client.Transport = xTransport.h3Transport
			dlog.Debugf("Probing HTTP/3 transport for [%s]", url.Host)
		} else {
			// Otherwise use traditional Alt-Svc detection
			xTransport.altSupport.RLock()
			var altPort uint16
			altPort, hasAltSupport = xTransport.altSupport.cache[url.Host]
			xTransport.altSupport.RUnlock()
			if hasAltSupport && altPort > 0 { // altPort > 0 ensures we're not in the negative cache
				if int(altPort) == port {
					client.Transport = xTransport.h3Transport
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
	if body != nil {
		req.ContentLength = int64(len(*body))
		req.Body = io.NopCloser(bytes.NewReader(*body))
	}
	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	// Handle HTTP/3 error case - fallback to HTTP/2 when HTTP/3 fails
	if err != nil && client.Transport == xTransport.h3Transport {
		if xTransport.http3Probe {
			dlog.Debugf("HTTP/3 probe failed for [%s]: [%s] - falling back to HTTP/2", url.Host, err)
		} else {
			dlog.Debugf("HTTP/3 connection failed for [%s]: [%s] - falling back to HTTP/2", url.Host, err)
		}

		// Add server to negative cache when HTTP/3 fails
		xTransport.altSupport.Lock()
		xTransport.altSupport.cache[url.Host] = 0 // 0 port means HTTP/3 failed and should not be tried again
		xTransport.altSupport.Unlock()

		// Retry with HTTP/2
		client.Transport = xTransport.transport
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
		xTransport.transport.CloseIdleConnections()
	}
	statusCode := 503
	if resp != nil {
		statusCode = resp.StatusCode
	}
	if err != nil {
		dlog.Debugf("[%s]: [%s]", req.URL, err)
		if xTransport.tlsCipherSuite != nil && strings.Contains(err.Error(), "handshake failure") {
			dlog.Warnf(
				"TLS handshake failure - Try changing or deleting the tls_cipher_suite value in the configuration file",
			)
			xTransport.tlsCipherSuite = nil
			xTransport.rebuildTransport()
		}
		return nil, statusCode, nil, rtt, err
	}
	if xTransport.h3Transport != nil && !hasAltSupport {
		// Check if there's entry in negative cache when using http3_probe
		skipAltSvcParsing := false
		if xTransport.http3Probe {
			xTransport.altSupport.RLock()
			altPort, inCache := xTransport.altSupport.cache[url.Host]
			xTransport.altSupport.RUnlock()
			// If server is in negative cache (altPort == 0), don't attempt to parse Alt-Svc header
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
	tls := resp.TLS

	var bodyReader io.ReadCloser = resp.Body
	if compress && resp.Header.Get("Content-Encoding") == "gzip" {
		bodyReader, err = gzip.NewReader(io.LimitReader(resp.Body, MaxHTTPBodyLength))
		if err != nil {
			return nil, statusCode, tls, rtt, err
		}
		defer bodyReader.Close()
	}

	bin, err := io.ReadAll(io.LimitReader(bodyReader, MaxHTTPBodyLength))
	if err != nil {
		return nil, statusCode, tls, rtt, err
	}
	resp.Body.Close()
	return bin, statusCode, tls, rtt, err
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
