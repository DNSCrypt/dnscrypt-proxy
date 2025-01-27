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
	SystemResolverIPTTL      = 24 * time.Hour
	MinResolverIPTTL         = 12 * time.Hour
	ExpiredCachedIPGraceTTL  = 15 * time.Minute
)

type CachedIPItem struct {
	ip         net.IP
	expiration *time.Time
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
	h3Transport              *http3.RoundTripper
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
	tlsDisableSessionTickets bool
	tlsCipherSuite           []uint16
	keepCipherSuite          bool
	CSHandleError            int
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
		tlsDisableSessionTickets: false,
		tlsCipherSuite:           nil,
		keepCipherSuite:          false,
		CSHandleError:            0,
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
	item := &CachedIPItem{ip: ip, expiration: nil}
	if ttl >= 0 {
		if ttl < MinResolverIPTTL {
			ttl = MinResolverIPTTL
		}
		expiration := time.Now().Add(ttl)
		item.expiration = &expiration
	}
	xTransport.cachedIPs.Lock()
	xTransport.cachedIPs.cache[host] = item
	xTransport.cachedIPs.Unlock()
}

func (xTransport *XTransport) loadCachedIP(host string) (ip net.IP, expired bool) {
	ip, expired = nil, false
	xTransport.cachedIPs.RLock()
	item, ok := xTransport.cachedIPs.cache[host]
	xTransport.cachedIPs.RUnlock()
	if !ok {
		return
	}
	ip = item.ip
	expiration := item.expiration
	if expiration != nil && time.Until(*expiration) < 0 {
		expired = true
	}
	return
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
			cachedIP, _ := xTransport.loadCachedIP(host)
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
	if xTransport.tlsDisableSessionTickets {
		tlsClientConfig.SessionTicketsDisabled = xTransport.tlsDisableSessionTickets
		tlsClientConfig.ClientSessionCache = nil
	} else {
		tlsClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(10)
	}
	if xTransport.tlsCipherSuite != nil && len(xTransport.tlsCipherSuite) > 0 && xTransport.keepCipherSuite == true {
		var tls13 = "198 199 4865 4866 4867 4868 4869 49332 49333"
		var only13 = 0
		var SuitesCount = 0
		for _, expectedSuiteID := range xTransport.tlsCipherSuite {
			check := strconv.Itoa(int(expectedSuiteID))
			if strings.Contains(tls13 , check) {
				SuitesCount += 1
			}
			only13 += 1 
		}
		if only13 != SuitesCount {
			tlsClientConfig.CipherSuites = xTransport.tlsCipherSuite
			dlog.Info("Explicit cipher suite configured downgrading to TLS 1.2")
			tlsClientConfig.MaxVersion = tls.VersionTLS12
			if xTransport.CSHandleError < 2 {
				xTransport.CSHandleError += 1
			}
		}
	} else {
		tlsClientConfig.MaxVersion = tls.VersionTLS13
	}
	transport.TLSClientConfig = &tlsClientConfig
	if http2Transport, err := http2.ConfigureTransports(transport); err != nil {
		http2Transport.ReadIdleTimeout = timeout
		http2Transport.AllowHTTP = false
	}
	xTransport.transport = transport
	if xTransport.http3 {
		dial := func(ctx context.Context, addrStr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			dlog.Debugf("Dialing for H3: [%v]", addrStr)
			host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
			ipOnly := host
			cachedIP, _ := xTransport.loadCachedIP(host)
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
			return quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
		}
		h3Transport := &http3.RoundTripper{DisableCompression: true, TLSClientConfig: &tlsClientConfig, Dial: dial}
		xTransport.h3Transport = h3Transport
	}
}

func (xTransport *XTransport) resolveUsingSystem(host string) (ip net.IP, ttl time.Duration, err error) {
	ttl = SystemResolverIPTTL
	var foundIPs []string
	foundIPs, err = net.LookupHost(host)
	if err != nil {
		return
	}
	ips := make([]net.IP, 0)
	for _, ip := range foundIPs {
		if foundIP := net.ParseIP(ip); foundIP != nil {
			if xTransport.useIPv4 {
				if ipv4 := foundIP.To4(); ipv4 != nil {
					ips = append(ips, foundIP)
				}
			}
			if xTransport.useIPv6 {
				if ipv6 := foundIP.To16(); ipv6 != nil {
					ips = append(ips, foundIP)
				}
			}
		}
	}
	if len(ips) > 0 {
		ip = ips[rand.Intn(len(ips))]
	}
	return
}

func (xTransport *XTransport) resolveUsingResolver(
	proto, host string,
	resolver string,
) (ip net.IP, ttl time.Duration, err error) {
	dnsClient := dns.Client{Net: proto}
	if xTransport.useIPv4 {
		msg := dns.Msg{}
		msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
		msg.SetEdns0(uint16(MaxDNSPacketSize), true)
		var in *dns.Msg
		if in, _, err = dnsClient.Exchange(&msg, resolver); err == nil {
			answers := make([]dns.RR, 0)
			for _, answer := range in.Answer {
				if answer.Header().Rrtype == dns.TypeA {
					answers = append(answers, answer)
				}
			}
			if len(answers) > 0 {
				answer := answers[rand.Intn(len(answers))]
				ip = answer.(*dns.A).A
				ttl = time.Duration(answer.Header().Ttl) * time.Second
				return
			}
		}
	}
	if xTransport.useIPv6 {
		msg := dns.Msg{}
		msg.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
		msg.SetEdns0(uint16(MaxDNSPacketSize), true)
		var in *dns.Msg
		if in, _, err = dnsClient.Exchange(&msg, resolver); err == nil {
			answers := make([]dns.RR, 0)
			for _, answer := range in.Answer {
				if answer.Header().Rrtype == dns.TypeAAAA {
					answers = append(answers, answer)
				}
			}
			if len(answers) > 0 {
				answer := answers[rand.Intn(len(answers))]
				ip = answer.(*dns.AAAA).AAAA
				ttl = time.Duration(answer.Header().Ttl) * time.Second
				return
			}
		}
	}
	return
}

func (xTransport *XTransport) resolveUsingResolvers(
	proto, host string,
	resolvers []string,
) (ip net.IP, ttl time.Duration, err error) {
	err = errors.New("Empty resolvers")
	for i, resolver := range resolvers {
		ip, ttl, err = xTransport.resolveUsingResolver(proto, host, resolver)
		if err == nil {
			dlog.Infof("Resolution succeeded with resolver %s[%s]", proto, resolver)
			resolvers[0], resolvers[i] = resolvers[i], resolvers[0]
			break
		}
		dlog.Infof("Unable to resolve [%s] using resolver [%s] (%s): %v", host, resolver, proto, err)
	}
	return
}

// If a name is not present in the cache, resolve the name and update the cache
func (xTransport *XTransport) resolveAndUpdateCache(host string) error {
	if xTransport.proxyDialer != nil || xTransport.httpProxyFunction != nil {
		return nil
	}
	if ParseIP(host) != nil {
		return nil
	}
	cachedIP, expired := xTransport.loadCachedIP(host)
	if cachedIP != nil && !expired {
		return nil
	}
	var foundIP net.IP
	var ttl time.Duration
	var err error
	protos := []string{"udp", "tcp"}
	if xTransport.mainProto == "tcp" {
		protos = []string{"tcp", "udp"}
	}
	if xTransport.internalResolverReady {
		for _, proto := range protos {
			foundIP, ttl, err = xTransport.resolveUsingResolvers(proto, host, xTransport.internalResolvers)
			if err == nil {
				break
			}
		}
	} else {
		err = errors.New("Service is not usable yet")
		dlog.Notice(err)
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
			foundIP, ttl, err = xTransport.resolveUsingResolvers(proto, host, xTransport.bootstrapResolvers)
			if err == nil {
				break
			}
		}
	}
	if err != nil && xTransport.ignoreSystemDNS == false {
		dlog.Noticef("Bootstrap resolvers didn't respond - Trying with the system resolver as a last resort")
		foundIP, ttl, err = xTransport.resolveUsingSystem(host)
		if err != nil {
			err = errors.New("System DNS error")
			dlog.Notice(err)
		}	
	}else if err != nil && xTransport.ignoreSystemDNS == true {
		dlog.Noticef("Bootstrap resolvers didn't respond and we are ignoring system dns")
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
	}else{
		xTransport.saveCachedIP(host, foundIP, ttl)
		dlog.Debugf("[%s] IP address [%s] added to the cache, valid for %v", host, foundIP, ttl)
	}
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
		xTransport.altSupport.RLock()
		var altPort uint16
		altPort, hasAltSupport = xTransport.altSupport.cache[url.Host]
		xTransport.altSupport.RUnlock()
		if hasAltSupport {
			if int(altPort) == port {
				client.Transport = xTransport.h3Transport
				dlog.Debugf("Using HTTP/3 transport for [%s]", url.Host)
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
	var statusCode int
	if resp != nil {
		statusCode = resp.StatusCode
	}
	if err == nil {
		if resp == nil {
			err = errors.New("Webserver returned an error")
		} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
			err = errors.New(resp.Status)
		}
	} else {
		dlog.Debugf("HTTP client error: [%v]", err)
		dlog.Debugf("[%s]: [%s]", req.URL, err)
		if xTransport.tlsCipherSuite != nil && xTransport.keepCipherSuite == true {
			dlog.Warnf(
				"TLS handshake failure with cipher suite: %v - Try changing or deleting the tls_cipher_suite value in the configuration file",
				xTransport.tlsCipherSuite,
			)
			if strings.Contains(err.Error(), "handshake failure") || strings.Contains(err.Error(), "tls: error decoding message") {
				if xTransport.CSHandleError == 1 {
					xTransport.CSHandleError += 1
					xTransport.keepCipherSuite = false
				}
			}
			xTransport.rebuildTransport()
		}
		return nil, statusCode, nil, rtt, err
	}
	if xTransport.h3Transport != nil && !hasAltSupport {
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
