package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
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
	ip         netip.Addr
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
	bootstrapResolvers       []string
	mainProto                string
	ignoreSystemDNS          bool
	useIPv4                  bool
	useIPv6                  bool
	http3                    bool
	tlsDisableSessionTickets bool
	tlsCipherSuite           []uint16
	proxyDialer              *netproxy.Dialer
	httpProxyFunction        func(*http.Request) (*url.URL, error)
	tlsClientCreds           DOHClientCreds
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
	}
	return &xTransport
}

func ParseIP(ipStr string) (netip.Addr, error) {
	return netip.ParseAddr(strings.TrimRight(strings.TrimLeft(ipStr, "["), "]"))
}

// If ttl < 0, never expire
// Otherwise, ttl is set to max(ttl, MinResolverIPTTL)
func (xTransport *XTransport) saveCachedIP(host string, ip netip.Addr, ttl time.Duration) {
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

func (xTransport *XTransport) loadCachedIP(host string) (ip netip.Addr, expired bool) {
	ip, expired = netip.IPv4Unspecified(), false
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
		(*xTransport.transport).CloseIdleConnections()
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
			if cachedIP != netip.IPv4Unspecified() {
				if cachedIP.Is4() {
					ipOnly = cachedIP.String()
				} else {
					ipOnly = "[" + cachedIP.String() + "]"
				}
			} else {
				dlog.Debugf("[%s] IP address was not cached", host)
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

	if clientCreds.rootCA != "" {
		if certPool == nil {
			dlog.Fatalf("Additional CAs not supported on this platform: %v", certPoolErr)
		}
		additionalCaCert, err := ioutil.ReadFile(clientCreds.rootCA)
		if err != nil {
			dlog.Fatal(err)
		}
		certPool.AppendCertsFromPEM(additionalCaCert)
	}

	if certPool != nil {
		// Some operating systems don't include Let's Encrypt ISRG Root X1 certificate yet
		var letsEncryptX1Cert = []byte(`-----BEGIN CERTIFICATE-----
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

	if xTransport.tlsDisableSessionTickets || xTransport.tlsCipherSuite != nil {
		tlsClientConfig.SessionTicketsDisabled = xTransport.tlsDisableSessionTickets
		if !xTransport.tlsDisableSessionTickets {
			tlsClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(10)
		}
		if xTransport.tlsCipherSuite != nil {
			tlsClientConfig.CipherSuites = xTransport.tlsCipherSuite
		}
	}
	transport.TLSClientConfig = &tlsClientConfig
	if http2Transport, err := http2.ConfigureTransports(transport); err != nil {
		http2Transport.ReadIdleTimeout = timeout
		http2Transport.AllowHTTP = false
	}
	xTransport.transport = transport
	if xTransport.http3 {
		h3Transport := &http3.RoundTripper{DisableCompression: true, TLSClientConfig: &tlsClientConfig}
		xTransport.h3Transport = h3Transport
	}
}

func (xTransport *XTransport) resolveUsingSystem(host string) (ip netip.Addr, ttl time.Duration, err error) {
	ttl = SystemResolverIPTTL
	var foundIPs []string
	foundIPs, err = net.LookupHost(host)
	if err != nil {
		return
	}
	ips := make([]netip.Addr, 0)
	for _, ip := range foundIPs {
		if foundIP, err := netip.ParseAddr(ip); err == nil {
			if xTransport.useIPv4 {
				if foundIP.Is4() {
					ips = append(ips, foundIP)
				}
			}
			if xTransport.useIPv6 {
				if foundIP.Is6() || foundIP.Is4In6() {
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
) (ip netip.Addr, ttl time.Duration, err error) {
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
				ip, _ = netip.ParseAddr(answer.(*dns.A).A.String())
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
				ip, _ = netip.ParseAddr(answer.(*dns.AAAA).AAAA.String())
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
) (ip netip.Addr, ttl time.Duration, err error) {
	for i, resolver := range resolvers {
		ip, ttl, err = xTransport.resolveUsingResolver(proto, host, resolver)
		if err == nil {
			if i > 0 {
				dlog.Infof("Resolution succeeded with bootstrap resolver %s[%s]", proto, resolver)
				resolvers[0], resolvers[i] = resolvers[i], resolvers[0]
			}
			break
		}
		dlog.Infof("Unable to resolve [%s] using bootstrap resolver %s[%s]: %v", host, proto, resolver, err)
	}
	return
}

// If a name is not present in the cache, resolve the name and update the cache
func (xTransport *XTransport) resolveAndUpdateCache(host string) error {
	if xTransport.proxyDialer != nil || xTransport.httpProxyFunction != nil {
		return nil
	}
	_, err := ParseIP(host)
	if err != nil {
		return nil
	}

	cachedIP, expired := xTransport.loadCachedIP(host)
	if cachedIP != netip.IPv4Unspecified() && !expired {
		return nil
	}
	var foundIP netip.Addr
	var ttl time.Duration

	if !xTransport.ignoreSystemDNS {
		foundIP, ttl, err = xTransport.resolveUsingSystem(host)
	}
	if xTransport.ignoreSystemDNS || err != nil {
		protos := []string{"udp", "tcp"}
		if xTransport.mainProto == "tcp" {
			protos = []string{"tcp", "udp"}
		}
		for _, proto := range protos {
			if err != nil {
				dlog.Noticef(
					"System DNS configuration not usable yet, exceptionally resolving [%s] using bootstrap resolvers over %s",
					host,
					proto,
				)
			} else {
				dlog.Debugf("Resolving [%s] using bootstrap resolvers over %s", host, proto)
			}
			foundIP, ttl, err = xTransport.resolveUsingResolvers(proto, host, xTransport.bootstrapResolvers)
			if err == nil {
				break
			}
		}
	}
	if err != nil && xTransport.ignoreSystemDNS {
		dlog.Noticef("Bootstrap resolvers didn't respond - Trying with the system resolver as a last resort")
		foundIP, ttl, err = xTransport.resolveUsingSystem(host)
	}
	if ttl < MinResolverIPTTL {
		ttl = MinResolverIPTTL
	}
	if err != nil {
		if cachedIP != netip.IPv4Unspecified() {
			dlog.Noticef("Using stale [%v] cached address for a grace period", host)
			foundIP = cachedIP
			ttl = ExpiredCachedIPGraceTTL
		} else {
			return err
		}
	}
	xTransport.saveCachedIP(host, foundIP, ttl)
	dlog.Debugf("[%s] IP address [%s] added to the cache, valid for %v", host, foundIP, ttl)
	return nil
}

func (xTransport *XTransport) Fetch(
	method string,
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
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
		altPort, hasAltSupport := xTransport.altSupport.cache[url.Host]
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
	req := &http.Request{
		Method: method,
		URL:    url,
		Header: header,
		Close:  false,
	}
	if body != nil {
		req.ContentLength = int64(len(*body))
		req.Body = ioutil.NopCloser(bytes.NewReader(*body))
	}
	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)
	if err == nil {
		if resp == nil {
			err = errors.New("Webserver returned an error")
		} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
			err = errors.New(resp.Status)
		}
	} else {
		(*xTransport.transport).CloseIdleConnections()
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
		if alt, found := resp.Header["Alt-Svc"]; found {
			dlog.Debugf("Alt-Svc [%s]: [%s]", url.Host, alt)
			altPort := uint16(port)
			for i, xalt := range alt {
				for j, v := range strings.Split(xalt, ";") {
					if i > 8 || j > 16 {
						break
					}
					v = strings.TrimSpace(v)
					if strings.HasPrefix(v, "h3=\":") {
						v = strings.TrimPrefix(v, "h3=\":")
						v = strings.TrimSuffix(v, "\"")
						if xAltPort, err := strconv.ParseUint(v, 10, 16); err == nil && xAltPort <= 65536 {
							altPort = uint16(xAltPort)
							dlog.Debugf("Using HTTP/3 for [%s]", url.Host)
							break
						}
					}
				}
			}
			xTransport.altSupport.Lock()
			xTransport.altSupport.cache[url.Host] = altPort
			xTransport.altSupport.Unlock()
		}
	}
	tls := resp.TLS
	bin, err := ioutil.ReadAll(io.LimitReader(resp.Body, MaxHTTPBodyLength))
	if err != nil {
		return nil, statusCode, tls, rtt, err
	}
	resp.Body.Close()
	return bin, statusCode, tls, rtt, err
}

func (xTransport *XTransport) Get(
	url *url.URL,
	accept string,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.Fetch("GET", url, accept, "", nil, timeout)
}

func (xTransport *XTransport) Post(
	url *url.URL,
	accept string,
	contentType string,
	body *[]byte,
	timeout time.Duration,
) ([]byte, int, *tls.ConnectionState, time.Duration, error) {
	return xTransport.Fetch("POST", url, accept, contentType, body, timeout)
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
