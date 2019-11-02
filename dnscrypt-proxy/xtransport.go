package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
	netproxy "golang.org/x/net/proxy"
)

const (
	DefaultFallbackResolver = "9.9.9.9:53"
	DefaultKeepAlive        = 5 * time.Second
	DefaultTimeout          = 30 * time.Second
	SystemRresolverIPTTL    = 24 * time.Hour
	MinRresolverIPTTL       = 8 * time.Hour
	ExpiredCachedIPGraceTTL = 5 * time.Minute
)

type CachedIPItem struct {
	ip         net.IP
	expiration *time.Time
}

type CachedIPs struct {
	sync.RWMutex
	cache map[string]*CachedIPItem
}

type XTransport struct {
	transport                *http.Transport
	keepAlive                time.Duration
	timeout                  time.Duration
	cachedIPs                CachedIPs
	fallbackResolver         string
	mainProto                string
	ignoreSystemDNS          bool
	useIPv4                  bool
	useIPv6                  bool
	tlsDisableSessionTickets bool
	tlsCipherSuite           []uint16
	proxyDialer              *netproxy.Dialer
	httpProxyFunction        func(*http.Request) (*url.URL, error)
}

func NewXTransport() *XTransport {
	if err := isIPAndPort(DefaultFallbackResolver); err != nil {
		panic("DefaultFallbackResolver does not parse")
	}
	xTransport := XTransport{
		cachedIPs:                CachedIPs{cache: make(map[string]*CachedIPItem)},
		keepAlive:                DefaultKeepAlive,
		timeout:                  DefaultTimeout,
		fallbackResolver:         DefaultFallbackResolver,
		mainProto:                "",
		ignoreSystemDNS:          false,
		useIPv4:                  true,
		useIPv6:                  false,
		tlsDisableSessionTickets: false,
		tlsCipherSuite:           nil,
	}
	return &xTransport
}

func ParseIP(ipStr string) net.IP {
	return net.ParseIP(strings.TrimRight(strings.TrimLeft(ipStr, "["), "]"))
}

// If ttl < 0, never expire
// Otherwise, ttl is set to max(ttl, MinRresolverIPTTL)
func (xTransport *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	item := &CachedIPItem{ip: ip, expiration: nil}
	if ttl >= 0 {
		if ttl < MinRresolverIPTTL {
			ttl = MinRresolverIPTTL
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
			// resolveWithCache() is always called in `Fetch()` before the `Dial()`
			// method is used, so that a cached entry must be present at this point.
			cachedIP, _ := xTransport.loadCachedIP(host)
			if cachedIP != nil {
				if ipv4 := cachedIP.To4(); ipv4 != nil {
					ipOnly = ipv4.String()
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
	if xTransport.tlsDisableSessionTickets || xTransport.tlsCipherSuite != nil {
		tlsClientConfig := tls.Config{
			SessionTicketsDisabled: xTransport.tlsDisableSessionTickets,
		}
		if !xTransport.tlsDisableSessionTickets {
			tlsClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(10)
		}
		if xTransport.tlsCipherSuite != nil {
			tlsClientConfig.PreferServerCipherSuites = false
			tlsClientConfig.CipherSuites = xTransport.tlsCipherSuite
		}
		transport.TLSClientConfig = &tlsClientConfig
	}
	http2.ConfigureTransport(transport)
	xTransport.transport = transport
}

func (xTransport *XTransport) resolveUsingSystem(host string) (ip net.IP, ttl time.Duration, err error) {
	ttl = SystemRresolverIPTTL
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

func (xTransport *XTransport) resolveUsingResolver(proto, host string, resolver string) (ip net.IP, ttl time.Duration, err error) {
	dnsClient := dns.Client{Net: proto}
	if xTransport.useIPv4 {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
		msg.SetEdns0(uint16(MaxDNSPacketSize), true)
		var in *dns.Msg
		if in, _, err = dnsClient.Exchange(msg, resolver); err == nil {
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
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
		msg.SetEdns0(uint16(MaxDNSPacketSize), true)
		var in *dns.Msg
		if in, _, err = dnsClient.Exchange(msg, resolver); err == nil {
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

// Return a cached entry, or resolve a name and update the cache
func (xTransport *XTransport) resolveWithCache(host string) (err error) {
	if xTransport.proxyDialer != nil || xTransport.httpProxyFunction != nil {
		return
	}
	if ParseIP(host) != nil {
		return
	}
	cachedIP, expired := xTransport.loadCachedIP(host)
	if cachedIP != nil && !expired {
		return
	}
	var foundIP net.IP
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
				dlog.Noticef("System DNS configuration not usable yet, exceptionally resolving [%s] using resolver %s[%s]", host, proto, xTransport.fallbackResolver)
			} else {
				dlog.Debugf("Resolving [%s] using resolver %s[%s]", host, proto, xTransport.fallbackResolver)
			}
			foundIP, ttl, err = xTransport.resolveUsingResolver(proto, host, xTransport.fallbackResolver)
			if err == nil {
				break
			}
		}
	}
	if ttl < MinRresolverIPTTL {
		ttl = MinRresolverIPTTL
	}
	if err != nil {
		if cachedIP != nil {
			foundIP = cachedIP
			ttl = ExpiredCachedIPGraceTTL
		} else {
			return
		}
	}
	xTransport.saveCachedIP(host, foundIP, ttl)
	dlog.Debugf("[%s] IP address [%s] added to the cache, valid for %v", host, foundIP, ttl)
	return
}

func (xTransport *XTransport) Fetch(method string, url *url.URL, accept string, contentType string, body *[]byte, timeout time.Duration, padding *string) (*http.Response, time.Duration, error) {
	if timeout <= 0 {
		timeout = xTransport.timeout
	}
	client := http.Client{Transport: xTransport.transport, Timeout: timeout}
	header := map[string][]string{"User-Agent": {"dnscrypt-proxy"}}
	if len(accept) > 0 {
		header["Accept"] = []string{accept}
	}
	if len(contentType) > 0 {
		header["Content-Type"] = []string{contentType}
	}
	if padding != nil {
		header["X-Pad"] = []string{*padding}
	}
	if body != nil {
		h := sha512.Sum512(*body)
		qs := url.Query()
		qs.Add("body_hash", hex.EncodeToString(h[:32]))
		url2 := *url
		url2.RawQuery = qs.Encode()
		url = &url2
	}
	host, _ := ExtractHostAndPort(url.Host, 0)
	if xTransport.proxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, errors.New("Onion service is not reachable without Tor")
	}
	if err := xTransport.resolveWithCache(host); err != nil {
		return nil, 0, err
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
	if err != nil {
		dlog.Debugf("[%s]: [%s]", req.URL, err)
		if xTransport.tlsCipherSuite != nil && strings.Contains(err.Error(), "handshake failure") {
			dlog.Warnf("TLS handshake failure - Try changing or deleting the tls_cipher_suite value in the configuration file")
			xTransport.tlsCipherSuite = nil
			xTransport.rebuildTransport()
		}
	}
	return resp, rtt, err
}

func (xTransport *XTransport) Get(url *url.URL, accept string, timeout time.Duration) (*http.Response, time.Duration, error) {
	return xTransport.Fetch("GET", url, accept, "", nil, timeout, nil)
}

func (xTransport *XTransport) Post(url *url.URL, accept string, contentType string, body *[]byte, timeout time.Duration, padding *string) (*http.Response, time.Duration, error) {

	return xTransport.Fetch("POST", url, accept, contentType, body, timeout, padding)
}

func (xTransport *XTransport) DoHQuery(useGet bool, url *url.URL, body []byte, timeout time.Duration) (*http.Response, time.Duration, error) {
	padLen := 63 - (len(body)+63)&63
	padding := xTransport.makePad(padLen)
	dataType := "application/dns-message"
	if useGet {
		qs := url.Query()
		qs.Add("ct", "")
		encBody := base64.RawURLEncoding.EncodeToString(body)
		qs.Add("dns", encBody)
		url2 := *url
		url2.RawQuery = qs.Encode()
		return xTransport.Get(&url2, dataType, timeout)
	}
	return xTransport.Post(url, dataType, dataType, &body, timeout, padding)
}

func (xTransport *XTransport) makePad(padLen int) *string {
	if padLen <= 0 {
		return nil
	}
	padding := strings.Repeat("X", padLen)
	return &padding
}
