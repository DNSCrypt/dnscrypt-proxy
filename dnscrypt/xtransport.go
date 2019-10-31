package dnscrypt

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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
	SystemResolverTTL       = 24 * time.Hour
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
	KeepAlive                time.Duration
	timeout                  time.Duration
	cachedIPs                CachedIPs
	FallbackResolver         string
	MainProto                string
	IgnoreSystemDNS          bool
	UseIPv4                  bool
	UseIPv6                  bool
	TLSDisableSessionTickets bool
	TLSCipherSuite           []uint16
	ProxyDialer              *netproxy.Dialer
	HTTPProxyFunction        func(*http.Request) (*url.URL, error)
}

func NewXTransport() *XTransport {
	if err := CheckResolver(DefaultFallbackResolver); err != nil {
		panic("DefaultFallbackResolver does not parse")
	}
	xTransport := XTransport{
		cachedIPs:                CachedIPs{cache: make(map[string]*CachedIPItem)},
		KeepAlive:                DefaultKeepAlive,
		timeout:                  DefaultTimeout,
		FallbackResolver:         DefaultFallbackResolver,
		MainProto:                "",
		IgnoreSystemDNS:          false,
		UseIPv4:                  true,
		UseIPv6:                  false,
		TLSDisableSessionTickets: false,
		TLSCipherSuite:           nil,
	}
	return &xTransport
}

func ParseIP(ipStr string) net.IP {
	return net.ParseIP(strings.TrimRight(strings.TrimLeft(ipStr, "["), "]"))
}

// If ttl < 0, never expire
// Otherwise, ttl is set to max(ttl, xTransport.timeout)
func (xTransport *XTransport) saveCachedIP(host string, ip net.IP, ttl time.Duration) {
	item := &CachedIPItem{ip: ip, expiration: nil}
	if ttl >= 0 {
		if ttl < xTransport.timeout {
			ttl = xTransport.timeout
		}
		expiration := time.Now().Add(ttl)
		item.expiration = &expiration
	}
	xTransport.cachedIPs.Lock()
	xTransport.cachedIPs.cache[host] = item
	xTransport.cachedIPs.Unlock()
}

func (xTransport *XTransport) loadCachedIP(host string, deleteIfExpired bool) (net.IP, bool) {
	xTransport.cachedIPs.RLock()
	item, ok := xTransport.cachedIPs.cache[host]
	xTransport.cachedIPs.RUnlock()
	if !ok {
		return nil, false
	}
	expiration := item.expiration
	if deleteIfExpired && expiration != nil && time.Until(*expiration) < 0 {
		xTransport.cachedIPs.Lock()
		delete(xTransport.cachedIPs.cache, host)
		xTransport.cachedIPs.Unlock()
		return nil, false
	}
	return item.ip, ok
}

func (xTransport *XTransport) RebuildTransport() {
	dlog.Debug("Rebuilding transport")
	if xTransport.transport != nil {
		(*xTransport.transport).CloseIdleConnections()
	}
	timeout := xTransport.timeout
	transport := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true,
		MaxIdleConns:           1,
		IdleConnTimeout:        xTransport.KeepAlive,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  timeout,
		MaxResponseHeaderBytes: 4096,
		DialContext: func(ctx context.Context, network, addrStr string) (net.Conn, error) {
			host, port := ExtractHostAndPort(addrStr, stamps.DefaultPort)
			ipOnly := host
			cachedIP, ok := xTransport.loadCachedIP(host, false)
			if ok {
				ipOnly = cachedIP.String()
			} else {
				dlog.Debugf("[%s] IP address was not cached", host)
			}
			addrStr = ipOnly + ":" + strconv.Itoa(port)
			if xTransport.ProxyDialer == nil {
				dialer := &net.Dialer{Timeout: timeout, KeepAlive: timeout, DualStack: true}
				return dialer.DialContext(ctx, network, addrStr)
			}
			return (*xTransport.ProxyDialer).Dial(network, addrStr)
		},
	}
	if xTransport.HTTPProxyFunction != nil {
		transport.Proxy = xTransport.HTTPProxyFunction
	}
	if xTransport.TLSDisableSessionTickets || xTransport.TLSCipherSuite != nil {
		tlsClientConfig := tls.Config{
			SessionTicketsDisabled: xTransport.TLSDisableSessionTickets,
		}
		if !xTransport.TLSDisableSessionTickets {
			tlsClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(10)
		}
		if xTransport.TLSCipherSuite != nil {
			tlsClientConfig.PreferServerCipherSuites = false
			tlsClientConfig.CipherSuites = xTransport.TLSCipherSuite
		}
		transport.TLSClientConfig = &tlsClientConfig
	}
	http2.ConfigureTransport(transport)
	xTransport.transport = transport
}

func (xTransport *XTransport) resolveUsingSystem(host string) (ip net.IP, ttl time.Duration, err error) {
	ttl = SystemResolverTTL
	var foundIPs []string
	foundIPs, err = net.LookupHost(host)
	if err != nil {
		return
	}
	ips := make([]net.IP, 0)
	for _, ip := range foundIPs {
		if foundIP := net.ParseIP(ip); foundIP != nil {
			if xTransport.UseIPv4 {
				if ipv4 := foundIP.To4(); ipv4 != nil {
					ips = append(ips, foundIP)
				}
			}
			if xTransport.UseIPv6 {
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
	if xTransport.UseIPv4 {
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
	if xTransport.UseIPv6 {
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

func (xTransport *XTransport) resolveHost(host string) (err error) {
	if xTransport.ProxyDialer != nil || xTransport.HTTPProxyFunction != nil {
		return
	}
	if ParseIP(host) != nil {
		return
	}
	if _, ok := xTransport.loadCachedIP(host, true); ok {
		return
	}
	var foundIP net.IP
	var ttl time.Duration
	if !xTransport.IgnoreSystemDNS {
		foundIP, ttl, err = xTransport.resolveUsingSystem(host)
	}
	if xTransport.IgnoreSystemDNS || err != nil {
		protos := []string{"udp", "tcp"}
		if xTransport.MainProto == "tcp" {
			protos = []string{"tcp", "udp"}
		}
		for _, proto := range protos {
			if err != nil {
				dlog.Noticef("System DNS configuration not usable yet, exceptionally resolving [%s] using resolver %s[%s]", host, proto, xTransport.FallbackResolver)
			} else {
				dlog.Debugf("Resolving [%s] using resolver %s[%s]", host, proto, xTransport.FallbackResolver)
			}
			foundIP, ttl, err = xTransport.resolveUsingResolver(proto, host, xTransport.FallbackResolver)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return
	}
	xTransport.saveCachedIP(host, foundIP, ttl)
	dlog.Debugf("[%s] IP address [%s] added to the cache, valid until %v", host, foundIP, ttl)
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
	if xTransport.ProxyDialer == nil && strings.HasSuffix(host, ".onion") {
		return nil, 0, errors.New("Onion service is not reachable without Tor")
	}
	if err := xTransport.resolveHost(host); err != nil {
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
		if xTransport.TLSCipherSuite != nil && strings.Contains(err.Error(), "handshake failure") {
			dlog.Warnf("TLS handshake failure - Try changing or deleting the tls_cipher_suite value in the configuration file")
			xTransport.TLSCipherSuite = nil
			xTransport.RebuildTransport()
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

func CheckResolver(resolver string) error {
	host, port := ExtractHostAndPort(resolver, -1)
	if ip := ParseIP(host); ip == nil {
		return fmt.Errorf("Host does not parse as IP '%s'", resolver)
	} else if port == -1 {
		return fmt.Errorf("Port missing '%s'", resolver)
	} else if _, err := strconv.ParseUint(strconv.Itoa(port), 10, 16); err != nil {
		return fmt.Errorf("Port does not parse '%s' [%v]", resolver, err)
	}
	return nil
}
