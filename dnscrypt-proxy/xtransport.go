package main

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
)

type CachedIPs struct {
	sync.RWMutex
	cache map[string]string
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
	if err := CheckResolver(DefaultFallbackResolver); err != nil {
		panic("DefaultFallbackResolver does not parse")
	}
	xTransport := XTransport{
		cachedIPs:                CachedIPs{cache: make(map[string]string)},
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

func (xTransport *XTransport) clearCache() {
	xTransport.cachedIPs.Lock()
	xTransport.cachedIPs.cache = make(map[string]string)
	xTransport.cachedIPs.Unlock()
	dlog.Info("IP cache cleared")
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
			xTransport.cachedIPs.RLock()
			cachedIP := xTransport.cachedIPs.cache[host]
			xTransport.cachedIPs.RUnlock()
			if len(cachedIP) > 0 {
				ipOnly = cachedIP
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

func (xTransport *XTransport) resolveUsingSystem(host string) (*string, error) {
	foundIPs, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}
	for _, ip := range foundIPs {
		foundIP := net.ParseIP(ip)
		if foundIP == nil {
			continue
		}
		if xTransport.useIPv4 {
			if ipv4 := foundIP.To4(); ipv4 != nil {
				foundIPx := foundIP.String()
				return &foundIPx, nil
			}
		}
		if xTransport.useIPv6 {
			if ipv6 := foundIP.To16(); ipv6 != nil {
				foundIPx := "[" + foundIP.String() + "]"
				return &foundIPx, nil
			}
		}
	}
	return nil, err
}

func (xTransport *XTransport) resolveUsingResolver(dnsClient *dns.Client, host string, resolver string) (*string, error) {
	var err error
	if xTransport.useIPv4 {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
		msg.SetEdns0(uint16(MaxDNSPacketSize), true)
		var in *dns.Msg
		in, _, err = dnsClient.Exchange(msg, resolver)
		if err == nil {
			for _, answer := range in.Answer {
				if answer.Header().Rrtype == dns.TypeA {
					foundIP := answer.(*dns.A).A.String()
					return &foundIP, nil
				}
			}
		}
	}
	if xTransport.useIPv6 {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
		msg.SetEdns0(uint16(MaxDNSPacketSize), true)
		var in *dns.Msg
		in, _, err = dnsClient.Exchange(msg, resolver)
		if err == nil {
			for _, answer := range in.Answer {
				if answer.Header().Rrtype == dns.TypeAAAA {
					foundIP := "[" + answer.(*dns.AAAA).AAAA.String() + "]"
					return &foundIP, nil
				}
			}
		}
	}
	return nil, err
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
	var err error
	resolveByProxy := false
	if xTransport.proxyDialer != nil || xTransport.httpProxyFunction != nil {
		resolveByProxy = true
	}
	var foundIP *string
	if !resolveByProxy && ParseIP(host) == nil {
		xTransport.cachedIPs.RLock()
		cachedIP := xTransport.cachedIPs.cache[host]
		xTransport.cachedIPs.RUnlock()
		if len(cachedIP) > 0 {
			foundIP = &cachedIP
		} else {
			if !xTransport.ignoreSystemDNS {
				foundIP, err = xTransport.resolveUsingSystem(host)
			} else {
				dlog.Debug("Ignoring system DNS")
			}
			if xTransport.ignoreSystemDNS || err != nil {
				if xTransport.ignoreSystemDNS {
					dlog.Debugf("Resolving [%s] using fallback resolver [%s]", host, xTransport.fallbackResolver)
				} else {
					dlog.Noticef("System DNS configuration not usable yet, exceptionally resolving [%s] using fallback resolver [%s]", host, xTransport.fallbackResolver)
				}
				dnsClient := dns.Client{Net: xTransport.mainProto}
				foundIP, err = xTransport.resolveUsingResolver(&dnsClient, host, xTransport.fallbackResolver)
			}
			if foundIP == nil {
				return nil, 0, fmt.Errorf("No IP found for [%s]", host)
			}
			if err != nil {
				return nil, 0, err
			}
			xTransport.cachedIPs.Lock()
			xTransport.cachedIPs.cache[host] = *foundIP
			xTransport.cachedIPs.Unlock()
			dlog.Debugf("[%s] IP address [%s] added to the cache", host, *foundIP)
		}
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
