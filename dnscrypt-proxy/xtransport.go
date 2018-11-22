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

const DefaultFallbackResolver = "9.9.9.9:53"

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
	ignoreSystemDNS          bool
	useIPv4                  bool
	useIPv6                  bool
	tlsDisableSessionTickets bool
	tlsCipherSuite           []uint16
	proxyDialer              *netproxy.Dialer
	httpProxyFunction        func(*http.Request) (*url.URL, error)
}

var DefaultKeepAlive = 5 * time.Second
var DefaultTimeout = 30 * time.Second

func NewXTransport() *XTransport {
	xTransport := XTransport{
		cachedIPs:                CachedIPs{cache: make(map[string]string)},
		keepAlive:                DefaultKeepAlive,
		timeout:                  DefaultTimeout,
		fallbackResolver:         DefaultFallbackResolver,
		ignoreSystemDNS:          false,
		useIPv4:                  true,
		useIPv6:                  false,
		tlsDisableSessionTickets: false,
		tlsCipherSuite:           nil,
	}
	return &xTransport
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
			} else {
				return (*xTransport.proxyDialer).Dial(network, addrStr)
			}
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

func (xTransport *XTransport) resolve(dnsClient *dns.Client, host string, resolver string) (*string, error) {
	var foundIP *string
	var err error
	if xTransport.useIPv4 {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
		msg.SetEdns0(4096, true)
		var in *dns.Msg
		in, _, err = dnsClient.Exchange(msg, resolver)
		if err == nil {
			for _, answer := range in.Answer {
				if answer.Header().Rrtype == dns.TypeA {
					foundIPx := answer.(*dns.A).A.String()
					foundIP = &foundIPx
					return foundIP, nil
				}
			}
		}
	}
	if xTransport.useIPv6 && foundIP == nil {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
		msg.SetEdns0(4096, true)
		var in *dns.Msg
		in, _, err = dnsClient.Exchange(msg, resolver)
		if err == nil {
			for _, answer := range in.Answer {
				if answer.Header().Rrtype == dns.TypeAAAA {
					foundIPx := "[" + answer.(*dns.AAAA).AAAA.String() + "]"
					foundIP = &foundIPx
					return foundIP, nil
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
	req := &http.Request{
		Method: method,
		URL:    url,
		Header: header,
		Close:  false,
	}
	if body != nil {
		req.ContentLength = int64(len(*body))
		bc := ioutil.NopCloser(bytes.NewReader(*body))
		req.Body = bc
	}
	var err error
	host := url.Host
	xTransport.cachedIPs.RLock()
	cachedIP := xTransport.cachedIPs.cache[host]
	xTransport.cachedIPs.RUnlock()
	if !xTransport.ignoreSystemDNS || len(cachedIP) > 0 {
		var resp *http.Response
		start := time.Now()
		resp, err = client.Do(req)
		rtt := time.Since(start)
		if err == nil {
			if resp == nil {
				err = errors.New("Webserver returned an error")
			} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
				err = fmt.Errorf("Webserver returned code %d", resp.StatusCode)
			}
			return resp, rtt, err
		}
		(*xTransport.transport).CloseIdleConnections()
		dlog.Debugf("[%s]: [%s]", req.URL, err)
	} else {
		dlog.Debug("Ignoring system DNS")
	}
	if len(cachedIP) > 0 && err != nil {
		dlog.Debugf("IP for [%s] was cached to [%s], but connection failed: [%s]", host, cachedIP, err)
		return nil, 0, err
	}
	if !xTransport.ignoreSystemDNS {
		dlog.Noticef("System DNS configuration not usable yet, exceptionally resolving [%s] using fallback resolver [%s]", host, xTransport.fallbackResolver)
	} else {
		dlog.Debugf("Resolving [%s] using fallback resolver [%s]", host, xTransport.fallbackResolver)
	}
	dnsClient := new(dns.Client)
	foundIP, err := xTransport.resolve(dnsClient, host, xTransport.fallbackResolver)
	if err != nil {
		return nil, 0, err
	}
	if foundIP == nil {
		return nil, 0, fmt.Errorf("No IP found for [%s]", host)
	}
	xTransport.cachedIPs.Lock()
	xTransport.cachedIPs.cache[host] = *foundIP
	xTransport.cachedIPs.Unlock()
	dlog.Debugf("[%s] IP address [%s] added to the cache", host, *foundIP)

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)
	if err == nil {
		if resp == nil {
			err = errors.New("Webserver returned an error")
		} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
			err = fmt.Errorf("Webserver returned code %d", resp.StatusCode)
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
