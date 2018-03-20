package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

const DefaultFallbackResolver = "9.9.9.9:53"

type CachedIPs struct {
	sync.RWMutex
	cache map[string]string
}

type XTransport struct {
	transport        *http.Transport
	timeout          time.Duration
	cachedIPs        CachedIPs
	fallbackResolver string
	ignoreSystemDNS  bool
	useIPv4          bool
	useIPv6          bool
}

var IdleConnTimeout = 5 * time.Second

func NewXTransport(timeout time.Duration, useIPv4 bool, useIPv6 bool) *XTransport {
	xTransport := XTransport{
		cachedIPs:        CachedIPs{cache: make(map[string]string)},
		timeout:          timeout,
		fallbackResolver: DefaultFallbackResolver,
		ignoreSystemDNS:  false,
		useIPv4:          useIPv4,
		useIPv6:          useIPv6,
	}
	xTransport.rebuildTransport()
	return &xTransport
}

func (xTransport *XTransport) rebuildTransport() {
	dlog.Debug("Rebuilding transport")
	if xTransport.transport != nil {
		(*xTransport.transport).CloseIdleConnections()
	}
	timeout := xTransport.timeout
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: timeout, DualStack: true}
	transport := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true,
		MaxIdleConns:           1,
		IdleConnTimeout:        IdleConnTimeout,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  timeout,
		MaxResponseHeaderBytes: 4096,
		DialContext: func(ctx context.Context, network, addrStr string) (net.Conn, error) {
			host := addrStr[:strings.LastIndex(addrStr, ":")]
			ipOnly := host
			xTransport.cachedIPs.RLock()
			cachedIP := xTransport.cachedIPs.cache[host]
			xTransport.cachedIPs.RUnlock()
			if len(cachedIP) > 0 {
				ipOnly = cachedIP
			} else {
				dlog.Debugf("[%s] IP address was not cached", host)
			}
			addrStr = ipOnly + addrStr[strings.LastIndex(addrStr, ":"):]
			return dialer.DialContext(ctx, network, addrStr)
		},
	}
	xTransport.transport = transport
}

func (xTransport *XTransport) Fetch(method string, url *url.URL, accept string, contentType string, body *io.ReadCloser, timeout time.Duration, padding *string) (*http.Response, time.Duration, error) {
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
	req := &http.Request{
		Method: method,
		URL:    url,
		Header: header,
		Close:  false,
	}
	if body != nil {
		req.Body = *body
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
	if !xTransport.useIPv4 {
		return nil, 0, fmt.Errorf("IPv4 connectivity would be required to use [%s]", host)
	}
	dnsClient := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
	msg.SetEdns0(4096, true)
	if !xTransport.ignoreSystemDNS {
		dlog.Noticef("System DNS configuration not usable yet, exceptionally resolving [%s] using fallback resolver [%s]", host, xTransport.fallbackResolver)
	} else {
		dlog.Debugf("Resolving [%s] using fallback resolver [%s]", host, xTransport.fallbackResolver)
	}
	in, _, err := dnsClient.Exchange(msg, xTransport.fallbackResolver)
	if err != nil {
		return nil, 0, err
	}
	var foundIP *string
	for _, answer := range in.Answer {
		if answer.Header().Rrtype == dns.TypeA {
			foundIPx := answer.(*dns.A).A.String()
			foundIP = &foundIPx
			break
		}
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
	}
	return resp, rtt, err
}

func (xTransport *XTransport) Get(url *url.URL, accept string, timeout time.Duration) (*http.Response, time.Duration, error) {
	return xTransport.Fetch("GET", url, "", "", nil, timeout, nil)
}

func (xTransport *XTransport) Post(url *url.URL, accept string, contentType string, body []byte, timeout time.Duration, padding *string) (*http.Response, time.Duration, error) {
	bc := ioutil.NopCloser(bytes.NewReader(body))
	return xTransport.Fetch("POST", url, accept, contentType, &bc, timeout, padding)
}

func (xTransport *XTransport) DoHQuery(useGet bool, url *url.URL, body []byte, timeout time.Duration) (*http.Response, time.Duration, error) {
	padLen := 63 - (len(body)+63)&63
	padding := xTransport.makePad(padLen)
	dataType := "application/dns-udpwireformat"
	if useGet {
		qs := url.Query()
		qs.Add("ct", "")
		encBody := base64.RawURLEncoding.EncodeToString(body)
		qs.Add("body", encBody)
		qs.Add("dns", encBody)
		qs.Add("random_padding", *padding)
		url2 := *url
		url2.RawQuery = qs.Encode()
		return xTransport.Get(&url2, dataType, timeout)
	}
	return xTransport.Post(url, dataType, dataType, body, timeout, padding)
}

func (xTransport *XTransport) makePad(padLen int) *string {
	if padLen <= 0 {
		return nil
	}
	padding := strings.Repeat("X", padLen)
	return &padding
}
