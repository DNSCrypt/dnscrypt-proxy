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
}

func NewXTransport(timeout time.Duration) *XTransport {
	xTransport := XTransport{
		cachedIPs:        CachedIPs{cache: make(map[string]string)},
		timeout:          timeout,
		fallbackResolver: DefaultFallbackResolver,
		ignoreSystemDNS:  false,
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: timeout, DualStack: true}
	transport := &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     true,
		MaxIdleConns:           1,
		IdleConnTimeout:        timeout,
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
	return &xTransport
}

func (xTransport *XTransport) Fetch(method string, url *url.URL, accept string, contentType string, body *io.ReadCloser, timeout time.Duration) (*http.Response, time.Duration, error) {
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
		start := time.Now()
		resp, err := client.Do(req)
		rtt := time.Since(start)
		if err == nil {
			if resp == nil {
				err = errors.New("Webserver returned an error")
			} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
				err = fmt.Errorf("Webserver returned code %d", resp.StatusCode)
			}
			return resp, rtt, err
		}
		dlog.Debugf("[%s]: [%s]", req.URL, err)
	} else {
		dlog.Debug("Ignoring system DNS")
	}
	if len(cachedIP) > 0 && err != nil {
		dlog.Debugf("IP for [%s] was cached to [%s], but connection failed: [%s]", host, cachedIP, err)
		return nil, 0, err
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
	if len(in.Answer) <= 0 {
		return nil, 0, fmt.Errorf("No IP found for [%s]", host)
	}
	foundIP := in.Answer[0].(*dns.A).A.String()
	xTransport.cachedIPs.Lock()
	xTransport.cachedIPs.cache[host] = foundIP
	xTransport.cachedIPs.Unlock()
	dlog.Debugf("[%s] IP address [%s] added to the cache", host, foundIP)

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)
	if err == nil {
		if resp == nil {
			err = errors.New("Webserver returned an error")
		} else if resp.StatusCode < 200 || resp.StatusCode > 299 {
			err = fmt.Errorf("Webserver returned code %d", resp.StatusCode)
		}
	}
	if err != nil {
		dlog.Debugf("[%s]: [%s]", req.URL, err)
	}
	return resp, rtt, err
}

func (xTransport *XTransport) Get(url *url.URL, accept string, timeout time.Duration) (*http.Response, time.Duration, error) {
	return xTransport.Fetch("GET", url, "", "", nil, timeout)
}

func (xTransport *XTransport) Post(url *url.URL, accept string, contentType string, body []byte, timeout time.Duration) (*http.Response, time.Duration, error) {
	bc := ioutil.NopCloser(bytes.NewReader(body))
	return xTransport.Fetch("POST", url, accept, contentType, &bc, timeout)
}
func (xTransport *XTransport) DoHQuery(useGet bool, url *url.URL, body []byte, timeout time.Duration) (*http.Response, time.Duration, error) {
	dataType := "application/dns-udpwireformat"
	if useGet {
		qs := url.Query()
		qs.Add("ct", "")
		qs.Add("body", base64.RawURLEncoding.EncodeToString(body))
		url2 := *url
		url2.RawQuery = qs.Encode()
		return xTransport.Get(&url2, dataType, timeout)
	}
	return xTransport.Post(url, dataType, dataType, body, timeout)
}
