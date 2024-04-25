package main

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"github.com/powerman/check"
)

func TestUDPExchangeIPv4(tt *testing.T) {
	if testing.Verbose() {
		dlog.SetLogLevel(dlog.SeverityDebug)
		dlog.UseSyslog(false)
	}
	t := check.T(tt)

	us, err := startServerUDP(t, "udp4", dns.HandlerFunc(FakeServer1))
	t.Nil(err)
	defer us.Shutdown()

	var relay *DNSCryptRelay
	proxy := Proxy{timeout: 2 * time.Second}

	msg := dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)

	query, err := msg.Pack()
	t.Nil(err)
	serverAddr, err := toServerAddr(us)
	t.Nil(err)
	r, rtt, err := udpExchange(&proxy, serverAddr, relay, query)

	t.Nil(err)
	t.Must(len(r) > 0)
	t.Must(rtt > 0)
	resp := dns.Msg{}
	resp.Unpack(r)
	t.Must(resp.Rcode == dns.RcodeSuccess)
}

func TestUDPExchangeIPv6(tt *testing.T) {
	if testing.Verbose() {
		dlog.SetLogLevel(dlog.SeverityDebug)
		dlog.UseSyslog(false)
	}
	t := check.T(tt)

	us, err := startServerUDP(t, "udp6", dns.HandlerFunc(FakeServer1))
	t.Nil(err)
	defer us.Shutdown()

	var relay *DNSCryptRelay
	proxy := Proxy{timeout: 2 * time.Second}

	msg := dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)

	query, err := msg.Pack()
	t.Nil(err)
	serverAddr, err := toServerAddr(us)
	t.Nil(err)
	r, rtt, err := udpExchange(&proxy, serverAddr, relay, query)

	t.Nil(err)
	t.Must(len(r) > 0)
	t.Must(rtt > 0)
	resp := dns.Msg{}
	resp.Unpack(r)
	t.Must(resp.Rcode == dns.RcodeSuccess)
}

func TestTCPExchangeIPv4(tt *testing.T) {
	if testing.Verbose() {
		dlog.SetLogLevel(dlog.SeverityDebug)
		dlog.UseSyslog(false)
	}
	t := check.T(tt)

	us, err := startServerTCP(t, "tcp4", dns.HandlerFunc(FakeServer1))
	t.Nil(err)
	defer us.Shutdown()

	var relay *DNSCryptRelay
	proxy := Proxy{timeout: 2 * time.Second, xTransport: &XTransport{proxyDialer: nil}}

	msg := dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)

	query, err := msg.Pack()
	t.Nil(err)
	serverAddr, err := toServerAddr(us)
	t.Nil(err)
	r, rtt, err := tcpExchange(&proxy, serverAddr, relay, query)

	t.Nil(err)
	t.Must(len(r) > 0)
	t.Must(rtt > 0)
	resp := dns.Msg{}
	resp.Unpack(r)
	t.Must(resp.Rcode == dns.RcodeSuccess)
}

func TestTCPExchangeIPv6(tt *testing.T) {
	if testing.Verbose() {
		dlog.SetLogLevel(dlog.SeverityDebug)
		dlog.UseSyslog(false)
	}
	t := check.T(tt)

	us, err := startServerTCP(t, "tcp6", dns.HandlerFunc(FakeServer1))
	t.Nil(err)
	defer us.Shutdown()

	var relay *DNSCryptRelay
	proxy := Proxy{timeout: 2 * time.Second, xTransport: &XTransport{proxyDialer: nil}}

	msg := dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)

	query, err := msg.Pack()
	t.Nil(err)
	serverAddr, err := toServerAddr(us)
	t.Nil(err)
	r, rtt, err := tcpExchange(&proxy, serverAddr, relay, query)

	t.Nil(err)
	t.Must(len(r) > 0)
	t.Must(rtt > 0)
	resp := dns.Msg{}
	resp.Unpack(r)
	t.Must(resp.Rcode == dns.RcodeSuccess)
}

func toServerAddr(s *dns.Server) (string, error) {
	var h, p string
	var err error
	if strings.HasPrefix(s.Net, "udp") {
		h, p, err = net.SplitHostPort(s.PacketConn.LocalAddr().String())
	} else {
		h, p, err = net.SplitHostPort(s.Listener.Addr().String())
	}
	if err != nil {
		return "", err
	}
	if net.ParseIP(h).To4() == nil {
		return "[::1]:" + p, nil
	}
	return "127.0.0.1:" + p, nil
}

func startServerUDP(t *check.C, proto string, h dns.Handler) (*dns.Server, error) {
	waitLock := sync.Mutex{}
	addr := ":0"
	if proto == "udp6" {
		addr = "[::]:0"
	}
	server := &dns.Server{Addr: addr, Net: proto, ReadTimeout: time.Hour, WriteTimeout: time.Hour, NotifyStartedFunc: waitLock.Unlock, Handler: h}
	waitLock.Lock()

	go func() {
		err := server.ListenAndServe()
		t.Nil(err)
	}()
	waitLock.Lock()
	return server, nil
}

func startServerTCP(t *check.C, proto string, h dns.Handler) (*dns.Server, error) {
	waitLock := sync.Mutex{}
	addr := ":0"
	if proto == "tcp6" {
		addr = "[::]:0"
	}
	server := &dns.Server{Addr: addr, Net: proto, ReadTimeout: time.Hour, WriteTimeout: time.Hour, NotifyStartedFunc: waitLock.Unlock, Handler: h}
	waitLock.Lock()

	go func() {
		err := server.ListenAndServe()
		t.Nil(err)
	}()
	waitLock.Lock()
	return server, nil
}

func FakeServer1(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	m.Extra = make([]dns.RR, 1)
	m.Extra[0] = &dns.TXT{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{"Hello world"}}
	w.WriteMsg(m)
}
