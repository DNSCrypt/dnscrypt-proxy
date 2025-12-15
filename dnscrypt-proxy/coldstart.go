package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/jedisct1/dlog"
)

type CaptivePortalEntryIPs []net.IP

type CaptivePortalMap map[string]CaptivePortalEntryIPs

type CaptivePortalHandler struct {
	wg            sync.WaitGroup
	cancelChannel chan struct{}
}

func (captivePortalHandler *CaptivePortalHandler) Stop() {
	close(captivePortalHandler.cancelChannel)
	captivePortalHandler.wg.Wait()
}

func (ipsMap *CaptivePortalMap) GetEntry(msg *dns.Msg) (dns.RR, *CaptivePortalEntryIPs) {
	if len(msg.Question) != 1 {
		return nil, nil
	}
	question := msg.Question[0]
	hdr := question.Header()
	name, err := NormalizeQName(hdr.Name)
	if err != nil {
		return nil, nil
	}
	ips, ok := (*ipsMap)[name]
	if !ok {
		return nil, nil
	}
	if hdr.Class != dns.ClassINET {
		return nil, nil
	}
	return question, &ips
}

func HandleCaptivePortalQuery(msg *dns.Msg, question dns.RR, ips *CaptivePortalEntryIPs) *dns.Msg {
	respMsg := EmptyResponseFromMessage(msg)
	ttl := uint32(1)
	hdr := question.Header()
	qtype := dns.RRToType(question)
	if qtype == dns.TypeA {
		for _, xip := range *ips {
			if ip := xip.To4(); ip != nil {
				rr := new(dns.A)
				rr.Hdr = dns.Header{Name: hdr.Name, Class: dns.ClassINET, TTL: ttl}
				rr.A = rdata.A{Addr: netip.AddrFrom4([4]byte(ip))}
				respMsg.Answer = append(respMsg.Answer, rr)
			}
		}
	} else if qtype == dns.TypeAAAA {
		for _, xip := range *ips {
			if xip.To4() == nil {
				rr := new(dns.AAAA)
				rr.Hdr = dns.Header{Name: hdr.Name, Class: dns.ClassINET, TTL: ttl}
				rr.AAAA = rdata.AAAA{Addr: netip.AddrFrom16([16]byte(xip.To16()))}
				respMsg.Answer = append(respMsg.Answer, rr)
			}
		}
	}

	qTypeStr, ok := dns.TypeToString[qtype]
	if !ok {
		qTypeStr = fmt.Sprint(qtype)
	}
	dlog.Infof("Query for captive portal detection: [%v] (%v)", hdr.Name, qTypeStr)
	return respMsg
}

func handleColdStartClient(clientPc *net.UDPConn, cancelChannel chan struct{}, ipsMap *CaptivePortalMap) bool {
	buffer := make([]byte, MaxDNSPacketSize)
	clientPc.SetDeadline(time.Now().Add(time.Duration(1) * time.Second))
	length, clientAddr, err := clientPc.ReadFrom(buffer)
	exit := false
	select {
	case <-cancelChannel:
		exit = true
	default:
	}
	if exit {
		return true
	}
	if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
		return false
	}
	if err != nil {
		dlog.Warn(err)
		return true
	}
	packet := buffer[:length]
	msg := &dns.Msg{}
	msg.Data = packet
	if err := msg.Unpack(); err != nil {
		return false
	}
	question, ips := ipsMap.GetEntry(msg)
	if ips == nil {
		return false
	}
	respMsg := HandleCaptivePortalQuery(msg, question, ips)
	if respMsg == nil {
		return false
	}
	if err := respMsg.Pack(); err == nil {
		clientPc.WriteTo(respMsg.Data, clientAddr)
	}
	return false
}

func addColdStartListener(
	ipsMap *CaptivePortalMap,
	listenAddrStr string,
	captivePortalHandler *CaptivePortalHandler,
) error {
	network := "udp"
	isIPv4 := isDigit(listenAddrStr[0])
	if isIPv4 {
		network = "udp4"
	}
	listenUDPAddr, err := net.ResolveUDPAddr(network, listenAddrStr)
	if err != nil {
		return err
	}
	clientPc, err := net.ListenUDP(network, listenUDPAddr)
	if err != nil {
		return err
	}
	captivePortalHandler.wg.Add(1)
	go func() {
		for !handleColdStartClient(clientPc, captivePortalHandler.cancelChannel, ipsMap) {
		}
		clientPc.Close()
		captivePortalHandler.wg.Done()
	}()
	return nil
}

func ColdStart(proxy *Proxy) (*CaptivePortalHandler, error) {
	if len(proxy.captivePortalMapFile) == 0 {
		return nil, nil
	}
	lines, err := ReadTextFile(proxy.captivePortalMapFile)
	if err != nil {
		dlog.Warn(err)
		return nil, err
	}
	ipsMap := make(CaptivePortalMap)
	for lineNo, line := range strings.Split(lines, "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		name, ipsStr, ok := StringTwoFields(line)
		if !ok {
			return nil, fmt.Errorf(
				"Syntax error for a captive portal rule at line %d",
				1+lineNo,
			)
		}
		name, err = NormalizeQName(name)
		if err != nil {
			continue
		}
		if strings.Contains(ipsStr, "*") {
			return nil, fmt.Errorf(
				"A captive portal rule must use an exact host name at line %d",
				1+lineNo,
			)
		}
		var ips []net.IP
		for _, ip := range strings.Split(ipsStr, ",") {
			ipStr := strings.TrimSpace(ip)
			if ip := net.ParseIP(ipStr); ip != nil {
				ips = append(ips, ip)
			} else {
				return nil, fmt.Errorf(
					"Syntax error for a captive portal rule at line %d",
					1+lineNo,
				)
			}
		}
		ipsMap[name] = ips
	}
	listenAddrStrs := proxy.listenAddresses
	captivePortalHandler := CaptivePortalHandler{
		cancelChannel: make(chan struct{}),
	}
	ok := false
	for _, listenAddrStr := range listenAddrStrs {
		err = addColdStartListener(&ipsMap, listenAddrStr, &captivePortalHandler)
		if err == nil {
			ok = true
		}
	}
	if ok {
		err = nil
	}
	proxy.captivePortalMap = &ipsMap
	return &captivePortalHandler, err
}
