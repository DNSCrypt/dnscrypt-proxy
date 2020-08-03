package main

import (
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type CaptivePortalEntryips []net.IP

type CaptivePortalEntry struct {
	name string
	ips  CaptivePortalEntryips
}

type CaptivePortalHandler struct {
	cancelChannels []chan struct{}
}

func (captivePortalHandler *CaptivePortalHandler) Stop() {	
	for _, cancelChannel := range captivePortalHandler.cancelChannels {
		cancelChannel <- struct{}{}
		_ = <-cancelChannel
	}
}

func handleColdStartClient(clientPc *net.UDPConn, cancelChannel chan struct{}, ipsMap *map[string]CaptivePortalEntryips) bool {
	buffer := make([]byte, MaxDNSPacketSize-1)
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
	if err := msg.Unpack(packet); err != nil {
		return false
	}
	if len(msg.Question) != 1 {
		return false
	}
	question := msg.Question[0]
	qType, ok := dns.TypeToString[question.Qtype]
	if !ok {
		qType = string(qType)
	}
	name, err := NormalizeQName(question.Name)
	if err != nil {
		return false
	}
	ips, ok := (*ipsMap)[name]
	if !ok {
		dlog.Infof("Coldstart query: [%v] (%v)", name, qType)
		return false
	}
	dlog.Noticef("Coldstart query for captive portal detection: [%v] (%v)", name, qType)
	if question.Qclass != dns.ClassINET {
		return false
	}
	var respMsg *dns.Msg
	respMsg = EmptyResponseFromMessage(msg)
	ttl := uint32(1)
	if question.Qtype == dns.TypeA {
		for _, xip := range ips {
			if ip := xip.To4(); ip != nil {
				rr := new(dns.A)
				rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
				rr.A = ip
				respMsg.Answer = []dns.RR{rr}
				break
			}
		}
	} else if question.Qtype == dns.TypeAAAA {
		for _, xip := range ips {
			if ip := xip.To16(); ip != nil {
				rr := new(dns.AAAA)
				rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
				rr.AAAA = ip
				respMsg.Answer = []dns.RR{rr}
				break
			}
		}
	}
	if response, err := respMsg.Pack(); err == nil {
		clientPc.WriteTo(response, clientAddr)
		dlog.Noticef("Coldstart query synthesized: [%v] (%v)", name, qType)
	}
	return false
}

func addColdStartListener(proxy *Proxy, ipsMap *map[string]CaptivePortalEntryips, listenAddrStr string, cancelChannel chan struct{}) error {
	listenUDPAddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
	if err != nil {
		return err
	}
	clientPc, err := net.ListenUDP("udp", listenUDPAddr)
	if err != nil {
		return err
	}
	go func() {
		for !handleColdStartClient(clientPc, cancelChannel, ipsMap) {
		}
		clientPc.Close()
		cancelChannel <- struct{}{}
	}()
	return nil
}

func ColdStart(proxy *Proxy) (*CaptivePortalHandler, error) {
	if len(proxy.captivePortalFile) == 0 {
		return nil, nil
	}
	bin, err := ReadTextFile(proxy.captivePortalFile)
	if err != nil {
		dlog.Warn(err)
		return nil, err
	}
	ipsMap := make(map[string]CaptivePortalEntryips)
	for lineNo, line := range strings.Split(string(bin), "\n") {
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
		var ips []net.IP
		for _, ip := range strings.Split(ipsStr, ",") {
			ipStr := strings.TrimFunc(ip, unicode.IsSpace)
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
	cancelChannels := make([]chan struct{}, 0)
	for _, listenAddrStr := range listenAddrStrs {
		cancelChannel := make(chan struct{})
		if err := addColdStartListener(proxy, &ipsMap, listenAddrStr, cancelChannel); err == nil {
			cancelChannels = append(cancelChannels, cancelChannel)
		}
	}
	captivePortalHandler := CaptivePortalHandler{
		cancelChannels: cancelChannels,
	}
	return &captivePortalHandler, nil
}
