package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type CaptivePortalEntryIPs []net.IP

type CaptivePortalMap map[string]CaptivePortalEntryIPs

type CaptivePortalHandler struct {
	cancelChannels []chan struct{}
}

func (captivePortalHandler *CaptivePortalHandler) Stop() {
	for _, cancelChannel := range captivePortalHandler.cancelChannels {
		cancelChannel <- struct{}{}
		<-cancelChannel
	}
}

func (ipsMap *CaptivePortalMap) GetEntry(msg *dns.Msg) (*dns.Question, *CaptivePortalEntryIPs) {
	if len(msg.Question) != 1 {
		return nil, nil
	}
	question := &msg.Question[0]
	name, err := NormalizeQName(question.Name)
	if err != nil {
		return nil, nil
	}
	ips, ok := (*ipsMap)[name]
	if !ok {
		return nil, nil
	}
	if question.Qclass != dns.ClassINET {
		return nil, nil
	}
	return question, &ips
}

func HandleCaptivePortalQuery(msg *dns.Msg, question *dns.Question, ips *CaptivePortalEntryIPs) *dns.Msg {
	respMsg := EmptyResponseFromMessage(msg)
	ttl := uint32(1)
	if question.Qtype == dns.TypeA {
		for _, xip := range *ips {
			if ip := xip.To4(); ip != nil {
				rr := new(dns.A)
				rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
				rr.A = ip
				respMsg.Answer = append(respMsg.Answer, rr)
			}
		}
	} else if question.Qtype == dns.TypeAAAA {
		for _, xip := range *ips {
			if xip.To4() == nil {
				if ip := xip.To16(); ip != nil {
					rr := new(dns.AAAA)
					rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
					rr.AAAA = ip
					respMsg.Answer = append(respMsg.Answer, rr)
				}
			}
		}
	}

	qType, ok := dns.TypeToString[question.Qtype]
	if !ok {
		qType = fmt.Sprint(question.Qtype)
	}
	dlog.Infof("Query for captive portal detection: [%v] (%v)", question.Name, qType)
	return respMsg
}

func handleColdStartClient(clientPc *net.UDPConn, cancelChannel chan struct{}, ipsMap *CaptivePortalMap) bool {
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
	question, ips := ipsMap.GetEntry(msg)
	if ips == nil {
		return false
	}
	respMsg := HandleCaptivePortalQuery(msg, question, ips)
	if respMsg == nil {
		return false
	}
	if response, err := respMsg.Pack(); err == nil {
		clientPc.WriteTo(response, clientAddr)
	}
	return false
}

func addColdStartListener(proxy *Proxy, ipsMap *CaptivePortalMap, listenAddrStr string, cancelChannel chan struct{}) error {
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
	if len(proxy.captivePortalMapFile) == 0 {
		return nil, nil
	}
	bin, err := ReadTextFile(proxy.captivePortalMapFile)
	if err != nil {
		dlog.Warn(err)
		return nil, err
	}
	ipsMap := make(CaptivePortalMap)
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
	proxy.captivePortalMap = &ipsMap
	return &captivePortalHandler, nil
}
