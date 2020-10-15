package main

import (
	"errors"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type PluginBlockIPv6 struct {
	proxy          *Proxy
	blockDualStack bool
}

func (plugin *PluginBlockIPv6) Name() string {
	return "block_ipv6"
}

func (plugin *PluginBlockIPv6) Description() string {
	return "Return a synthetic response to AAAA queries immediately or if A record exists"
}

func (plugin *PluginBlockIPv6) Init(proxy *Proxy) error {
	plugin.proxy = proxy
	plugin.blockDualStack = !proxy.pluginBlockIPv6 && proxy.pluginBlockIPv6DualStack
	return nil
}

func (plugin *PluginBlockIPv6) Drop() error {
	return nil
}

func (plugin *PluginBlockIPv6) Reload() error {
	return nil
}

func (plugin *PluginBlockIPv6) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	question := msg.Question[0]
	if question.Qclass != dns.ClassINET || question.Qtype != dns.TypeAAAA {
		return nil
	}
	if plugin.blockDualStack {
		msgA := msg.Copy()
		msgA.SetQuestion(question.Name, dns.TypeA)
		msgAPacket, err := msgA.Pack()
		if err != nil {
			return err
		}
		if !plugin.proxy.clientsCountInc() {
			return errors.New("Too many concurrent connections to handle block_ipv6_dual_stack subqueries")
		}
		respAPacket := plugin.proxy.processIncomingQuery("trampoline", plugin.proxy.mainProto, msgAPacket, nil, nil, time.Now())
		plugin.proxy.clientsCountDec()
		respA := dns.Msg{}
		if err := respA.Unpack(respAPacket); err != nil {
			return err
		}
		if respA.Rcode != dns.RcodeSuccess {
			return nil
		}
		hasAAnswer := false
		for _, answer := range respA.Answer {
			header := answer.Header()
			if header.Rrtype == dns.TypeA {
				hasAAnswer = true
				break
			}
		}
		if !hasAAnswer {
			return nil
		}
	}
	synth := EmptyResponseFromMessage(msg)
	hinfo := new(dns.HINFO)
	hinfo.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeHINFO,
		Class: dns.ClassINET, Ttl: 86400}
	hinfo.Cpu = "This AAAA query has been locally blocked by dnscrypt-proxy"
	hinfo.Os = "Set block_ipv6 and block_ipv6_dual_stack to false to disable this feature"
	synth.Answer = []dns.RR{hinfo}
	qName := question.Name
	i := strings.Index(qName, ".")
	parentZone := "."
	if !(i < 0 || i+1 >= len(qName)) {
		parentZone = qName[i+1:]
	}
	soa := new(dns.SOA)
	soa.Mbox = "h.invalid."
	soa.Ns = "a.root-servers.net."
	soa.Serial = 1
	soa.Refresh = 10000
	soa.Minttl = 2400
	soa.Expire = 604800
	soa.Retry = 300
	soa.Hdr = dns.RR_Header{Name: parentZone, Rrtype: dns.TypeSOA,
		Class: dns.ClassINET, Ttl: 60}
	synth.Ns = []dns.RR{soa}
	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeSynth
	return nil
}
