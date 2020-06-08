package main

import (
	"strings"

	"github.com/miekg/dns"
)

type PluginBlockIPv6 struct{}

func (plugin *PluginBlockIPv6) Name() string {
	return "block_ipv6"
}

func (plugin *PluginBlockIPv6) Description() string {
	return "Immediately return a synthetic response to AAAA queries."
}

func (plugin *PluginBlockIPv6) Init(proxy *Proxy) error {
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
	synth := EmptyResponseFromMessage(msg)
	hinfo := new(dns.HINFO)
	hinfo.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeHINFO,
		Class: dns.ClassINET, Ttl: 86400}
	hinfo.Cpu = "AAAA queries have been locally blocked by dnscrypt-proxy"
	hinfo.Os = "Set block_ipv6 to false to disable this feature"
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
