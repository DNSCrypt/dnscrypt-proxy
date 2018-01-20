package main

import "github.com/miekg/dns"

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
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	question := questions[0]
	if question.Qclass != dns.ClassINET || question.Qtype != dns.TypeAAAA {
		return nil
	}
	synth, err := EmptyResponseFromMessage(msg)
	if err != nil {
		return err
	}
	hinfo := new(dns.HINFO)
	hinfo.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeHINFO,
		Class: dns.ClassINET, Ttl: 86400}
	hinfo.Cpu = "AAAA queries have been locally blocked by dnscrypt-proxy"
	hinfo.Os = "Set block_ipv6 to false to disable this feature"
	synth.Answer = []dns.RR{hinfo}
	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	return nil
}
