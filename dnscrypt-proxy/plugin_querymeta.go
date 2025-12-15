package main

import (
	"codeberg.org/miekg/dns"
)

type PluginQueryMeta struct {
	queryMetaRR *dns.TXT
}

func (plugin *PluginQueryMeta) Name() string {
	return "query_log"
}

func (plugin *PluginQueryMeta) Description() string {
	return "Log DNS queries."
}

func (plugin *PluginQueryMeta) Init(proxy *Proxy) error {
	queryMetaRR := new(dns.TXT)
	queryMetaRR.Hdr = dns.Header{
		Name: ".", Class: dns.ClassINET, TTL: 86400,
	}
	queryMetaRR.Txt = proxy.queryMeta
	plugin.queryMetaRR = queryMetaRR
	return nil
}

func (plugin *PluginQueryMeta) Drop() error {
	return nil
}

func (plugin *PluginQueryMeta) Reload() error {
	return nil
}

func (plugin *PluginQueryMeta) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	msg.Extra = []dns.RR{plugin.queryMetaRR}
	return nil
}
