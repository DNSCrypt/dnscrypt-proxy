package main

import (
	"github.com/miekg/dns"
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
	queryMetaRR.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeTXT,
		Class: dns.ClassINET, Ttl: 86400}
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
