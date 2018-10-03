package main

import "github.com/miekg/dns"

type PluginGetSetPayloadSize struct{}

func (plugin *PluginGetSetPayloadSize) Name() string {
	return "get_set_payload_size"
}

func (plugin *PluginGetSetPayloadSize) Description() string {
	return "Adjusts the maximum payload size advertised in queries sent to upstream servers."
}

func (plugin *PluginGetSetPayloadSize) Init(proxy *Proxy) error {
	return nil
}

func (plugin *PluginGetSetPayloadSize) Drop() error {
	return nil
}

func (plugin *PluginGetSetPayloadSize) Reload() error {
	return nil
}

func (plugin *PluginGetSetPayloadSize) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	pluginsState.originalMaxPayloadSize = 512 - ResponseOverhead
	edns0 := msg.IsEdns0()
	dnssec := false
	if edns0 != nil {
		pluginsState.originalMaxPayloadSize = Min(int(edns0.UDPSize())-ResponseOverhead, pluginsState.originalMaxPayloadSize)
		dnssec = edns0.Do()
	}
	var options *[]dns.EDNS0
	pluginsState.dnssec = dnssec
	pluginsState.maxPayloadSize = Min(MaxDNSUDPPacketSize-ResponseOverhead, Max(pluginsState.originalMaxPayloadSize, pluginsState.maxPayloadSize))
	if pluginsState.maxPayloadSize > 512 {
		extra2 := []dns.RR{}
		for _, extra := range msg.Extra {
			if extra.Header().Rrtype != dns.TypeOPT {
				extra2 = append(extra2, extra)
			} else if xoptions := &extra.(*dns.OPT).Option; len(*xoptions) > 0 && options == nil {
				options = xoptions
			}
		}
		msg.Extra = extra2
		msg.SetEdns0(uint16(pluginsState.maxPayloadSize), dnssec)
		if options != nil {
			for _, extra := range msg.Extra {
				if extra.Header().Rrtype == dns.TypeOPT {
					extra.(*dns.OPT).Option = *options
					break
				}
			}
		}
	}
	return nil
}
