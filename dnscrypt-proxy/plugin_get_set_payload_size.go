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
	opt := msg.IsEdns0()
	dnssec := false
	if opt != nil {
		pluginsState.originalMaxPayloadSize = Min(int(opt.UDPSize())-ResponseOverhead, pluginsState.originalMaxPayloadSize)
		dnssec = opt.Do()
	}
	pluginsState.dnssec = dnssec
	pluginsState.maxPayloadSize = Min(MaxDNSUDPPacketSize-ResponseOverhead, Max(pluginsState.originalMaxPayloadSize, pluginsState.maxPayloadSize))
	if pluginsState.maxPayloadSize > 512 {
		msg.SetEdns0(uint16(pluginsState.maxPayloadSize), dnssec)
	}
	return nil
}
