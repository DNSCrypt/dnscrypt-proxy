package main

import "codeberg.org/miekg/dns"

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

	// In v2, EDNS0 info is directly on msg
	dnssec := msg.Security
	if msg.UDPSize > 0 {
		pluginsState.maxUnencryptedUDPSafePayloadSize = int(msg.UDPSize)
		pluginsState.originalMaxPayloadSize = Max(
			pluginsState.maxUnencryptedUDPSafePayloadSize-ResponseOverhead,
			pluginsState.originalMaxPayloadSize,
		)
	}

	pluginsState.dnssec = dnssec
	pluginsState.maxPayloadSize = Min(
		MaxDNSUDPPacketSize-ResponseOverhead,
		Max(pluginsState.originalMaxPayloadSize, pluginsState.maxPayloadSize),
	)

	if pluginsState.maxPayloadSize > 512 {
		// Set the EDNS0 parameters on msg directly
		msg.UDPSize = uint16(pluginsState.maxPayloadSize)
		msg.Security = dnssec
	}

	return nil
}
