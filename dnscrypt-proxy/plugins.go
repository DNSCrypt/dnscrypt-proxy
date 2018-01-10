package main

import (
	"github.com/miekg/dns"
)

type PluginsAction int

const (
	PluginsActionNone    = 0
	PluginsActionForward = 1
	PluginsActionDrop    = 2
	PluginsActionReject  = 3
)

type PluginsState struct {
	sessionData            map[string]interface{}
	action                 PluginsAction
	originalMaxPayloadSize int
	maxPayloadSize         int
	proto                  string
	queryPlugins           *[]Plugin
	responsePlugins        *[]Plugin
}

type Plugin interface {
	Name() string
	Description() string
	Eval(pluginsState *PluginsState, msg *dns.Msg) error
}

func NewPluginsState(proto string) PluginsState {
	queryPlugins := &[]Plugin{Plugin(new(PluginGetSetPayloadSize))}
	responsePlugins := &[]Plugin{}
	return PluginsState{action: PluginsActionForward, maxPayloadSize: MaxDNSUDPPacketSize - ResponseOverhead,
		queryPlugins: queryPlugins, responsePlugins: responsePlugins, proto: proto}
}

func (pluginsState *PluginsState) ApplyQueryPlugins(packet []byte) ([]byte, error) {
	pluginsState.action = PluginsActionForward
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return packet, err
	}
	for _, plugin := range *pluginsState.queryPlugins {
		if ret := plugin.Eval(pluginsState, &msg); ret != nil {
			pluginsState.action = PluginsActionDrop
			return packet, ret
		}
	}
	packet2, err := msg.PackBuffer(packet)
	if err != nil {
		return packet, err
	}
	return packet2, nil
}

type PluginGetSetPayloadSize struct{}

func (plugin *PluginGetSetPayloadSize) Name() string {
	return "get_set_payload_size"
}

func (plugin *PluginGetSetPayloadSize) Description() string {
	return "Adjusts the maximum payload size advertised in queries sent to upstream servers."
}

func (plugin *PluginGetSetPayloadSize) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	pluginsState.originalMaxPayloadSize = 512 - ResponseOverhead
	opt := msg.IsEdns0()
	dnssec := false
	if opt != nil {
		pluginsState.originalMaxPayloadSize = Min(int(opt.UDPSize())-ResponseOverhead, pluginsState.originalMaxPayloadSize)
		dnssec = opt.Do()
	}
	pluginsState.maxPayloadSize = Min(MaxDNSUDPPacketSize-ResponseOverhead, Max(pluginsState.originalMaxPayloadSize, pluginsState.maxPayloadSize))
	if pluginsState.maxPayloadSize > 512 {
		extra2 := []dns.RR{}
		for _, extra := range msg.Extra {
			if extra.Header().Rrtype != dns.TypeOPT {
				extra2 = append(extra2, extra)
			}
		}
		msg.Extra = extra2
		msg.SetEdns0(uint16(pluginsState.maxPayloadSize), dnssec)
	}
	return nil
}
