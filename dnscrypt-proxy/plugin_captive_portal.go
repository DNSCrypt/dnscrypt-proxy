package main

import (
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginCaptivePortal struct {
	captivePortalMap *CaptivePortalMap
}

func (plugin *PluginCaptivePortal) Name() string {
	return "captive portal handlers"
}

func (plugin *PluginCaptivePortal) Description() string {
	return "Handle test queries operating systems make to detect Wi-Fi captive portal"
}

func (plugin *PluginCaptivePortal) Init(proxy *Proxy) error {
	plugin.captivePortalMap = proxy.captivePortalMap
	dlog.Notice("Captive portals handler enabled")
	return nil
}

func (plugin *PluginCaptivePortal) Drop() error {
	return nil
}

func (plugin *PluginCaptivePortal) Reload() error {
	return nil
}

func (plugin *PluginCaptivePortal) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	question, ips := plugin.captivePortalMap.GetEntry(msg)
	if ips == nil {
		return nil
	}
	if synth := HandleCaptivePortalQuery(msg, question, ips); synth != nil {
		pluginsState.synthResponse = synth
		pluginsState.action = PluginsActionSynth
	}
	return nil
}
