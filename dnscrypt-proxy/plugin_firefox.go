// Work around Mozilla's evil plan - https://sk.tl/3Ek6tzhq

package main

import (
	"strings"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginFirefox struct {
}

func (plugin *PluginFirefox) Name() string {
	return "firefox"
}

func (plugin *PluginFirefox) Description() string {
	return "Work around Firefox taking over DNS"
}

func (plugin *PluginFirefox) Init(proxy *Proxy) error {
	dlog.Noticef("Firefox workaround initialized")
	return nil
}

func (plugin *PluginFirefox) Drop() error {
	return nil
}

func (plugin *PluginFirefox) Reload() error {
	return nil
}

func (plugin *PluginFirefox) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if pluginsState.clientProto == "local_doh" {
		return nil
	}
	question := msg.Question[0]
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return nil
	}
	qName := pluginsState.qName
	if qName != "use-application-dns.net" && !strings.HasSuffix(qName, ".use-application-dns.net") {
		return nil
	}
	synth := EmptyResponseFromMessage(msg)
	synth.Rcode = dns.RcodeNameError
	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeSynth
	return nil
}
