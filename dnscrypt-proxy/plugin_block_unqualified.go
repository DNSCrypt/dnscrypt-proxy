package main

import (
	"strings"

	"github.com/miekg/dns"
)

type PluginBlockUnqualified struct {
}

func (plugin *PluginBlockUnqualified) Name() string {
	return "block_unqualified"
}

func (plugin *PluginBlockUnqualified) Description() string {
	return "Block unqualified DNS names"
}

func (plugin *PluginBlockUnqualified) Init(proxy *Proxy) error {
	return nil
}

func (plugin *PluginBlockUnqualified) Drop() error {
	return nil
}

func (plugin *PluginBlockUnqualified) Reload() error {
	return nil
}

func (plugin *PluginBlockUnqualified) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	question := msg.Question[0]
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return nil
	}
	if strings.IndexByte(pluginsState.qName, '.') >= 0 {
		return nil
	}
	synth := EmptyResponseFromMessage(msg)
	synth.Rcode = dns.RcodeNameError
	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeSynth

	return nil
}
