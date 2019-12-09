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
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	question := questions[0]
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return nil
	}
	qName := questions[0].Name
	idx := strings.IndexByte(qName, '.')
	if idx == -1 || (idx == 0 || idx+1 != len(qName)) {
		return nil
	}
	synth := EmptyResponseFromMessage(msg)
	synth.Rcode = dns.RcodeNameError
	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeSynth

	return nil
}
