// Firefox DoH Canary Domain Plugin
//
// This plugin prevents Firefox from bypassing dnscrypt-proxy and using external DoH servers.
// Firefox queries "use-application-dns.net" (the canary domain) to determine if it should
// enable its built-in DoH. When this domain returns NXDOMAIN, Firefox respects the local
// DNS configuration and doesn't override it with external DoH servers.
//
// Why this is important:
// - Without this plugin, Firefox may bypass dnscrypt-proxy entirely and send DNS queries
//   directly to external DoH servers (like Cloudflare), defeating the purpose of running
//   a local DNS proxy for privacy, filtering, or security.
// - This is especially critical when NOT using local DoH, as Firefox would otherwise
//   route around the proxy.
// - Even when using local DoH, this plugin ensures Firefox respects the user's DNS choice.
//
// Technical details:
// - Firefox performs a lookup for "use-application-dns.net" and its subdomains
// - If the query returns NXDOMAIN (name error), Firefox disables its automatic DoH
// - This allows dnscrypt-proxy to handle all DNS queries as configured
//
// Reference: https://sk.tl/3Ek6tzhq (Mozilla's canary domain documentation)

package main

import (
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
)

type PluginFirefox struct{}

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
	qtype := dns.RRToType(question)
	if question.Header().Class != dns.ClassINET || (qtype != dns.TypeA && qtype != dns.TypeAAAA) {
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
