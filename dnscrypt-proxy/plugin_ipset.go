package main

import (
	"io"
	"strings"
	"github.com/janeczku/go-ipset/ipset"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginIPSet struct {
	patternMatcher  *PatternMatcher
	ipsets			map[string]*ipset.IPSet
	logger          io.Writer
	format          string
}

type anIPSet struct {
	ipsetName		string
}

func (plugin *PluginIPSet) Name() string {
	return "ipset_name"
}

func (plugin *PluginIPSet) Description() string {
	return "ipset name matching patterns"
}

func (plugin *PluginIPSet) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of ipset names from [%s]", proxy.ipsetNameFile)
	bin, err := ReadTextFile(proxy.ipsetNameFile)
	if err != nil {
		return err
	}
	plugin.patternMatcher = NewPatternMatcher()
	plugin.ipsets = make(map[string]*ipset.IPSet)
	for lineNo, line := range strings.Split(string(bin), "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		parts := strings.Fields(line)
		ipsetName := ""
		if len(parts) < 2 {
			dlog.Errorf("Syntax error in ipset names at line %d. Missing ipset name?", 1+lineNo)
		}
		ipsetName = strings.TrimSpace(parts[1])
		var xIpset anIPSet
		xIpset.ipsetName = ipsetName
		dlog.Noticef("Found ipset: [%s]", xIpset.ipsetName)
		plugin.ipsets[ipsetName], _ = ipset.New(ipsetName, "hash:ip", &ipset.Params{})
		plugin.ipsets[ipsetName + "6"], _ = ipset.New(ipsetName + "6", "hash:ip", &ipset.Params{HashFamily: "inet6"})
		dlog.Noticef("line:%s", parts[0])
		if err := plugin.patternMatcher.Add(parts[0], xIpset, lineNo+1); err != nil {
			dlog.Error(err)
			continue
		}
	}

	return nil
}

func (plugin *PluginIPSet) Drop() error {
	return nil
}

func (plugin *PluginIPSet) Reload() error {
	return nil
}

func (plugin *PluginIPSet) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	answers := msg.Answer
	if len(answers) == 0 {
		return nil
	}
	qName := pluginsState.qName
	ipsetList, _, xIpset := plugin.patternMatcher.Eval(qName)
	if xIpset == nil {
		return nil
	}
	var ipStr string
	var ipsetName = xIpset.(anIPSet).ipsetName
	dlog.Noticef("ipsetName: %s", ipsetName)

	if ipsetList {
	for _, answer := range answers {
		header := answer.Header()
		Rrtype := header.Rrtype
		if header.Class != dns.ClassINET || (Rrtype != dns.TypeA && Rrtype != dns.TypeAAAA) {
			continue
		}
		if Rrtype == dns.TypeA {
			ipStr = answer.(*dns.A).A.String()
			dlog.Noticef("ipStr: %s", ipStr)
			var _ipset interface{Add(string, int) error} = plugin.ipsets[ipsetName]
			_ = _ipset.Add(ipStr, 0)
		} else if Rrtype == dns.TypeAAAA {
			ipStr = answer.(*dns.AAAA).AAAA.String() // IPv4-mapped IPv6 addresses are converted to IPv4
			dlog.Noticef("ipStr: %s", ipStr)
			var _ipset interface{Add(string, int) error} = plugin.ipsets[ipsetName + "6"]
			_ = _ipset.Add(ipStr, 0)
		}
	}
	}
	return nil
}
