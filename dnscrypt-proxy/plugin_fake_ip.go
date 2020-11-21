package main

import (
	"net"
	"strings"
	"unicode"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginFakeIP struct {
	fakeIPs map[string]net.IP
}

func (plugin *PluginFakeIP) Name() string {
	return "fake_ip"
}

func (plugin *PluginFakeIP) Description() string {
	return "Return a synthetic IP address when it should return specific ips"
}

func (plugin *PluginFakeIP) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of fake IP rules from [%s]", proxy.fakeIPFile)
	bin, err := ReadTextFile(proxy.fakeIPFile)
	if err != nil {
		return err
	}
	plugin.fakeIPs = make(map[string]net.IP)
	for lineNo, line := range strings.Split(string(bin), "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		var match, target string
		parts := strings.FieldsFunc(line, unicode.IsSpace)
		if len(parts) == 2 {
			match = strings.TrimFunc(parts[0], unicode.IsSpace)
			target = strings.TrimFunc(parts[1], unicode.IsSpace)
		} else if len(parts) > 2 {
			dlog.Errorf("Syntax error in fake IP rules at line %d -- Unexpected space character", 1+lineNo)
			continue
		}
		if len(match) == 0 || len(target) == 0 {
			dlog.Errorf("Syntax error in fake IP rules at line %d -- Missing ip name or target", 1+lineNo)
			continue
		}
		if strings.Contains(match, "*") || strings.Contains(target, "*") {
			dlog.Errorf("Invalid rule: [%s] - do not support wildcards at line %d", line, lineNo)
			continue
		}
		matchIP := net.ParseIP(match)
		targetIP := net.ParseIP(target)
		if matchIP == nil || targetIP == nil {
			dlog.Errorf("Suspicious fake IP rule [%s] at line %d", line, lineNo)
			continue
		}
		plugin.fakeIPs[matchIP.String()] = targetIP
	}
	if len(proxy.blockIPLogFile) == 0 {
		return nil
	}
	return nil
}

func (plugin *PluginFakeIP) Drop() error {
	return nil
}

func (plugin *PluginFakeIP) Reload() error {
	return nil
}

func (plugin *PluginFakeIP) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	answers := msg.Answer
	if len(answers) == 0 {
		return nil
	}
	for i, answer := range answers {
		header := answer.Header()
		Rrtype := header.Rrtype
		if header.Class != dns.ClassINET || (Rrtype != dns.TypeA && Rrtype != dns.TypeAAAA) {
			continue
		}
		var ipStr string
		if Rrtype == dns.TypeA {
			ipStr = answer.(*dns.A).A.String()
		} else if Rrtype == dns.TypeAAAA {
			ipStr = answer.(*dns.AAAA).AAAA.String() // IPv4-mapped IPv6 addresses are converted to IPv4
		}
		if _, found := plugin.fakeIPs[ipStr]; found {
			switch answer.(type) {
			case *dns.A:
				answers[i] = &dns.A{
					Hdr: *answer.Header(),
					A:   plugin.fakeIPs[ipStr],
				}
			case *dns.AAAA:
				answers[i] = &dns.AAAA{
					Hdr:  *answer.Header(),
					AAAA: plugin.fakeIPs[ipStr],
				}
			}
		}
	}
	var cleanedRR []dns.RR
	exist := map[string]bool{}
	for _, answer := range answers {
		if answer.Header().Rrtype != dns.TypeA && answer.Header().Rrtype != dns.TypeAAAA {
			cleanedRR = append(cleanedRR, answer)
			continue
		}
		if exist[answer.String()] {
			continue
		} else {
			cleanedRR = append(cleanedRR, answer)
			exist[answer.String()] = true
		}
	}
	msg.Answer = cleanedRR
	return nil
}
