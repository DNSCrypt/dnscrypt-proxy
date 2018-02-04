package main

import (
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type CloakedName struct {
	target     string
	ipv4       *net.IP
	ipv6       *net.IP
	lastUpdate *time.Time
	isIP       bool
}

type PluginCloak struct {
	sync.RWMutex
	cloakedNames map[string]*CloakedName
}

func (plugin *PluginCloak) Name() string {
	return "cloak"
}

func (plugin *PluginCloak) Description() string {
	return "Return a synthetic IP address or a flattened CNAME for specific names"
}

func (plugin *PluginCloak) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of cloaking rules from [%s]", proxy.cloakFile)
	bin, err := ioutil.ReadFile(proxy.cloakFile)
	if err != nil {
		return err
	}
	plugin.cloakedNames = make(map[string]*CloakedName)
	for lineNo, line := range strings.Split(string(bin), "\n") {
		line = strings.TrimFunc(line, unicode.IsSpace)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		var target string
		parts := strings.FieldsFunc(line, unicode.IsSpace)
		if len(parts) == 2 {
			line = strings.TrimFunc(parts[0], unicode.IsSpace)
			target = strings.TrimFunc(parts[1], unicode.IsSpace)
		} else if len(parts) > 2 {
			dlog.Errorf("Syntax error in cloaking rules at line %d -- Unexpected space character", 1+lineNo)
			continue
		}
		if len(line) == 0 || len(target) == 0 {
			dlog.Errorf("Syntax error in cloaking rules at line %d -- Missing name or target", 1+lineNo)
			continue
		}
		line = strings.ToLower(line)
		cloakedName := CloakedName{}
		if ip := net.ParseIP(target); ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				cloakedName.ipv4 = &ipv4
			} else if ipv6 := ip.To16(); ipv6 != nil {
				cloakedName.ipv6 = &ipv6
			} else {
				dlog.Errorf("Invalid IP address in cloaking rule at line %d", 1+lineNo)
				continue
			}
			cloakedName.isIP = true
		} else {
			cloakedName.target = target
		}
		plugin.cloakedNames[line] = &cloakedName
	}
	return nil
}

func (plugin *PluginCloak) Drop() error {
	return nil
}

func (plugin *PluginCloak) Reload() error {
	return nil
}

func (plugin *PluginCloak) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	question := questions[0]
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return nil
	}
	qName := strings.ToLower(StripTrailingDot(questions[0].Name))
	if len(qName) < 2 {
		return nil
	}
	plugin.RLock()
	cloakedName, _ := plugin.cloakedNames[qName]
	plugin.RUnlock()
	if cloakedName == nil {
		return nil
	}
	var ip *net.IP
	if question.Qtype == dns.TypeA {
		ip = cloakedName.ipv4
	} else {
		ip = cloakedName.ipv6
	}
	if !cloakedName.isIP {
		foundIPs, err := net.LookupIP(cloakedName.target)
		if err != nil {
			return nil
		}
		plugin.Lock()
		for _, foundIP := range foundIPs {
			if ipv4 := foundIP.To4(); ipv4 != nil {
				cloakedName.ipv4 = &ipv4
			} else {
				cloakedName.ipv6 = &foundIP
			}
			if cloakedName.ipv4 != nil && cloakedName.ipv6 != nil {
				break
			}
		}
		plugin.Unlock()
		if question.Qtype == dns.TypeA {
			ip = cloakedName.ipv4
		} else {
			ip = cloakedName.ipv6
		}
	}
	if ip == nil {
		return nil
	}
	synth, err := EmptyResponseFromMessage(msg)
	if err != nil {
		return err
	}
	if question.Qtype == dns.TypeA {
		rr := new(dns.A)
		rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}
		rr.A = *ip
		synth.Answer = []dns.RR{rr}
	} else {
		rr := new(dns.AAAA)
		rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1}
		rr.AAAA = *ip
		synth.Answer = []dns.RR{rr}
	}
	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	return nil
}
