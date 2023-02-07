package main

import (
	"math/rand"
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
	ipv4       []net.IP
	ipv6       []net.IP
	lastUpdate *time.Time
	lineNo     int
	isIP       bool
	PTR        []string
}

type PluginCloak struct {
	sync.RWMutex
	patternMatcher *PatternMatcher
	ttl            uint32
	createPTR      bool
}

func (plugin *PluginCloak) Name() string {
	return "cloak"
}

func (plugin *PluginCloak) Description() string {
	return "Return a synthetic IP address or a flattened CNAME for specific names"
}

func (plugin *PluginCloak) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of cloaking rules from [%s]", proxy.cloakFile)
	bin, err := ReadTextFile(proxy.cloakFile)
	if err != nil {
		return err
	}
	plugin.ttl = proxy.cloakTTL
	plugin.createPTR = proxy.cloakedPTR
	plugin.patternMatcher = NewPatternMatcher()
	cloakedNames := make(map[string]*CloakedName)
	for lineNo, line := range strings.Split(string(bin), "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		var target string
		parts := strings.FieldsFunc(line, unicode.IsSpace)
		if len(parts) == 2 {
			line = strings.TrimSpace(parts[0])
			target = strings.TrimSpace(parts[1])
		} else if len(parts) > 2 {
			dlog.Errorf("Syntax error in cloaking rules at line %d -- Unexpected space character", 1+lineNo)
			continue
		}
		if len(line) == 0 || len(target) == 0 {
			dlog.Errorf("Syntax error in cloaking rules at line %d -- Missing name or target", 1+lineNo)
			continue
		}
		line = strings.ToLower(line)
		cloakedName, found := cloakedNames[line]
		if !found {
			cloakedName = &CloakedName{}
		}
		ip := net.ParseIP(target)
		if ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				cloakedName.ipv4 = append((*cloakedName).ipv4, ipv4)
			} else if ipv6 := ip.To16(); ipv6 != nil {
				cloakedName.ipv6 = append((*cloakedName).ipv6, ipv6)
			} else {
				dlog.Errorf("Invalid IP address in cloaking rule at line %d", 1+lineNo)
				continue
			}
			cloakedName.isIP = true
		} else {
			cloakedName.target = target
		}
		cloakedName.lineNo = lineNo + 1
		cloakedNames[line] = cloakedName

		if !plugin.createPTR || strings.Contains(line, "*") || !cloakedName.isIP {
			continue
		}

		var ptrLine string
		if ipv4 := ip.To4(); ipv4 != nil {
			reversed, _ := dns.ReverseAddr(ip.To4().String())
			ptrLine = strings.TrimSuffix(reversed, ".")
		} else {
			reversed, _ := dns.ReverseAddr(cloakedName.ipv6[0].To16().String())
			ptrLine = strings.TrimSuffix(reversed, ".")
		}
		ptrQueryLine := ptrEntryToQuery(ptrLine)
		ptrCloakedName, found := cloakedNames[ptrQueryLine]
		if !found {
			ptrCloakedName = &CloakedName{}
		}
		ptrCloakedName.isIP = true
		ptrCloakedName.PTR = append((*ptrCloakedName).PTR, ptrNameToFQDN(line))
		ptrCloakedName.lineNo = lineNo + 1
		cloakedNames[ptrQueryLine] = ptrCloakedName
	}
	for line, cloakedName := range cloakedNames {
		if err := plugin.patternMatcher.Add(line, cloakedName, cloakedName.lineNo); err != nil {
			return err
		}
	}
	return nil
}

func ptrEntryToQuery(ptrEntry string) string {
	return "=" + ptrEntry
}

func ptrNameToFQDN(ptrLine string) string {
	ptrLine = strings.TrimPrefix(ptrLine, "=")
	return ptrLine + "."
}

func (plugin *PluginCloak) Drop() error {
	return nil
}

func (plugin *PluginCloak) Reload() error {
	return nil
}

func (plugin *PluginCloak) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	question := msg.Question[0]
	if question.Qclass != dns.ClassINET || question.Qtype == dns.TypeNS || question.Qtype == dns.TypeSOA {
		return nil
	}
	now := time.Now()
	plugin.RLock()
	_, _, xcloakedName := plugin.patternMatcher.Eval(pluginsState.qName)
	if xcloakedName == nil {
		plugin.RUnlock()
		return nil
	}
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA && question.Qtype != dns.TypePTR {
		plugin.RUnlock()
		pluginsState.action = PluginsActionReject
		pluginsState.returnCode = PluginsReturnCodeCloak
		return nil
	}
	cloakedName := xcloakedName.(*CloakedName)
	ttl, expired := plugin.ttl, false
	if cloakedName.lastUpdate != nil {
		if elapsed := uint32(now.Sub(*cloakedName.lastUpdate).Seconds()); elapsed < ttl {
			ttl -= elapsed
		} else {
			expired = true
		}
	}
	if !cloakedName.isIP && ((cloakedName.ipv4 == nil && cloakedName.ipv6 == nil) || expired) {
		target := cloakedName.target
		plugin.RUnlock()
		foundIPs, err := net.LookupIP(target)
		if err != nil {
			return nil
		}
		plugin.Lock()
		cloakedName.lastUpdate = &now
		cloakedName.ipv4 = nil
		cloakedName.ipv6 = nil
		for _, foundIP := range foundIPs {
			if ipv4 := foundIP.To4(); ipv4 != nil {
				cloakedName.ipv4 = append(cloakedName.ipv4, foundIP)
				if len(cloakedName.ipv4) >= 16 {
					break
				}
			} else {
				cloakedName.ipv6 = append(cloakedName.ipv6, foundIP)
				if len(cloakedName.ipv6) >= 16 {
					break
				}
			}
		}
		plugin.Unlock()
		plugin.RLock()
	}
	plugin.RUnlock()
	synth := EmptyResponseFromMessage(msg)
	synth.Answer = []dns.RR{}
	if question.Qtype == dns.TypeA {
		for _, ip := range cloakedName.ipv4 {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			rr.A = ip
			synth.Answer = append(synth.Answer, rr)
		}
	} else if question.Qtype == dns.TypeAAAA {
		for _, ip := range cloakedName.ipv6 {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			rr.AAAA = ip
			synth.Answer = append(synth.Answer, rr)
		}
	} else if question.Qtype == dns.TypePTR {
		for _, ptr := range cloakedName.PTR {
			rr := new(dns.PTR)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}
			rr.Ptr = ptr
			synth.Answer = append(synth.Answer, rr)
		}
	}
	rand.Shuffle(
		len(synth.Answer),
		func(i, j int) { synth.Answer[i], synth.Answer[j] = synth.Answer[j], synth.Answer[i] },
	)
	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeCloak
	return nil
}
