package main

import (
	"errors"
	"fmt"
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
	target      string
	ipv4        []net.IP
	ipv6        []net.IP
	lastUpdate4 *time.Time
	lastUpdate6 *time.Time
	lineNo      int
	isIP        bool
	PTR         []string
}

type PluginCloak struct {
	sync.RWMutex
	patternMatcher *PatternMatcher
	ttl            uint32
	createPTR      bool

	// Hot-reloading support
	configFile     string
	configWatcher  *ConfigWatcher
	stagingMatcher *PatternMatcher
}

func (plugin *PluginCloak) Name() string {
	return "cloak"
}

func (plugin *PluginCloak) Description() string {
	return "Return a synthetic IP address or a flattened CNAME for specific names"
}

func (plugin *PluginCloak) Init(proxy *Proxy) error {
	plugin.configFile = proxy.cloakFile
	dlog.Noticef("Loading the set of cloaking rules from [%s]", plugin.configFile)

	lines, err := ReadTextFile(plugin.configFile)
	if err != nil {
		return err
	}

	plugin.ttl = proxy.cloakTTL
	plugin.createPTR = proxy.cloakedPTR
	plugin.patternMatcher = NewPatternMatcher()

	if err := plugin.loadRules(lines, plugin.patternMatcher); err != nil {
		return err
	}

	return nil
}

// loadRules parses cloaking rules from text and adds them to a pattern matcher
func (plugin *PluginCloak) loadRules(lines string, patternMatcher *PatternMatcher) error {
	cloakedNames := make(map[string]*CloakedName)

	for lineNo, line := range strings.Split(lines, "\n") {
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
				cloakedName.ipv4 = append(cloakedName.ipv4, ipv4)
			} else {
				cloakedName.ipv6 = append(cloakedName.ipv6, ip)
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
			reversed, _ := dns.ReverseAddr(cloakedName.ipv6[0].String())
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
		if err := patternMatcher.Add(line, cloakedName, cloakedName.lineNo); err != nil {
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
	if plugin.configWatcher != nil {
		plugin.configWatcher.RemoveFile(plugin.configFile)
	}
	return nil
}

// PrepareReload loads new cloaking rules into staging matcher but doesn't apply them yet
func (plugin *PluginCloak) PrepareReload() error {
	// Read the configuration file
	lines, err := SafeReadTextFile(plugin.configFile)
	if err != nil {
		return fmt.Errorf("error reading config file during reload preparation: %w", err)
	}

	// Create new staging pattern matcher
	plugin.stagingMatcher = NewPatternMatcher()

	// Load rules into staging matcher
	if err := plugin.loadRules(lines, plugin.stagingMatcher); err != nil {
		return fmt.Errorf("error parsing config during reload preparation: %w", err)
	}

	return nil
}

// ApplyReload atomically replaces the active pattern matcher with the staging one
func (plugin *PluginCloak) ApplyReload() error {
	if plugin.stagingMatcher == nil {
		return errors.New("no staged configuration to apply")
	}

	// Use write lock to swap pattern matchers
	plugin.Lock()
	plugin.patternMatcher = plugin.stagingMatcher
	plugin.stagingMatcher = nil
	plugin.Unlock()

	dlog.Noticef("Applied new configuration for plugin [%s]", plugin.Name())
	return nil
}

// CancelReload cleans up any staging resources
func (plugin *PluginCloak) CancelReload() {
	plugin.stagingMatcher = nil
}

// Reload implements hot-reloading for the plugin
func (plugin *PluginCloak) Reload() error {
	dlog.Noticef("Reloading configuration for plugin [%s]", plugin.Name())

	// Prepare the new configuration
	if err := plugin.PrepareReload(); err != nil {
		plugin.CancelReload()
		return err
	}

	// Apply the new configuration
	return plugin.ApplyReload()
}

// GetConfigPath returns the path to the plugin's configuration file
func (plugin *PluginCloak) GetConfigPath() string {
	return plugin.configFile
}

// SetConfigWatcher sets the config watcher for this plugin
func (plugin *PluginCloak) SetConfigWatcher(watcher *ConfigWatcher) {
	plugin.configWatcher = watcher
}

func (plugin *PluginCloak) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	question := msg.Question[0]
	if question.Qclass != dns.ClassINET || question.Qtype == dns.TypeNS || question.Qtype == dns.TypeSOA {
		return nil
	}
	now := time.Now()

	// Use read lock for thread-safe access to patternMatcher
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
	var lastUpdate *time.Time
	switch question.Qtype {
	case dns.TypeA:
		lastUpdate = cloakedName.lastUpdate4
	case dns.TypeAAAA:
		lastUpdate = cloakedName.lastUpdate6
	}
	if lastUpdate != nil {
		if elapsed := uint32(now.Sub(*lastUpdate).Seconds()); elapsed < ttl {
			ttl -= elapsed
		} else {
			expired = true
		}
	}
	synth := EmptyResponseFromMessage(msg)
	if !cloakedName.isIP && ((question.Qtype == dns.TypeA && cloakedName.ipv4 == nil) ||
		(question.Qtype == dns.TypeAAAA && cloakedName.ipv6 == nil) || expired) {
		target := cloakedName.target
		plugin.RUnlock()
		returnIPv4 := question.Qtype == dns.TypeA
		returnIPv6 := question.Qtype == dns.TypeAAAA
		foundIPs, _, err := pluginsState.xTransport.resolveUsingServers(
			pluginsState.xTransport.mainProto,
			target,
			pluginsState.xTransport.internalResolvers,
			returnIPv4,
			returnIPv6,
		)
		if err != nil {
			synth.Rcode = dns.RcodeServerFailure
			pluginsState.synthResponse = synth
			pluginsState.action = PluginsActionSynth
			pluginsState.returnCode = PluginsReturnCodeCloak
			return nil
		}

		// Use write lock to update cloakedName
		plugin.Lock()
		if len(foundIPs) > 0 {
			n := Min(16, len(foundIPs))
			switch question.Qtype {
			case dns.TypeA:
				cloakedName.lastUpdate4 = &now
				cloakedName.ipv4 = foundIPs[:n]
			case dns.TypeAAAA:
				cloakedName.lastUpdate6 = &now
				cloakedName.ipv6 = foundIPs[:n]
			}
		}
		plugin.Unlock()

		// Reacquire read lock
		plugin.RLock()
	}

	ipv4 := append([]net.IP(nil), cloakedName.ipv4...)
	ipv6 := append([]net.IP(nil), cloakedName.ipv6...)
	ptrs := append([]string(nil), cloakedName.PTR...)
	ttlLocal := ttl
	plugin.RUnlock()

	synth := EmptyResponseFromMessage(msg)

	synth.Answer = []dns.RR{}
	if question.Qtype == dns.TypeA {
		for _, ip := range ipv4 {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttlLocal}
			rr.A = ip
			synth.Answer = append(synth.Answer, rr)
		}
	} else if question.Qtype == dns.TypeAAAA {
		for _, ip := range ipv6 {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttlLocal}
			rr.AAAA = ip
			synth.Answer = append(synth.Answer, rr)
		}
	} else if question.Qtype == dns.TypePTR {
		for _, ptr := range ptrs {
			rr := new(dns.PTR)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttlLocal}
			rr.Ptr = ptr
			synth.Answer = append(synth.Answer, rr)
		}
	}
	plugin.RUnlock()

	rand.Shuffle(
		len(synth.Answer),
		func(i, j int) { synth.Answer[i], synth.Answer[j] = synth.Answer[j], synth.Answer[i] },
	)
	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeCloak
	return nil
}
