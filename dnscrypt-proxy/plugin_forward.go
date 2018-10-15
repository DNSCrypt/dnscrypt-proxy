package main

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"unicode"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginForwardEntry struct {
	domain  string
	servers []string
}

type PluginForward struct {
	forwardMap []PluginForwardEntry
}

func (plugin *PluginForward) Name() string {
	return "forward"
}

func (plugin *PluginForward) Description() string {
	return "Route queries matching specific domains to a dedicated set of servers"
}

func (plugin *PluginForward) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of forwarding rules from [%s]", proxy.forwardFile)
	bin, err := ReadTextFile(proxy.forwardFile)
	if err != nil {
		return err
	}
	for lineNo, line := range strings.Split(string(bin), "\n") {
		line = strings.TrimFunc(line, unicode.IsSpace)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		domain, serversStr, ok := StringTwoFields(line)
		if !ok {
			return fmt.Errorf("Syntax error for a forwarding rule at line %d. Expected syntax: example.com: 9.9.9.9,8.8.8.8", 1+lineNo)
		}
		domain = strings.ToLower(domain)
		var servers []string
		for _, server := range strings.Split(serversStr, ",") {
			server = strings.TrimFunc(server, unicode.IsSpace)
			if net.ParseIP(server) != nil {
				server = fmt.Sprintf("%s:%d", server, 53)
			}
			servers = append(servers, server)
		}
		if len(servers) == 0 {
			continue
		}
		plugin.forwardMap = append(plugin.forwardMap, PluginForwardEntry{
			domain: domain, servers: servers,
		})
	}
	return nil
}

func (plugin *PluginForward) Drop() error {
	return nil
}

func (plugin *PluginForward) Reload() error {
	return nil
}

func (plugin *PluginForward) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	question := strings.ToLower(StripTrailingDot(questions[0].Name))
	questionLen := len(question)
	var servers []string
	for _, candidate := range plugin.forwardMap {
		candidateLen := len(candidate.domain)
		if candidateLen > questionLen {
			continue
		}
		if question[questionLen-candidateLen:] == candidate.domain && (candidateLen == questionLen || (question[questionLen-candidateLen-1] == '.')) {
			servers = candidate.servers
			break
		}
	}
	if len(servers) == 0 {
		return nil
	}
	server := servers[rand.Intn(len(servers))]
	respMsg, err := dns.Exchange(msg, server)
	if err != nil {
		return err
	}
	pluginsState.synthResponse = respMsg
	pluginsState.action = PluginsActionSynth
	return nil
}
