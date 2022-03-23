package main

import (
	"fmt"
	"math/rand"
	"net"
	"strings"

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
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		domain, serversStr, ok := StringTwoFields(line)
		if !ok {
			return fmt.Errorf(
				"Syntax error for a forwarding rule at line %d. Expected syntax: example.com 9.9.9.9,8.8.8.8",
				1+lineNo,
			)
		}
		domain = strings.ToLower(domain)
		var servers []string
		for _, server := range strings.Split(serversStr, ",") {
			server = strings.TrimSpace(server)
			if net.ParseIP(server) != nil {
				server = fmt.Sprintf("%s:%d", server, 53)
			}
			servers = append(servers, server)
		}
		if len(servers) == 0 {
			continue
		}
		plugin.forwardMap = append(plugin.forwardMap, PluginForwardEntry{
			domain:  domain,
			servers: servers,
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
	qName := pluginsState.qName
	qNameLen := len(qName)
	var servers []string
	for _, candidate := range plugin.forwardMap {
		candidateLen := len(candidate.domain)
		if candidateLen > qNameLen {
			continue
		}
		if qName[qNameLen-candidateLen:] == candidate.domain &&
			(candidateLen == qNameLen || (qName[qNameLen-candidateLen-1] == '.')) {
			servers = candidate.servers
			break
		}
	}
	if len(servers) == 0 {
		return nil
	}
	server := servers[rand.Intn(len(servers))]
	pluginsState.serverName = server
	client := dns.Client{Net: pluginsState.serverProto, Timeout: pluginsState.timeout}
	respMsg, _, err := client.Exchange(msg, server)
	if err != nil {
		return err
	}
	if respMsg.Truncated {
		client.Net = "tcp"
		respMsg, _, err = client.Exchange(msg, server)
		if err != nil {
			return err
		}
	}
	if edns0 := respMsg.IsEdns0(); edns0 == nil || !edns0.Do() {
		respMsg.AuthenticatedData = false
	}
	respMsg.Id = msg.Id
	pluginsState.synthResponse = respMsg
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeForward
	return nil
}
