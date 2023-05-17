package main

import (
	"fmt"
	"math/rand"
	"net"
	"strings"

	"github.com/jedisct1/dlog"
	"github.com/lifenjoiner/dhcpdns"
	"github.com/miekg/dns"
)

type PluginForwardEntry struct {
	domain  string
	servers []string
}

type PluginForward struct {
	forwardMap      []PluginForwardEntry
	dhcpdns         []*dhcpdns.Detector
	dhcpdnsFallback []string
}

func (plugin *PluginForward) Name() string {
	return "forward"
}

func (plugin *PluginForward) Description() string {
	return "Route queries matching specific domains to a dedicated set of servers"
}

func (plugin *PluginForward) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of forwarding rules from [%s]", proxy.forwardFile)
	lines, err := ReadTextFile(proxy.forwardFile)
	if err != nil {
		return err
	}
	hasVar := false
	for lineNo, line := range strings.Split(lines, "\n") {
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
			if server == "$DHCPDNS" {
				hasVar = true
			} else if net.ParseIP(server) != nil {
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
	if hasVar {
		if proxy.SourceIPv6 {
			d6 := &dhcpdns.Detector{RemoteIPPort: "[2001:4860:4860::8888]:80"}
			go d6.Serve(9, 10)
			plugin.dhcpdns = append(plugin.dhcpdns, d6)
		}
		if proxy.SourceIPv4 {
			d4 := &dhcpdns.Detector{RemoteIPPort: "8.8.8.8:80"}
			go d4.Serve(9, 10)
			plugin.dhcpdns = append(plugin.dhcpdns, d4)
		}
		plugin.dhcpdnsFallback = proxy.xTransport.bootstrapResolvers
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
	if server == "$DHCPDNS" {
		for _, dhcpdns := range plugin.dhcpdns {
			n, ip, DNS, err := dhcpdns.Status()
			maxFail := 9
			if err != nil && ip != "" && n > maxFail {
				DNS = nil
			}
			if len(DNS) > 0 {
				server = net.JoinHostPort(DNS[rand.Intn(len(DNS))].String(), "53")
				break
			}
		}
		if server == "$DHCPDNS" {
			dlog.Noticef("$DHCPDNS han't been solved, forward to one of bootstrap_resolvers")
			server = plugin.dhcpdnsFallback[rand.Intn(len(plugin.dhcpdnsFallback))]
		}
	}
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
