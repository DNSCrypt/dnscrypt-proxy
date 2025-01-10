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

type SearchSequenceItemType int

const (
	Explicit SearchSequenceItemType = iota
	Bootstrap
	DHCP
)

type SearchSequenceItem struct {
	typ     SearchSequenceItemType
	servers []string
}

type PluginForwardEntry struct {
	domain   string
	sequence []SearchSequenceItem
}

type PluginForward struct {
	forwardMap         []PluginForwardEntry
	bootstrapResolvers []string
	dhcpdns            []*dhcpdns.Detector
}

func (plugin *PluginForward) Name() string {
	return "forward"
}

func (plugin *PluginForward) Description() string {
	return "Route queries matching specific domains to a dedicated set of servers"
}

func (plugin *PluginForward) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of forwarding rules from [%s]", proxy.forwardFile)

	if proxy.xTransport != nil {
		plugin.bootstrapResolvers = proxy.xTransport.bootstrapResolvers
	}

	lines, err := ReadTextFile(proxy.forwardFile)
	if err != nil {
		return err
	}
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
		requiresDHCP := false
		var sequence []SearchSequenceItem
		for _, server := range strings.Split(serversStr, ",") {
			server = strings.TrimSpace(server)
			switch server {
			case "$BOOTSTRAP":
				if len(plugin.bootstrapResolvers) == 0 {
					return fmt.Errorf(
						"Syntax error for a forwarding rule at line %d. No bootstrap resolvers available",
						1+lineNo,
					)
				}
				if len(sequence) > 0 && sequence[len(sequence)-1].typ == Bootstrap {
					// Ignore repetitions
				} else {
					sequence = append(sequence, SearchSequenceItem{typ: Bootstrap})
					dlog.Infof("Forwarding [%s] to the bootstrap servers", domain)
				}
			case "$DHCP":
				if len(sequence) > 0 && sequence[len(sequence)-1].typ == DHCP {
					// Ignore repetitions
				} else {
					sequence = append(sequence, SearchSequenceItem{typ: DHCP})
					dlog.Infof("Forwarding [%s] to the DHCP servers", domain)
				}
				requiresDHCP = true
			default:
				if strings.HasPrefix(server, "$") {
					dlog.Criticalf("Unknown keyword [%s] at line %d", server, 1+lineNo)
					continue
				}
				server = strings.TrimPrefix(server, "[")
				server = strings.TrimSuffix(server, "]")
				if ip := net.ParseIP(server); ip != nil {
					if ip.To4() != nil {
						server = fmt.Sprintf("%s:%d", server, 53)
					} else {
						server = fmt.Sprintf("[%s]:%d", server, 53)
					}
				}
				idxServers := -1
				for i, item := range sequence {
					if item.typ == Explicit {
						idxServers = i
					}
				}
				if idxServers == -1 {
					sequence = append(sequence, SearchSequenceItem{typ: Explicit, servers: []string{server}})
				} else {
					sequence[idxServers].servers = append(sequence[idxServers].servers, server)
				}
				dlog.Infof("Forwarding [%s] to [%s]", domain, server)
			}
		}
		if requiresDHCP {
			if len(proxy.userName) > 0 {
				dlog.Warn("DHCP/DNS detection may not work when `user_name` is set or when starting as a non-root user")
			}
			if proxy.SourceIPv6 {
				dlog.Info("Starting a DHCP/DNS detector for IPv6")
				d6 := &dhcpdns.Detector{RemoteIPPort: "[2001:DB8::53]:80"}
				go d6.Serve(9, 10)
				plugin.dhcpdns = append(plugin.dhcpdns, d6)
			}
			if proxy.SourceIPv4 {
				dlog.Info("Starting a DHCP/DNS detector for IPv4")
				d4 := &dhcpdns.Detector{RemoteIPPort: "192.0.2.53:80"}
				go d4.Serve(9, 10)
				plugin.dhcpdns = append(plugin.dhcpdns, d4)
			}
		}
		plugin.forwardMap = append(plugin.forwardMap, PluginForwardEntry{
			domain:   domain,
			sequence: sequence,
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
	var sequence []SearchSequenceItem
	for _, candidate := range plugin.forwardMap {
		candidateLen := len(candidate.domain)
		if candidateLen > qNameLen {
			continue
		}
		if (qName[qNameLen-candidateLen:] == candidate.domain &&
			(candidateLen == qNameLen || (qName[qNameLen-candidateLen-1] == '.'))) ||
			(candidate.domain == ".") {
			sequence = candidate.sequence
			break
		}
	}
	if len(sequence) == 0 {
		return nil
	}
	var err error
	var respMsg *dns.Msg
	tries := 4
	for _, item := range sequence {
		var server string
		switch item.typ {
		case Explicit:
			server = item.servers[rand.Intn(len(item.servers))]
		case Bootstrap:
			server = plugin.bootstrapResolvers[rand.Intn(len(plugin.bootstrapResolvers))]
		case DHCP:
			const maxInconsistency = 9
			for _, dhcpdns := range plugin.dhcpdns {
				inconsistency, ip, dhcpDNS, err := dhcpdns.Status()
				if err != nil && ip != "" && inconsistency > maxInconsistency {
					dhcpDNS = nil
				}
				if len(dhcpDNS) > 0 {
					server = net.JoinHostPort(dhcpDNS[rand.Intn(len(dhcpDNS))].String(), "53")
					break
				}
			}
			if len(server) == 0 {
				dlog.Warn("DHCP didn't provide any DNS server")
				continue
			}
		}
		pluginsState.serverName = server
		if len(server) == 0 {
			continue
		}

		if tries == 0 {
			break
		}
		tries--
		dlog.Debugf("Forwarding [%s] to [%s]", qName, server)
		client := dns.Client{Net: pluginsState.serverProto, Timeout: pluginsState.timeout}
		respMsg, _, err = client.Exchange(msg, server)
		if err != nil {
			continue
		}
		if respMsg.Truncated {
			client.Net = "tcp"
			respMsg, _, err = client.Exchange(msg, server)
			if err != nil {
				continue
			}
		}
		if len(sequence) > 0 {
			switch respMsg.Rcode {
			case dns.RcodeNameError, dns.RcodeRefused, dns.RcodeNotAuth:
				continue
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
	return err
}
