package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"path"
	"strings"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsconf"
	"github.com/jedisct1/dlog"
	"github.com/lifenjoiner/dhcpdns"
)

type SearchSequenceItemType int

const (
	Explicit SearchSequenceItemType = iota
	Bootstrap
	DHCP
	Resolvconf
)

type SearchSequenceItem struct {
	typ        SearchSequenceItemType
	servers    []string
	resolvconf string
}

type PluginForwardEntry struct {
	domain   string
	sequence []SearchSequenceItem
}

type PluginForward struct {
	forwardMap         []PluginForwardEntry
	bootstrapResolvers []string
	dhcpdns            []*dhcpdns.Detector

	// Hot-reloading support
	rwLock        sync.RWMutex
	configFile    string
	configWatcher *ConfigWatcher
	stagingMap    []PluginForwardEntry
}

func (plugin *PluginForward) Name() string {
	return "forward"
}

func (plugin *PluginForward) Description() string {
	return "Route queries matching specific domains to a dedicated set of servers"
}

func (plugin *PluginForward) Init(proxy *Proxy) error {
	plugin.configFile = proxy.forwardFile
	dlog.Noticef("Loading the set of forwarding rules from [%s]", plugin.configFile)

	if proxy.xTransport != nil {
		plugin.bootstrapResolvers = proxy.xTransport.bootstrapResolvers
	}

	lines, err := ReadTextFile(plugin.configFile)
	if err != nil {
		return err
	}

	requiresDHCP, forwardMap, err := plugin.parseForwardFile(lines)
	if err != nil {
		return err
	}

	plugin.forwardMap = forwardMap

	if requiresDHCP {
		if len(proxy.userName) > 0 {
			dlog.Warn("DHCP/DNS detection may not work when 'user_name' is set or when starting as a non-root user")
		}
		if proxy.SourceIPv6 {
			dlog.Notice("Starting a DHCP/DNS detector for IPv6")
			d6 := &dhcpdns.Detector{RemoteIPPort: "[2001:DB8::53]:80"}
			go d6.Serve(9, 10)
			plugin.dhcpdns = append(plugin.dhcpdns, d6)
		}
		if proxy.SourceIPv4 {
			dlog.Notice("Starting a DHCP/DNS detector for IPv4")
			d4 := &dhcpdns.Detector{RemoteIPPort: "192.0.2.53:80"}
			go d4.Serve(9, 10)
			plugin.dhcpdns = append(plugin.dhcpdns, d4)
		}
	}
	return nil
}

// parseForwardFile parses forward rules from text
func (plugin *PluginForward) parseForwardFile(lines string) (bool, []PluginForwardEntry, error) {
	requiresDHCP := false
	forwardMap := []PluginForwardEntry{}

	for lineNo, line := range strings.Split(lines, "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		domain, serversStr, ok := StringTwoFields(line)
		domain = strings.TrimPrefix(domain, "*.")
		if strings.Contains(domain, "*") {
			ok = false
		}
		if !ok {
			return false, nil, fmt.Errorf(
				"Syntax error for a forwarding rule at line %d. Expected syntax: example.com 9.9.9.9,8.8.8.8",
				1+lineNo,
			)
		}
		domain = strings.ToLower(domain)
		var sequence []SearchSequenceItem
		for _, server := range strings.Split(serversStr, ",") {
			server = strings.TrimSpace(server)
			switch server {
			case "$BOOTSTRAP":
				if len(plugin.bootstrapResolvers) == 0 {
					return false, nil, fmt.Errorf(
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
				const resolvconfPrexix = "$RESOLVCONF:"
				if strings.HasPrefix(server, resolvconfPrexix) {
					file := server[len(resolvconfPrexix):]
					if len(file) == 0 {
						dlog.Criticalf("File needs to be specified for $RESOLVCONF in line %d", 1+lineNo)
						continue
					}
					sequence = append(sequence, SearchSequenceItem{typ: Resolvconf, resolvconf: path.Clean(file)})
					dlog.Infof("Forwarding [%s] to the servers specified in '%s'", domain, file)
					continue
				}
				if strings.HasPrefix(server, "$") {
					dlog.Criticalf("Unknown keyword [%s] at line %d", server, 1+lineNo)
					continue
				}
				if server, err := normalizeIPAndOptionalPort(server, "53"); err != nil {
					dlog.Criticalf("Syntax error for a forwarding rule at line %d: %s", 1+lineNo, err)
					continue
				} else {
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
		}
		forwardMap = append(forwardMap, PluginForwardEntry{
			domain:   domain,
			sequence: sequence,
		})
	}

	return requiresDHCP, forwardMap, nil
}

func (plugin *PluginForward) Drop() error {
	if plugin.configWatcher != nil {
		plugin.configWatcher.RemoveFile(plugin.configFile)
	}
	return nil
}

// PrepareReload loads new rules into staging structure but doesn't apply them yet
func (plugin *PluginForward) PrepareReload() error {
	// Read the configuration file
	lines, err := SafeReadTextFile(plugin.configFile)
	if err != nil {
		return fmt.Errorf("error reading config file during reload preparation: %w", err)
	}

	// Parse the forward file
	_, stagingMap, err := plugin.parseForwardFile(lines)
	if err != nil {
		return fmt.Errorf("error parsing config during reload preparation: %w", err)
	}

	// Store in staging area
	plugin.stagingMap = stagingMap

	return nil
}

// ApplyReload atomically replaces the active rules with the staging ones
func (plugin *PluginForward) ApplyReload() error {
	if plugin.stagingMap == nil {
		return errors.New("no staged configuration to apply")
	}

	// Use write lock to swap rule structures
	plugin.rwLock.Lock()
	plugin.forwardMap = plugin.stagingMap
	plugin.stagingMap = nil
	plugin.rwLock.Unlock()

	dlog.Noticef("Applied new configuration for plugin [%s]", plugin.Name())
	return nil
}

// CancelReload cleans up any staging resources
func (plugin *PluginForward) CancelReload() {
	plugin.stagingMap = nil
}

// Reload implements hot-reloading for the plugin
func (plugin *PluginForward) Reload() error {
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
func (plugin *PluginForward) GetConfigPath() string {
	return plugin.configFile
}

// SetConfigWatcher sets the config watcher for this plugin
func (plugin *PluginForward) SetConfigWatcher(watcher *ConfigWatcher) {
	plugin.configWatcher = watcher
}

func (plugin *PluginForward) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	qName := pluginsState.qName
	qNameLen := len(qName)

	// Use read lock for thread-safe access to forwardMap
	plugin.rwLock.RLock()
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
	plugin.rwLock.RUnlock()

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
					dlog.Infof("No response from the DHCP server while resolving [%s]: %v", qName, err)
					continue
				}
				if len(dhcpDNS) > 0 {
					server = net.JoinHostPort(dhcpDNS[rand.Intn(len(dhcpDNS))].String(), "53")
					break
				}
			}
			if len(server) == 0 {
				dlog.Infof("DHCP didn't provide any DNS server to forward [%s]", qName)
				continue
			}
		case Resolvconf:
			resolvconf, err := dnsconf.FromFile(item.resolvconf)
			if err != nil {
				dlog.Warnf("Failed to open '%s' while resolving [%s]: %v", item.resolvconf, qName, err)
				continue
			}
			if len(resolvconf.Servers) == 0 {
				dlog.Warnf("No nameservers specificied in '%s' while resolving [%s]", item.resolvconf, qName)
				continue
			}
			server = resolvconf.Servers[rand.Intn(len(resolvconf.Servers))]
			server, err = normalizeIPAndOptionalPort(server, "53")
			if err != nil {
				dlog.Warnf("Syntax error in address '%s' while resolving [%s]: %v", item.resolvconf, qName, err)
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
		client := dns.Client{}
		ctx, cancel := context.WithTimeout(context.Background(), pluginsState.timeout)

		// Create a clean copy of the message without Extra section for forwarding
		forwardMsg := msg.Copy()
		forwardMsg.Extra = nil
		forwardMsg.Data = nil // Clear packed data so Exchange will re-pack without Extra

		respMsg, _, err = client.Exchange(ctx, forwardMsg, pluginsState.serverProto, server)
		if err != nil {
			cancel()
			continue
		}
		if respMsg.Truncated {
			respMsg, _, err = client.Exchange(ctx, forwardMsg, "tcp", server)
			if err != nil {
				cancel()
				continue
			}
		}
		cancel()
		if !respMsg.Security {
			respMsg.AuthenticatedData = false
		}
		respMsg.ID = msg.ID
		pluginsState.synthResponse = respMsg
		pluginsState.action = PluginsActionSynth
		pluginsState.returnCode = PluginsReturnCodeForward
		if len(sequence) > 0 {
			switch respMsg.Rcode {
			case dns.RcodeNameError, dns.RcodeRefused, dns.RcodeNotAuth:
				continue
			}
		}
		return nil
	}
	return err
}

func normalizeIPAndOptionalPort(addr string, defaultPort string) (string, error) {
	var host, port string
	var err error

	if strings.HasPrefix(addr, "[") {
		if !strings.Contains(addr, "]:") {
			if addr[len(addr)-1] != ']' {
				return "", fmt.Errorf("invalid IPv6 format: missing closing ']'")
			}
			host = addr[1 : len(addr)-1]
			port = defaultPort
		} else {
			host, port, err = net.SplitHostPort(addr)
			if err != nil {
				return "", err
			}
		}
	} else {
		host, port, err = net.SplitHostPort(addr)
		if err != nil {
			host = addr
			port = defaultPort
		}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: [%s]", host)
	}
	if ip.To4() != nil {
		return fmt.Sprintf("%s:%s", ip.String(), port), nil
	}
	return fmt.Sprintf("[%s]:%s", ip.String(), port), nil
}
