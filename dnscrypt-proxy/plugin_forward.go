package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
	"github.com/lifenjoiner/dhcpdns"
)

const (
	defaultDNSPort             = "53"
	resolvconfRetryInterval    = 30 * time.Second
	maxDHCPInconsistency       = 9
	defaultForwardRetries      = 4
	dhcpIPv6DetectorRemoteAddr = "[2001:DB8::53]:80"
	dhcpIPv4DetectorRemoteAddr = "192.0.2.53:80"
)

type SearchSequenceItemType int

const (
	Explicit SearchSequenceItemType = iota
	Bootstrap
	DHCP
	Resolvconf
)

// SearchSequenceItem represents a single resolver source in a forwarding sequence.
type SearchSequenceItem struct {
	typ        SearchSequenceItemType
	servers    []string
	resolvconf string
	rcLastFail atomic.Int64 // unix timestamp of last failed resolv.conf read
}

// PluginForwardEntry represents a forwarding rule for a specific domain.
type PluginForwardEntry struct {
	domain   string
	sequence []SearchSequenceItem
}

type resolvConfCacheEntry struct {
	mtimeUnixNano int64
	servers       []string
	warnings      []string
}

// PluginForward routes queries matching specific domains to dedicated DNS servers.
type PluginForward struct {
	forwardMap         []PluginForwardEntry
	forwardIndex       map[string][]int
	bootstrapResolvers []string
	dhcpdns            []*dhcpdns.Detector
	resolvconfCache    map[string]resolvConfCacheEntry
	dnsClient          dns.Client

	// Hot-reloading support
	mu            sync.RWMutex
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
		return fmt.Errorf("failed to read forward rules: %w", err)
	}

	requiresDHCP, forwardMap, err := plugin.parseForwardFile(lines)
	if err != nil {
		return err
	}

	plugin.forwardMap = forwardMap

	if requiresDHCP {
		if err := plugin.initDHCPDetectors(proxy); err != nil {
			return fmt.Errorf("failed to initialize DHCP detectors: %w", err)
		}
	}
	plugin.forwardIndex = buildForwardIndex(plugin.forwardMap)
	plugin.resolvconfCache = make(map[string]resolvConfCacheEntry)
	plugin.dnsClient = dns.Client{}

	return nil
}

// initDHCPDetectors starts DHCP/DNS detectors for IPv4 and IPv6 if needed.
func (plugin *PluginForward) initDHCPDetectors(proxy *Proxy) error {
	if len(proxy.userName) > 0 {
		dlog.Warn("DHCP/DNS detection may not work when 'user_name' is set or when starting as a non-root user")
	}

	if proxy.SourceIPv6 {
		dlog.Notice("Starting a DHCP/DNS detector for IPv6")
		d6 := &dhcpdns.Detector{RemoteIPPort: dhcpIPv6DetectorRemoteAddr}
		go d6.Serve(9, 10)
		plugin.dhcpdns = append(plugin.dhcpdns, d6)
	}

	if proxy.SourceIPv4 {
		dlog.Notice("Starting a DHCP/DNS detector for IPv4")
		d4 := &dhcpdns.Detector{RemoteIPPort: dhcpIPv4DetectorRemoteAddr}
		go d4.Serve(9, 10)
		plugin.dhcpdns = append(plugin.dhcpdns, d4)
	}

	return nil
}

// parseForwardFile parses forward rules from text and returns whether DHCP is required,
// the parsed forward map, and any errors encountered.
func (plugin *PluginForward) parseForwardFile(lines string) (bool, []PluginForwardEntry, error) {
	requiresDHCP := false
	forwardMap := make([]PluginForwardEntry, 0, strings.Count(lines, "\n")+1)

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
				"syntax error for forwarding rule at line %d: expected format 'example.com 9.9.9.9,8.8.8.8'",
				1+lineNo,
			)
		}

		domain = strings.ToLower(domain)
		sequence, dhcpNeeded, err := plugin.parseServerSequence(serversStr, domain, lineNo)
		if err != nil {
			return false, nil, err
		}

		if dhcpNeeded {
			requiresDHCP = true
		}

		forwardMap = append(forwardMap, PluginForwardEntry{
			domain:   domain,
			sequence: sequence,
		})
	}

	return requiresDHCP, forwardMap, nil
}

// parseServerSequence parses a comma-separated list of server specifiers for a domain.
func (plugin *PluginForward) parseServerSequence(serversStr, domain string, lineNo int) ([]SearchSequenceItem, bool, error) {
	var sequence []SearchSequenceItem
	requiresDHCP := false

	for server := range strings.SplitSeq(serversStr, ",") {
		server = strings.TrimSpace(server)

		switch server {
		case "$BOOTSTRAP":
			if len(plugin.bootstrapResolvers) == 0 {
				return nil, false, fmt.Errorf(
					"syntax error at line %d: no bootstrap resolvers available",
					1+lineNo,
				)
			}
			if !isLastSequenceType(sequence, Bootstrap) {
				sequence = append(sequence, SearchSequenceItem{typ: Bootstrap})
				dlog.Infof("Forwarding [%s] to the bootstrap servers", domain)
			}

		case "$DHCP":
			if !isLastSequenceType(sequence, DHCP) {
				sequence = append(sequence, SearchSequenceItem{typ: DHCP})
				dlog.Infof("Forwarding [%s] to the DHCP servers", domain)
			}
			requiresDHCP = true

		default:
			item, err := plugin.parseServerSpecifier(server, domain, lineNo)
			if err != nil {
				return nil, false, err
			}
			if item != nil {
				sequence = appendServerToSequence(sequence, *item)
			}
		}
	}

	return sequence, requiresDHCP, nil
}

// parseServerSpecifier handles $RESOLVCONF:, unknown keywords, and explicit IP addresses.
func (plugin *PluginForward) parseServerSpecifier(server, domain string, lineNo int) (*SearchSequenceItem, error) {
	const resolvconfPrefix = "$RESOLVCONF:"
	if strings.HasPrefix(server, resolvconfPrefix) {
		file := server[len(resolvconfPrefix):]
		if len(file) == 0 {
			dlog.Criticalf("File needs to be specified for $RESOLVCONF at line %d", 1+lineNo)
			return nil, nil
		}

		file = filepath.Clean(file)
		if !filepath.IsAbs(file) {
			dlog.Warnf(
				"$RESOLVCONF path '%s' at line %d is not absolute; this may not resolve as expected",
				file, 1+lineNo,
			)
		}

		dlog.Infof("Forwarding [%s] to the servers specified in '%s'", domain, file)
		return &SearchSequenceItem{
			typ:        Resolvconf,
			resolvconf: file,
		}, nil
	}

	if strings.HasPrefix(server, "$") {
		dlog.Criticalf("Unknown keyword [%s] at line %d", server, 1+lineNo)
		return nil, nil
	}

	// Explicit IP address
	normalized, err := normalizeIPAndOptionalPort(server, defaultDNSPort)
	if err != nil {
		dlog.Criticalf("Syntax error for forwarding rule at line %d: %s", 1+lineNo, err)
		return nil, nil
	}

	dlog.Infof("Forwarding [%s] to [%s]", domain, normalized)
	return &SearchSequenceItem{
		typ:     Explicit,
		servers: []string{normalized},
	}, nil
}

// isLastSequenceType checks if the last item in the sequence has the given type.
func isLastSequenceType(sequence []SearchSequenceItem, typ SearchSequenceItemType) bool {
	return len(sequence) > 0 && sequence[len(sequence)-1].typ == typ
}

// appendServerToSequence adds a server to the sequence, coalescing with existing Explicit items.
func appendServerToSequence(sequence []SearchSequenceItem, item SearchSequenceItem) []SearchSequenceItem {
	if item.typ != Explicit {
		return append(sequence, item)
	}

	// Find existing Explicit item to append to
	for i := range sequence {
		if sequence[i].typ == Explicit {
			sequence[i].servers = append(sequence[i].servers, item.servers...)
			return sequence
		}
	}

	return append(sequence, item)
}

func (plugin *PluginForward) Drop() error {
	if plugin.configWatcher != nil {
		plugin.configWatcher.RemoveFile(plugin.configFile)
	}
	return nil
}

// PrepareReload loads new rules into staging without applying them.
func (plugin *PluginForward) PrepareReload() error {
	lines, err := ReadTextFile(plugin.configFile)
	if err != nil {
		return fmt.Errorf("error reading config file during reload: %w", err)
	}

	_, stagingMap, err := plugin.parseForwardFile(lines)
	if err != nil {
		return fmt.Errorf("error parsing config during reload: %w", err)
	}

	plugin.stagingMap = stagingMap
	return nil
}

// ApplyReload atomically replaces active rules with staged ones.
func (plugin *PluginForward) ApplyReload() error {
	if plugin.stagingMap == nil {
		return errors.New("no staged configuration to apply")
	}

	plugin.mu.Lock()
	plugin.forwardMap = plugin.stagingMap
	plugin.forwardIndex = buildForwardIndex(plugin.stagingMap)
	plugin.stagingMap = nil
	plugin.mu.Unlock()

	dlog.Noticef("Applied new configuration for plugin [%s]", plugin.Name())
	return nil
}

// CancelReload cleans up staging resources.
func (plugin *PluginForward) CancelReload() {
	plugin.stagingMap = nil
}

// Reload implements hot-reloading for the plugin.
func (plugin *PluginForward) Reload() error {
	dlog.Noticef("Reloading configuration for plugin [%s]", plugin.Name())

	if err := plugin.PrepareReload(); err != nil {
		plugin.CancelReload()
		return err
	}

	return plugin.ApplyReload()
}

// ConfigFile returns the plugin's configuration file path.
func (plugin *PluginForward) ConfigFile() string {
	return plugin.configFile
}

// SetConfigWatcher sets the config watcher for this plugin.
func (plugin *PluginForward) SetConfigWatcher(watcher *ConfigWatcher) {
	plugin.configWatcher = watcher
}

// Eval forwards DNS queries based on configured rules.
func (plugin *PluginForward) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	qName := pluginsState.qName

	plugin.mu.RLock()
	sequence := plugin.findMatchingSequence(qName)
	plugin.mu.RUnlock()

	if len(sequence) == 0 {
		return nil
	}

	return plugin.forwardQuery(pluginsState, msg, sequence)
}

// findMatchingSequence finds the forwarding sequence for a query name.
func (plugin *PluginForward) findMatchingSequence(qName string) []SearchSequenceItem {
	qNameLen := len(qName)
	tld := qName
	if idx := strings.LastIndexByte(qName, '.'); idx >= 0 && idx+1 < len(qName) {
		tld = qName[idx+1:]
	}

	for _, candidateIdx := range plugin.forwardIndex[tld] {
		candidate := plugin.forwardMap[candidateIdx]
		candidateLen := len(candidate.domain)
		if candidateLen > qNameLen {
			continue
		}

		// Check if candidate matches as suffix or is root
		if (qName[qNameLen-candidateLen:] == candidate.domain &&
			(candidateLen == qNameLen || qName[qNameLen-candidateLen-1] == '.')) ||
			candidate.domain == "." {
			return candidate.sequence
		}
	}

	for _, candidateIdx := range plugin.forwardIndex["."] {
		candidate := plugin.forwardMap[candidateIdx]
		if candidate.domain == "." {
			return candidate.sequence
		}
	}

	return nil
}

// forwardQuery attempts to forward a DNS query through the resolver sequence.
func (plugin *PluginForward) forwardQuery(pluginsState *PluginsState, msg *dns.Msg, sequence []SearchSequenceItem) error {
	qName := pluginsState.qName
	tries := defaultForwardRetries

	for i := range sequence {
		server, err := plugin.selectServer(&sequence[i], qName)
		if err != nil || server == "" {
			if err != nil {
				dlog.Debugf("Skipping resolver for [%s]: %v", qName, err)
			}
			continue
		}

		pluginsState.serverName = server

		if tries == 0 {
			break
		}
		tries--

		dlog.Debugf("Forwarding [%s] to [%s]", qName, server)

		respMsg, err := plugin.exchangeWithServer(pluginsState, msg, server)
		if err != nil {
			continue
		}

		// Successful response
		if !respMsg.Security {
			respMsg.AuthenticatedData = false
		}
		respMsg.ID = msg.ID
		pluginsState.synthResponse = respMsg
		pluginsState.action = PluginsActionSynth
		pluginsState.returnCode = PluginsReturnCodeForward

		// Continue to next server for certain error codes if we have more servers
		if len(sequence) > i+1 {
			switch respMsg.Rcode {
			case dns.RcodeNameError, dns.RcodeRefused, dns.RcodeNotAuth:
				continue
			}
		}

		return nil
	}

	return nil
}

// selectServer chooses a server from a SearchSequenceItem.
func (plugin *PluginForward) selectServer(item *SearchSequenceItem, qName string) (string, error) {
	switch item.typ {
	case Explicit:
		return item.servers[rand.Intn(len(item.servers))], nil

	case Bootstrap:
		return plugin.bootstrapResolvers[rand.Intn(len(plugin.bootstrapResolvers))], nil

	case DHCP:
		return plugin.selectDHCPServer(qName)

	case Resolvconf:
		return plugin.selectResolvconfServer(item, qName)

	default:
		return "", fmt.Errorf("unknown sequence type: %d", item.typ)
	}
}

// selectDHCPServer selects a DHCP-provided DNS server.
func (plugin *PluginForward) selectDHCPServer(qName string) (string, error) {
	for _, detector := range plugin.dhcpdns {
		inconsistency, ip, dhcpDNS, err := detector.Status()
		if err != nil && ip != "" && inconsistency > maxDHCPInconsistency {
			dlog.Infof("No response from DHCP server while resolving [%s]: %v", qName, err)
			continue
		}

		if len(dhcpDNS) > 0 {
			selectedIP := dhcpDNS[rand.Intn(len(dhcpDNS))]
			return net.JoinHostPort(selectedIP.String(), defaultDNSPort), nil
		}
	}

	return "", errors.New("DHCP didn't provide any DNS server")
}

// selectResolvconfServer selects a server from a resolv.conf file.
func (plugin *PluginForward) selectResolvconfServer(item *SearchSequenceItem, qName string) (string, error) {
	// Check if we're in retry backoff period
	if lastFail := item.rcLastFail.Load(); lastFail != 0 {
		if time.Since(time.Unix(lastFail, 0)) < resolvconfRetryInterval {
			return "", errors.New("resolv.conf in retry backoff")
		}
	}

	servers, warnings, err := plugin.cachedResolvConf(item.resolvconf)
	if err != nil {
		dlog.Warnf("Failed to open '%s' while resolving [%s]: %v", item.resolvconf, qName, err)
		item.rcLastFail.Store(time.Now().Unix())
		return "", err
	}

	if len(servers) == 0 {
		for _, w := range warnings {
			dlog.Warn(w)
		}
		dlog.Warnf("No valid nameservers in '%s' while resolving [%s]", item.resolvconf, qName)
		item.rcLastFail.Store(time.Now().Unix())
		return "", errors.New("no valid nameservers in resolv.conf")
	}

	item.rcLastFail.Store(0) // Clear failure state on successful read

	nameserver := servers[rand.Intn(len(servers))]
	normalized, err := normalizeIPAndOptionalPort(nameserver, defaultDNSPort)
	if err != nil {
		dlog.Warnf("Syntax error in address '%s' while resolving [%s]: %v", nameserver, qName, err)
		return "", err
	}

	return normalized, nil
}

// exchangeWithServer performs DNS exchange with a server, handling truncation.
func (plugin *PluginForward) exchangeWithServer(pluginsState *PluginsState, msg *dns.Msg, server string) (*dns.Msg, error) {
	client := plugin.dnsClient
	ctx, cancel := context.WithTimeout(context.Background(), pluginsState.timeout)
	defer cancel()

	// Create a struct value copy (slice headers are copied, backing arrays shared)
	// and clear Extra/Data for forwarding.
	forwardMsg := *msg
	forwardMsg.Extra = nil
	forwardMsg.Data = nil

	respMsg, _, err := client.Exchange(ctx, &forwardMsg, pluginsState.serverProto, server)
	if err != nil {
		return nil, fmt.Errorf("exchange failed: %w", err)
	}

	// Handle truncated response by retrying over TCP
	if respMsg.Truncated {
		respMsg, _, err = client.Exchange(ctx, &forwardMsg, "tcp", server)
		if err != nil {
			return nil, fmt.Errorf("TCP retry failed: %w", err)
		}
	}

	return respMsg, nil
}

// parseResolvConf parses a resolv.conf file for nameserver entries.
func parseResolvConf(filename string) ([]string, []string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read resolv.conf: %w", err)
	}

	var servers []string
	var warnings []string

	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		addr := fields[1]
		host := addr
		if h, _, err := net.SplitHostPort(addr); err == nil {
			host = h
		}

		if net.ParseIP(host) == nil {
			warnings = append(warnings, fmt.Sprintf(
				"Ignoring invalid nameserver address '%s' in [%s]", addr, filename,
			))
			continue
		}

		servers = append(servers, addr)
	}

	return servers, warnings, nil
}

func buildForwardIndex(forwardMap []PluginForwardEntry) map[string][]int {
	index := make(map[string][]int)
	for i, entry := range forwardMap {
		if entry.domain == "." {
			index["."] = append(index["."], i)
			continue
		}
		lastLabel := entry.domain
		if idx := strings.LastIndexByte(entry.domain, '.'); idx >= 0 && idx+1 < len(entry.domain) {
			lastLabel = entry.domain[idx+1:]
		}
		index[lastLabel] = append(index[lastLabel], i)
	}
	return index
}

func (plugin *PluginForward) cachedResolvConf(filename string) ([]string, []string, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, nil, err
	}
	mtime := info.ModTime().UnixNano()

	plugin.mu.RLock()
	cacheEntry, ok := plugin.resolvconfCache[filename]
	plugin.mu.RUnlock()
	if ok && cacheEntry.mtimeUnixNano == mtime {
		return cacheEntry.servers, cacheEntry.warnings, nil
	}

	servers, warnings, err := parseResolvConf(filename)
	if err != nil {
		return nil, nil, err
	}

	serversCopy := append([]string(nil), servers...)
	warningsCopy := append([]string(nil), warnings...)
	plugin.mu.Lock()
	if plugin.resolvconfCache == nil {
		plugin.resolvconfCache = make(map[string]resolvConfCacheEntry)
	}
	plugin.resolvconfCache[filename] = resolvConfCacheEntry{
		mtimeUnixNano: mtime,
		servers:       serversCopy,
		warnings:      warningsCopy,
	}
	plugin.mu.Unlock()
	return serversCopy, warningsCopy, nil
}

// normalizeIPAndOptionalPort validates and normalizes an IP address with optional port.
func normalizeIPAndOptionalPort(addr, defaultPort string) (string, error) {
	var host, port string

	// Handle IPv6 bracket notation
	if strings.HasPrefix(addr, "[") {
		if !strings.Contains(addr, "]:") {
			if addr[len(addr)-1] != ']' {
				return "", fmt.Errorf("invalid IPv6 format: missing closing ']'")
			}
			host = addr[1 : len(addr)-1]
			port = defaultPort
		} else {
			h, p, err := net.SplitHostPort(addr)
			if err != nil {
				return "", fmt.Errorf("invalid IPv6 address with port: %w", err)
			}
			host, port = h, p
		}
	} else {
		h, p, err := net.SplitHostPort(addr)
		if err != nil {
			// No port specified
			host = addr
			port = defaultPort
		} else {
			host, port = h, p
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
