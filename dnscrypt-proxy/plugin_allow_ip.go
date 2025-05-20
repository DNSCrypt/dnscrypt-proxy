package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	iradix "github.com/hashicorp/go-immutable-radix"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginAllowedIP struct {
	allowedPrefixes *iradix.Tree
	allowedIPs      map[string]interface{}
	logger          io.Writer
	format          string

	// Hot-reloading support
	rwLock          sync.RWMutex
	configFile      string
	configWatcher   *ConfigWatcher
	stagingPrefixes *iradix.Tree
	stagingIPs      map[string]interface{}
}

func (plugin *PluginAllowedIP) Name() string {
	return "allow_ip"
}

func (plugin *PluginAllowedIP) Description() string {
	return "Allows DNS queries containing specific IP addresses"
}

func (plugin *PluginAllowedIP) Init(proxy *Proxy) error {
	plugin.configFile = proxy.allowedIPFile
	dlog.Noticef("Loading the set of allowed IP rules from [%s]", plugin.configFile)

	lines, err := ReadTextFile(plugin.configFile)
	if err != nil {
		return err
	}

	plugin.allowedPrefixes = iradix.New()
	plugin.allowedIPs = make(map[string]interface{})

	if err := plugin.loadRules(lines, plugin.allowedPrefixes, plugin.allowedIPs); err != nil {
		return err
	}

	if len(proxy.allowedIPLogFile) > 0 {
		plugin.logger = Logger(proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups, proxy.allowedIPLogFile)
		plugin.format = proxy.allowedIPFormat
	}

	return nil
}

// loadRules parses and loads IP rules into the provided tree and map
func (plugin *PluginAllowedIP) loadRules(lines string, prefixes *iradix.Tree, ips map[string]interface{}) error {
	for lineNo, line := range strings.Split(lines, "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}

		ip := net.ParseIP(line)
		trailingStar := strings.HasSuffix(line, "*")
		if len(line) < 2 || (ip != nil && trailingStar) {
			dlog.Errorf("Suspicious allowed IP rule [%s] at line %d", line, lineNo)
			continue
		}

		if trailingStar {
			line = line[:len(line)-1]
		}
		if strings.HasSuffix(line, ":") || strings.HasSuffix(line, ".") {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			dlog.Errorf("Empty allowed IP rule at line %d", lineNo)
			continue
		}
		if strings.Contains(line, "*") {
			dlog.Errorf("Invalid rule: [%s] - wildcards can only be used as a suffix at line %d", line, lineNo)
			continue
		}

		line = strings.ToLower(line)
		if trailingStar {
			var updated *iradix.Tree
			updated, _, _ = prefixes.Insert([]byte(line), 0)
			prefixes = updated
		} else {
			ips[line] = true
		}
	}

	return nil
}

func (plugin *PluginAllowedIP) Drop() error {
	if plugin.configWatcher != nil {
		plugin.configWatcher.RemoveFile(plugin.configFile)
	}
	return nil
}

// PrepareReload loads new rules into staging structures but doesn't apply them yet
func (plugin *PluginAllowedIP) PrepareReload() error {
	// Read the configuration file
	lines, err := SafeReadTextFile(plugin.configFile)
	if err != nil {
		return fmt.Errorf("error reading config file during reload preparation: %w", err)
	}

	// Create staging structures
	plugin.stagingPrefixes = iradix.New()
	plugin.stagingIPs = make(map[string]interface{})

	// Load rules into staging structures
	if err := plugin.loadRules(lines, plugin.stagingPrefixes, plugin.stagingIPs); err != nil {
		return fmt.Errorf("error parsing config during reload preparation: %w", err)
	}

	return nil
}

// ApplyReload atomically replaces the active rules with the staging ones
func (plugin *PluginAllowedIP) ApplyReload() error {
	if plugin.stagingPrefixes == nil || plugin.stagingIPs == nil {
		return errors.New("no staged configuration to apply")
	}

	// Use write lock to swap rule structures
	plugin.rwLock.Lock()
	plugin.allowedPrefixes = plugin.stagingPrefixes
	plugin.allowedIPs = plugin.stagingIPs
	plugin.stagingPrefixes = nil
	plugin.stagingIPs = nil
	plugin.rwLock.Unlock()

	dlog.Noticef("Applied new configuration for plugin [%s]", plugin.Name())
	return nil
}

// CancelReload cleans up any staging resources
func (plugin *PluginAllowedIP) CancelReload() {
	plugin.stagingPrefixes = nil
	plugin.stagingIPs = nil
}

// Reload implements hot-reloading for the plugin
func (plugin *PluginAllowedIP) Reload() error {
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
func (plugin *PluginAllowedIP) GetConfigPath() string {
	return plugin.configFile
}

// SetConfigWatcher sets the config watcher for this plugin
func (plugin *PluginAllowedIP) SetConfigWatcher(watcher *ConfigWatcher) {
	plugin.configWatcher = watcher
}

func (plugin *PluginAllowedIP) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	answers := msg.Answer
	if len(answers) == 0 {
		return nil
	}

	allowed, reason, ipStr := false, "", ""

	// Use read lock for thread-safe access to configuration
	plugin.rwLock.RLock()
	defer plugin.rwLock.RUnlock()

	for _, answer := range answers {
		header := answer.Header()
		Rrtype := header.Rrtype
		if header.Class != dns.ClassINET || (Rrtype != dns.TypeA && Rrtype != dns.TypeAAAA) {
			continue
		}
		if Rrtype == dns.TypeA {
			ipStr = answer.(*dns.A).A.String()
		} else if Rrtype == dns.TypeAAAA {
			ipStr = answer.(*dns.AAAA).AAAA.String() // IPv4-mapped IPv6 addresses are converted to IPv4
		}
		if _, found := plugin.allowedIPs[ipStr]; found {
			allowed, reason = true, ipStr
			break
		}
		match, _, found := plugin.allowedPrefixes.Root().LongestPrefix([]byte(ipStr))
		if found {
			if len(match) == len(ipStr) || (ipStr[len(match)] == '.' || ipStr[len(match)] == ':') {
				allowed, reason = true, string(match)+"*"
				break
			}
		}
	}

	if allowed {
		pluginsState.sessionData["whitelisted"] = true
		if plugin.logger != nil {
			qName := pluginsState.qName
			var clientIPStr string
			switch pluginsState.clientProto {
			case "udp":
				clientIPStr = (*pluginsState.clientAddr).(*net.UDPAddr).IP.String()
			case "tcp", "local_doh":
				clientIPStr = (*pluginsState.clientAddr).(*net.TCPAddr).IP.String()
			default:
				// Ignore internal flow.
				return nil
			}
			var line string
			if plugin.format == "tsv" {
				now := time.Now()
				year, month, day := now.Date()
				hour, minute, second := now.Clock()
				tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
				line = fmt.Sprintf(
					"%s\t%s\t%s\t%s\t%s\n",
					tsStr,
					clientIPStr,
					StringQuote(qName),
					StringQuote(ipStr),
					StringQuote(reason),
				)
			} else if plugin.format == "ltsv" {
				line = fmt.Sprintf("time:%d\thost:%s\tqname:%s\tip:%s\tmessage:%s\n", time.Now().Unix(), clientIPStr, StringQuote(qName), StringQuote(ipStr), StringQuote(reason))
			} else {
				dlog.Fatalf("Unexpected log format: [%s]", plugin.format)
			}
			if plugin.logger == nil {
				return errors.New("Log file not initialized")
			}
			_, _ = plugin.logger.Write([]byte(line))
		}
	}
	return nil
}
