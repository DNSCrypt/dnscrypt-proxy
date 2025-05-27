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

type PluginBlockIP struct {
	blockedPrefixes *iradix.Tree
	blockedIPs      map[string]interface{}
	logger          io.Writer
	format          string

	// Hot-reloading support
	rwLock          sync.RWMutex
	configFile      string
	configWatcher   *ConfigWatcher
	stagingPrefixes *iradix.Tree
	stagingIPs      map[string]interface{}
}

func (plugin *PluginBlockIP) Name() string {
	return "block_ip"
}

func (plugin *PluginBlockIP) Description() string {
	return "Block responses containing specific IP addresses"
}

func (plugin *PluginBlockIP) Init(proxy *Proxy) error {
	plugin.configFile = proxy.blockIPFile
	dlog.Noticef("Loading the set of IP blocking rules from [%s]", plugin.configFile)

	lines, err := ReadTextFile(plugin.configFile)
	if err != nil {
		return err
	}

	plugin.blockedPrefixes = iradix.New()
	plugin.blockedIPs = make(map[string]interface{})

	plugin.blockedPrefixes, err = plugin.loadRules(lines, plugin.blockedPrefixes, plugin.blockedIPs)
	if err != nil {
		return err
	}

	if len(proxy.blockIPLogFile) > 0 {
		plugin.logger = Logger(proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups, proxy.blockIPLogFile)
		plugin.format = proxy.blockIPFormat
	}

	return nil
}

// loadRules parses and loads IP rules into the provided tree and map
func (plugin *PluginBlockIP) loadRules(lines string, prefixes *iradix.Tree, ips map[string]interface{}) (*iradix.Tree, error) {
	for lineNo, line := range strings.Split(lines, "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}

		ip := net.ParseIP(line)
		trailingStar := strings.HasSuffix(line, "*")
		if len(line) < 2 || (ip != nil && trailingStar) {
			dlog.Errorf("Suspicious IP blocking rule [%s] at line %d", line, lineNo)
			continue
		}

		if trailingStar {
			line = line[:len(line)-1]
		}
		if strings.HasSuffix(line, ":") || strings.HasSuffix(line, ".") {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			dlog.Errorf("Empty IP blocking rule at line %d", lineNo)
			continue
		}
		if strings.Contains(line, "*") {
			dlog.Errorf("Invalid rule: [%s] - wildcards can only be used as a suffix at line %d", line, lineNo)
			continue
		}

		line = strings.ToLower(line)
		if trailingStar {
			prefixes, _, _ = prefixes.Insert([]byte(line), 0)
		} else {
			ips[line] = true
		}
	}

	return prefixes, nil
}

func (plugin *PluginBlockIP) Drop() error {
	if plugin.configWatcher != nil {
		plugin.configWatcher.RemoveFile(plugin.configFile)
	}
	return nil
}

// PrepareReload loads new rules into staging structures but doesn't apply them yet
func (plugin *PluginBlockIP) PrepareReload() error {
	// Read the configuration file
	lines, err := SafeReadTextFile(plugin.configFile)
	if err != nil {
		return fmt.Errorf("error reading config file during reload preparation: %w", err)
	}

	// Create staging structures
	plugin.stagingPrefixes = iradix.New()
	plugin.stagingIPs = make(map[string]interface{})

	// Load rules into staging structures
	plugin.stagingPrefixes, err = plugin.loadRules(lines, plugin.stagingPrefixes, plugin.stagingIPs)
	if err != nil {
		return fmt.Errorf("error parsing config during reload preparation: %w", err)
	}

	return nil
}

// ApplyReload atomically replaces the active rules with the staging ones
func (plugin *PluginBlockIP) ApplyReload() error {
	if plugin.stagingPrefixes == nil || plugin.stagingIPs == nil {
		return errors.New("no staged configuration to apply")
	}

	// Use write lock to swap rule structures
	plugin.rwLock.Lock()
	plugin.blockedPrefixes = plugin.stagingPrefixes
	plugin.blockedIPs = plugin.stagingIPs
	plugin.stagingPrefixes = nil
	plugin.stagingIPs = nil
	plugin.rwLock.Unlock()

	dlog.Noticef("Applied new configuration for plugin [%s]", plugin.Name())
	return nil
}

// CancelReload cleans up any staging resources
func (plugin *PluginBlockIP) CancelReload() {
	plugin.stagingPrefixes = nil
	plugin.stagingIPs = nil
}

// Reload implements hot-reloading for the plugin
func (plugin *PluginBlockIP) Reload() error {
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
func (plugin *PluginBlockIP) GetConfigPath() string {
	return plugin.configFile
}

// SetConfigWatcher sets the config watcher for this plugin
func (plugin *PluginBlockIP) SetConfigWatcher(watcher *ConfigWatcher) {
	plugin.configWatcher = watcher
}

func (plugin *PluginBlockIP) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if pluginsState.sessionData["whitelisted"] != nil {
		return nil
	}

	answers := msg.Answer
	if len(answers) == 0 {
		return nil
	}

	reject, reason, ipStr := false, "", ""

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
		if _, found := plugin.blockedIPs[ipStr]; found {
			reject, reason = true, ipStr
			break
		}
		match, _, found := plugin.blockedPrefixes.Root().LongestPrefix([]byte(ipStr))
		if found {
			if len(match) == len(ipStr) || (ipStr[len(match)] == '.' || ipStr[len(match)] == ':') {
				reject, reason = true, string(match)+"*"
				break
			}
		}
	}

	if reject {
		pluginsState.action = PluginsActionReject
		pluginsState.returnCode = PluginsReturnCodeReject
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
