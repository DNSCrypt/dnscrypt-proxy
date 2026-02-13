package main

import (
	"errors"
	"io"
	"sync"

	"codeberg.org/miekg/dns"
	iradix "github.com/hashicorp/go-immutable-radix"
	"github.com/jedisct1/dlog"
)

type PluginBlockIP struct {
	blockedPrefixes *iradix.Tree
	blockedIPs      map[string]any
	logger          io.Writer
	format          string
	ipCryptConfig   *IPCryptConfig

	// Hot-reloading support
	rwLock          sync.RWMutex
	configFile      string
	configWatcher   *ConfigWatcher
	stagingPrefixes *iradix.Tree
	stagingIPs      map[string]any
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
	plugin.blockedIPs = make(map[string]any)

	plugin.blockedPrefixes, err = plugin.loadRules(lines, plugin.blockedPrefixes, plugin.blockedIPs)
	if err != nil {
		return err
	}

	plugin.logger, plugin.format = InitializePluginLogger(proxy.blockIPLogFile, proxy.blockIPFormat, proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups)
	plugin.ipCryptConfig = proxy.ipCryptConfig

	return nil
}

// loadRules parses and loads IP rules into the provided tree and map
func (plugin *PluginBlockIP) loadRules(lines string, prefixes *iradix.Tree, ips map[string]any) (*iradix.Tree, error) {
	return LoadIPRules(lines, prefixes, ips)
}

func (plugin *PluginBlockIP) Drop() error {
	if plugin.configWatcher != nil {
		plugin.configWatcher.RemoveFile(plugin.configFile)
	}
	return nil
}

// PrepareReload loads new rules into staging structures but doesn't apply them yet
func (plugin *PluginBlockIP) PrepareReload() error {
	return StandardPrepareReloadPattern(plugin.Name(), plugin.configFile, func(lines string) error {
		// Create staging structures
		plugin.stagingPrefixes = iradix.New()
		plugin.stagingIPs = make(map[string]any)

		// Load rules into staging structures
		var err error
		plugin.stagingPrefixes, err = plugin.loadRules(lines, plugin.stagingPrefixes, plugin.stagingIPs)
		return err
	})
}

// ApplyReload atomically replaces the active rules with the staging ones
func (plugin *PluginBlockIP) ApplyReload() error {
	return StandardApplyReloadPattern(plugin.Name(), func() error {
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

		return nil
	})
}

// CancelReload cleans up any staging resources
func (plugin *PluginBlockIP) CancelReload() {
	plugin.stagingPrefixes = nil
	plugin.stagingIPs = nil
}

// Reload implements hot-reloading for the plugin
func (plugin *PluginBlockIP) Reload() error {
	return StandardReloadPattern(plugin.Name(), func() error {
		// Prepare the new configuration
		if err := plugin.PrepareReload(); err != nil {
			plugin.CancelReload()
			return err
		}

		// Apply the new configuration
		return plugin.ApplyReload()
	})
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
		rrtype := dns.RRToType(answer)
		if header.Class != dns.ClassINET || (rrtype != dns.TypeA && rrtype != dns.TypeAAAA) {
			continue
		}
		if rrtype == dns.TypeA {
			ipStr = answer.(*dns.A).A.Addr.String()
		} else if rrtype == dns.TypeAAAA {
			ipStr = answer.(*dns.AAAA).AAAA.Addr.String() // IPv4-mapped IPv6 addresses are converted to IPv4
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
			clientIPStr, ok := ExtractClientIPStrEncrypted(pluginsState, plugin.ipCryptConfig)
			if !ok {
				// Ignore internal flow.
				return nil
			}

			if err := WritePluginLog(plugin.logger, plugin.format, clientIPStr, qName, reason, ipStr); err != nil {
				return err
			}
		}
	}
	return nil
}
