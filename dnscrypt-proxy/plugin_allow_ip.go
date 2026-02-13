package main

import (
	"errors"
	"io"
	"sync"

	"codeberg.org/miekg/dns"
	iradix "github.com/hashicorp/go-immutable-radix"
	"github.com/jedisct1/dlog"
)

type PluginAllowedIP struct {
	allowedPrefixes *iradix.Tree
	allowedIPs      map[string]any
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
	plugin.allowedIPs = make(map[string]any)

	plugin.allowedPrefixes, err = plugin.loadRules(lines, plugin.allowedPrefixes, plugin.allowedIPs)
	if err != nil {
		return err
	}

	plugin.logger, plugin.format = InitializePluginLogger(proxy.allowedIPLogFile, proxy.allowedIPFormat, proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups)
	plugin.ipCryptConfig = proxy.ipCryptConfig

	return nil
}

// loadRules parses and loads IP rules into the provided tree and map
func (plugin *PluginAllowedIP) loadRules(lines string, prefixes *iradix.Tree, ips map[string]any) (*iradix.Tree, error) {
	return LoadIPRules(lines, prefixes, ips)
}

func (plugin *PluginAllowedIP) Drop() error {
	if plugin.configWatcher != nil {
		plugin.configWatcher.RemoveFile(plugin.configFile)
	}
	return nil
}

// PrepareReload loads new rules into staging structures but doesn't apply them yet
func (plugin *PluginAllowedIP) PrepareReload() error {
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
func (plugin *PluginAllowedIP) ApplyReload() error {
	return StandardApplyReloadPattern(plugin.Name(), func() error {
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

		return nil
	})
}

// CancelReload cleans up any staging resources
func (plugin *PluginAllowedIP) CancelReload() {
	plugin.stagingPrefixes = nil
	plugin.stagingIPs = nil
}

// Reload implements hot-reloading for the plugin
func (plugin *PluginAllowedIP) Reload() error {
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
		rrtype := dns.RRToType(answer)
		if header.Class != dns.ClassINET || (rrtype != dns.TypeA && rrtype != dns.TypeAAAA) {
			continue
		}
		if rrtype == dns.TypeA {
			ipStr = answer.(*dns.A).A.Addr.String()
		} else if rrtype == dns.TypeAAAA {
			ipStr = answer.(*dns.AAAA).AAAA.Addr.String() // IPv4-mapped IPv6 addresses are converted to IPv4
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
