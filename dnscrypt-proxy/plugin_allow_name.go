package main

import (
	"errors"
	"io"
	"sync"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
)

type PluginAllowName struct {
	allWeeklyRanges *map[string]WeeklyRanges
	nameList        *NameList
	logger          io.Writer
	format          string
	ipCryptConfig   *IPCryptConfig

	// Hot-reloading support
	rwLock          sync.RWMutex
	configFile      string
	configWatcher   *ConfigWatcher
	stagingNameList *NameList // Used during reload
}

func (plugin *PluginAllowName) Name() string {
	return "allow_name"
}

func (plugin *PluginAllowName) Description() string {
	return "Allow names matching patterns"
}

func (plugin *PluginAllowName) Init(proxy *Proxy) error {
	plugin.configFile = proxy.allowNameFile
	dlog.Noticef("Loading the set of allowed names from [%s]", plugin.configFile)

	lines, err := ReadTextFile(plugin.configFile)
	if err != nil {
		return err
	}

	plugin.allWeeklyRanges = proxy.allWeeklyRanges

	nameList, err := LoadNameList(plugin.configFile, lines, plugin.allWeeklyRanges)
	if err != nil {
		return err
	}
	plugin.nameList = nameList

	plugin.logger, plugin.format = InitializePluginLogger(proxy.allowNameLogFile, proxy.allowNameFormat, proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups)
	plugin.ipCryptConfig = proxy.ipCryptConfig

	return nil
}

func (plugin *PluginAllowName) Drop() error {
	if plugin.configWatcher != nil {
		plugin.configWatcher.RemoveFile(plugin.configFile)
	}
	return nil
}

// PrepareReload loads new patterns into the staging list but doesn't apply them yet
func (plugin *PluginAllowName) PrepareReload() error {
	plugin.stagingNameList = nil
	return StandardPrepareReloadPattern(plugin.Name(), plugin.configFile, func(lines string) error {
		var err error
		plugin.stagingNameList, err = LoadNameList(plugin.configFile, lines, plugin.allWeeklyRanges)
		return err
	})
}

// ApplyReload atomically replaces the active name list with the staging one
func (plugin *PluginAllowName) ApplyReload() error {
	return StandardApplyReloadPattern(plugin.Name(), func() error {
		if plugin.stagingNameList == nil {
			return errors.New("no staged configuration to apply")
		}

		// Use write lock to swap name lists
		plugin.rwLock.Lock()
		plugin.nameList = plugin.stagingNameList
		plugin.stagingNameList = nil
		plugin.rwLock.Unlock()

		return nil
	})
}

// CancelReload cleans up any staging resources
func (plugin *PluginAllowName) CancelReload() {
	plugin.stagingNameList = nil
}

// Reload implements hot-reloading for the plugin
func (plugin *PluginAllowName) Reload() error {
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
func (plugin *PluginAllowName) GetConfigPath() string {
	return plugin.configFile
}

// SetConfigWatcher sets the config watcher for this plugin
func (plugin *PluginAllowName) SetConfigWatcher(watcher *ConfigWatcher) {
	plugin.configWatcher = watcher
}

func (plugin *PluginAllowName) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	qName := pluginsState.qName

	// Use read lock for thread-safe access to nameList
	plugin.rwLock.RLock()
	nameList := plugin.nameList
	plugin.rwLock.RUnlock()

	allowList, reason, err := nameList.Eval(qName)
	if err != nil {
		return err
	}

	if allowList {
		pluginsState.sessionData["whitelisted"] = true
		if plugin.logger != nil {
			clientIPStr, ok := ExtractClientIPStrEncrypted(pluginsState, plugin.ipCryptConfig)
			if !ok {
				// Ignore internal flow.
				return nil
			}

			if err := WritePluginLog(plugin.logger, plugin.format, clientIPStr, qName, reason); err != nil {
				return err
			}
		}
	}
	return nil
}
