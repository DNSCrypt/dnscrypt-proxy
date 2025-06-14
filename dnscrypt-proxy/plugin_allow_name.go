package main

import (
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginAllowName struct {
	allWeeklyRanges *map[string]WeeklyRanges
	patternMatcher  *PatternMatcher
	logger          io.Writer
	format          string

	// Hot-reloading support
	rwLock         sync.RWMutex
	configFile     string
	configWatcher  *ConfigWatcher
	stagingMatcher *PatternMatcher // Used during reload
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
	plugin.patternMatcher = NewPatternMatcher()

	if err := plugin.loadPatterns(lines, plugin.patternMatcher); err != nil {
		return err
	}

	if len(proxy.allowNameLogFile) > 0 {
		plugin.logger = Logger(proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups, proxy.allowNameLogFile)
		plugin.format = proxy.allowNameFormat
	}

	return nil
}

// loadPatterns parses and loads patterns into the provided pattern matcher
func (plugin *PluginAllowName) loadPatterns(lines string, patternMatcher *PatternMatcher) error {
	for lineNo, line := range strings.Split(lines, "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}

		rulePart, weeklyRanges, err := ParseTimeBasedRule(line, lineNo, plugin.allWeeklyRanges)
		if err != nil {
			dlog.Error(err)
			continue
		}

		if err := patternMatcher.Add(rulePart, weeklyRanges, lineNo+1); err != nil {
			dlog.Error(err)
			continue
		}
	}

	return nil
}

func (plugin *PluginAllowName) Drop() error {
	if plugin.configWatcher != nil {
		plugin.configWatcher.RemoveFile(plugin.configFile)
	}
	return nil
}

// PrepareReload loads new patterns into the staging matcher but doesn't apply them yet
func (plugin *PluginAllowName) PrepareReload() error {
	return StandardPrepareReloadPattern(plugin.Name(), plugin.configFile, func(lines string) error {
		// Create a new pattern matcher for staged changes
		plugin.stagingMatcher = NewPatternMatcher()

		// Load patterns into the staging matcher
		return plugin.loadPatterns(lines, plugin.stagingMatcher)
	})
}

// ApplyReload atomically replaces the active pattern matcher with the staging one
func (plugin *PluginAllowName) ApplyReload() error {
	return StandardApplyReloadPattern(plugin.Name(), func() error {
		if plugin.stagingMatcher == nil {
			return errors.New("no staged configuration to apply")
		}

		// Use write lock to swap pattern matchers
		plugin.rwLock.Lock()
		plugin.patternMatcher = plugin.stagingMatcher
		plugin.stagingMatcher = nil
		plugin.rwLock.Unlock()

		return nil
	})
}

// CancelReload cleans up any staging resources
func (plugin *PluginAllowName) CancelReload() {
	plugin.stagingMatcher = nil
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

	// Use read lock for thread-safe access to patternMatcher
	plugin.rwLock.RLock()
	allowList, reason, xweeklyRanges := plugin.patternMatcher.Eval(qName)
	plugin.rwLock.RUnlock()

	var weeklyRanges *WeeklyRanges
	if xweeklyRanges != nil {
		weeklyRanges = xweeklyRanges.(*WeeklyRanges)
	}

	// If time-based restrictions exist and don't match current time, don't allow
	if allowList && weeklyRanges != nil && !weeklyRanges.Match() {
		allowList = false
	}

	if allowList {
		pluginsState.sessionData["whitelisted"] = true
		if plugin.logger != nil {
			clientIPStr, ok := ExtractClientIPStr(pluginsState)
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
