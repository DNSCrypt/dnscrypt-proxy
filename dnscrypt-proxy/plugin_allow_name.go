package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

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

		parts := strings.Split(line, "@")
		timeRangeName := ""
		if len(parts) == 2 {
			line = strings.TrimSpace(parts[0])
			timeRangeName = strings.TrimSpace(parts[1])
		} else if len(parts) > 2 {
			dlog.Errorf("Syntax error in allowed names at line %d -- Unexpected @ character", 1+lineNo)
			continue
		}

		var weeklyRanges *WeeklyRanges
		if len(timeRangeName) > 0 {
			weeklyRangesX, ok := (*plugin.allWeeklyRanges)[timeRangeName]
			if !ok {
				dlog.Errorf("Time range [%s] not found at line %d", timeRangeName, 1+lineNo)
			} else {
				weeklyRanges = &weeklyRangesX
			}
		}

		if err := patternMatcher.Add(line, weeklyRanges, lineNo+1); err != nil {
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
	// Read the configuration file
	lines, err := SafeReadTextFile(plugin.configFile)
	if err != nil {
		return fmt.Errorf("error reading config file during reload preparation: %w", err)
	}

	// Create a new pattern matcher for staged changes
	plugin.stagingMatcher = NewPatternMatcher()

	// Load patterns into the staging matcher
	if err := plugin.loadPatterns(lines, plugin.stagingMatcher); err != nil {
		return fmt.Errorf("error parsing config during reload preparation: %w", err)
	}

	return nil
}

// ApplyReload atomically replaces the active pattern matcher with the staging one
func (plugin *PluginAllowName) ApplyReload() error {
	if plugin.stagingMatcher == nil {
		return errors.New("no staged configuration to apply")
	}

	// Use write lock to swap pattern matchers
	plugin.rwLock.Lock()
	plugin.patternMatcher = plugin.stagingMatcher
	plugin.stagingMatcher = nil
	plugin.rwLock.Unlock()

	dlog.Noticef("Applied new configuration for plugin [%s]", plugin.Name())
	return nil
}

// CancelReload cleans up any staging resources
func (plugin *PluginAllowName) CancelReload() {
	plugin.stagingMatcher = nil
}

// Reload implements hot-reloading for the plugin
func (plugin *PluginAllowName) Reload() error {
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
				line = fmt.Sprintf("%s\t%s\t%s\t%s\n", tsStr, clientIPStr, StringQuote(qName), StringQuote(reason))
			} else if plugin.format == "ltsv" {
				line = fmt.Sprintf("time:%d\thost:%s\tqname:%s\tmessage:%s\n", time.Now().Unix(), clientIPStr, StringQuote(qName), StringQuote(reason))
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
