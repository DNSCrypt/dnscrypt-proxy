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

type BlockedNames struct {
	allWeeklyRanges *map[string]WeeklyRanges
	patternMatcher  *PatternMatcher
	logger          io.Writer
	format          string
}

const aliasesLimit = 8

var (
	// protects access to the blockedNames global variable
	blockedNamesLock sync.RWMutex
	blockedNames     *BlockedNames
)

func (blockedNames *BlockedNames) check(pluginsState *PluginsState, qName string, aliasFor *string) (bool, error) {
	reject, reason, xweeklyRanges := blockedNames.patternMatcher.Eval(qName)
	if aliasFor != nil {
		reason = reason + " (alias for [" + *aliasFor + "])"
	}
	var weeklyRanges *WeeklyRanges
	if xweeklyRanges != nil {
		weeklyRanges = xweeklyRanges.(*WeeklyRanges)
	}
	if reject {
		if weeklyRanges != nil && !weeklyRanges.Match() {
			reject = false
		}
	}
	if !reject {
		return false, nil
	}
	pluginsState.action = PluginsActionReject
	pluginsState.returnCode = PluginsReturnCodeReject
	if blockedNames.logger != nil {
		var clientIPStr string
		switch pluginsState.clientProto {
		case "udp":
			clientIPStr = (*pluginsState.clientAddr).(*net.UDPAddr).IP.String()
		case "tcp", "local_doh":
			clientIPStr = (*pluginsState.clientAddr).(*net.TCPAddr).IP.String()
		default:
			// Ignore internal flow.
			return false, nil
		}
		var line string
		if blockedNames.format == "tsv" {
			now := time.Now()
			year, month, day := now.Date()
			hour, minute, second := now.Clock()
			tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
			line = fmt.Sprintf("%s\t%s\t%s\t%s\n", tsStr, clientIPStr, StringQuote(qName), StringQuote(reason))
		} else if blockedNames.format == "ltsv" {
			line = fmt.Sprintf("time:%d\thost:%s\tqname:%s\tmessage:%s\n", time.Now().Unix(), clientIPStr, StringQuote(qName), StringQuote(reason))
		} else {
			dlog.Fatalf("Unexpected log format: [%s]", blockedNames.format)
		}
		if blockedNames.logger == nil {
			return false, errors.New("Log file not initialized")
		}
		_, _ = blockedNames.logger.Write([]byte(line))
	}
	return true, nil
}

// ---

type PluginBlockName struct {
	// Hot-reloading support
	configFile     string
	configWatcher  *ConfigWatcher
	stagingBlocked *BlockedNames
}

func (plugin *PluginBlockName) Name() string {
	return "block_name"
}

func (plugin *PluginBlockName) Description() string {
	return "Block DNS queries matching name patterns"
}

func (plugin *PluginBlockName) Init(proxy *Proxy) error {
	plugin.configFile = proxy.blockNameFile
	dlog.Noticef("Loading the set of blocking rules from [%s]", plugin.configFile)

	lines, err := ReadTextFile(plugin.configFile)
	if err != nil {
		return err
	}

	xBlockedNames := BlockedNames{
		allWeeklyRanges: proxy.allWeeklyRanges,
		patternMatcher:  NewPatternMatcher(),
	}

	if err := plugin.loadRules(lines, &xBlockedNames); err != nil {
		return err
	}

	if len(proxy.blockNameLogFile) > 0 {
		xBlockedNames.logger = Logger(proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups, proxy.blockNameLogFile)
		xBlockedNames.format = proxy.blockNameFormat
	}

	blockedNamesLock.Lock()
	blockedNames = &xBlockedNames
	blockedNamesLock.Unlock()

	return nil
}

// loadRules parses and loads name patterns into the BlockedNames
func (plugin *PluginBlockName) loadRules(lines string, blockedNamesObj *BlockedNames) error {
	for lineNo, line := range strings.Split(lines, "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}

		// Handle time-based restrictions with @timerange format
		parts := strings.Split(line, "@")
		timeRangeName := ""
		if len(parts) == 2 {
			line = strings.TrimSpace(parts[0])
			timeRangeName = strings.TrimSpace(parts[1])
		} else if len(parts) > 2 {
			dlog.Errorf("Syntax error in block rules at line %d -- Unexpected @ character", 1+lineNo)
			continue
		}

		// Look up the time range if specified
		var weeklyRanges *WeeklyRanges
		if len(timeRangeName) > 0 {
			weeklyRangesX, ok := (*blockedNamesObj.allWeeklyRanges)[timeRangeName]
			if !ok {
				dlog.Errorf("Time range [%s] not found at line %d", timeRangeName, 1+lineNo)
			} else {
				weeklyRanges = &weeklyRangesX
			}
		}
		if err := blockedNamesObj.patternMatcher.Add(line, weeklyRanges, lineNo+1); err != nil {
			dlog.Error(err)
			continue
		}
	}

	return nil
}

func (plugin *PluginBlockName) Drop() error {
	if plugin.configWatcher != nil {
		plugin.configWatcher.RemoveFile(plugin.configFile)
	}
	return nil
}

// PrepareReload loads new patterns into staging structure but doesn't apply them yet
func (plugin *PluginBlockName) PrepareReload() error {
	// Read the configuration file
	lines, err := SafeReadTextFile(plugin.configFile)
	if err != nil {
		return fmt.Errorf("error reading config file during reload preparation: %w", err)
	}

	// Get current BlockedNames to access allWeeklyRanges and log settings
	blockedNamesLock.RLock()
	currentBlockedNames := blockedNames
	blockedNamesLock.RUnlock()

	if currentBlockedNames == nil {
		return errors.New("no existing blocked names configuration to base reload on")
	}

	// Create staging structure
	plugin.stagingBlocked = &BlockedNames{
		allWeeklyRanges: currentBlockedNames.allWeeklyRanges,
		patternMatcher:  NewPatternMatcher(),
		logger:          currentBlockedNames.logger,
		format:          currentBlockedNames.format,
	}

	// Load rules into staging structure
	if err := plugin.loadRules(lines, plugin.stagingBlocked); err != nil {
		return fmt.Errorf("error parsing config during reload preparation: %w", err)
	}

	return nil
}

// ApplyReload atomically replaces the active rules with the staging ones
func (plugin *PluginBlockName) ApplyReload() error {
	if plugin.stagingBlocked == nil {
		return errors.New("no staged configuration to apply")
	}

	// Use write lock to swap rule structures
	blockedNamesLock.Lock()
	blockedNames = plugin.stagingBlocked
	blockedNamesLock.Unlock()

	plugin.stagingBlocked = nil

	dlog.Noticef("Applied new configuration for plugin [%s]", plugin.Name())
	return nil
}

// CancelReload cleans up any staging resources
func (plugin *PluginBlockName) CancelReload() {
	plugin.stagingBlocked = nil
}

// Reload implements hot-reloading for the plugin
func (plugin *PluginBlockName) Reload() error {
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
func (plugin *PluginBlockName) GetConfigPath() string {
	return plugin.configFile
}

// SetConfigWatcher sets the config watcher for this plugin
func (plugin *PluginBlockName) SetConfigWatcher(watcher *ConfigWatcher) {
	plugin.configWatcher = watcher
}

func (plugin *PluginBlockName) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if pluginsState.sessionData["whitelisted"] != nil {
		return nil
	}

	blockedNamesLock.RLock()
	localBlockedNames := blockedNames
	blockedNamesLock.RUnlock()

	if localBlockedNames == nil {
		return nil
	}

	_, err := localBlockedNames.check(pluginsState, pluginsState.qName, nil)
	return err
}

// ---

type PluginBlockNameResponse struct {
	// The response plugin doesn't need any special fields for hot-reloading
	// as it uses the shared blockedNames
}

func (plugin *PluginBlockNameResponse) Name() string {
	return "block_name"
}

func (plugin *PluginBlockNameResponse) Description() string {
	return "Block DNS responses matching name patterns"
}

func (plugin *PluginBlockNameResponse) Init(proxy *Proxy) error {
	return nil
}

func (plugin *PluginBlockNameResponse) Drop() error {
	return nil
}

func (plugin *PluginBlockNameResponse) Reload() error {
	// The response plugin doesn't need to reload anything itself
	// as it uses the shared blockedNames that is reloaded by PluginBlockName
	return nil
}

func (plugin *PluginBlockNameResponse) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if pluginsState.sessionData["whitelisted"] != nil {
		return nil
	}

	blockedNamesLock.RLock()
	localBlockedNames := blockedNames
	blockedNamesLock.RUnlock()

	if localBlockedNames == nil {
		return nil
	}

	aliasFor := pluginsState.qName
	aliasesLeft := aliasesLimit
	answers := msg.Answer
	for _, answer := range answers {
		header := answer.Header()
		if header.Class != dns.ClassINET {
			continue
		}
		var target string
		if header.Rrtype == dns.TypeCNAME {
			target = answer.(*dns.CNAME).Target
		} else if header.Rrtype == dns.TypeSVCB && answer.(*dns.SVCB).Priority == 0 {
			target = answer.(*dns.SVCB).Target
		} else if header.Rrtype == dns.TypeHTTPS && answer.(*dns.HTTPS).Priority == 0 {
			target = answer.(*dns.HTTPS).Target
		} else {
			continue
		}
		target, err := NormalizeQName(target)
		if err != nil {
			return err
		}
		if blocked, err := localBlockedNames.check(pluginsState, target, &aliasFor); blocked || err != nil {
			return err
		}
		aliasesLeft--
		if aliasesLeft == 0 {
			break
		}
	}
	return nil
}
