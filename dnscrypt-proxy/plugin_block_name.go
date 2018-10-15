package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type PluginBlockName struct {
	allWeeklyRanges *map[string]WeeklyRanges
	patternMatcher  *PatternMatcher
	logger          *lumberjack.Logger
	format          string
}

func (plugin *PluginBlockName) Name() string {
	return "block_name"
}

func (plugin *PluginBlockName) Description() string {
	return "Block DNS queries matching name patterns"
}

func (plugin *PluginBlockName) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of blocking rules from [%s]", proxy.blockNameFile)
	bin, err := ReadTextFile(proxy.blockNameFile)
	if err != nil {
		return err
	}
	plugin.allWeeklyRanges = proxy.allWeeklyRanges
	plugin.patternMatcher = NewPatternPatcher()
	for lineNo, line := range strings.Split(string(bin), "\n") {
		line = strings.TrimFunc(line, unicode.IsSpace)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "@")
		timeRangeName := ""
		if len(parts) == 2 {
			line = strings.TrimFunc(parts[0], unicode.IsSpace)
			timeRangeName = strings.TrimFunc(parts[1], unicode.IsSpace)
		} else if len(parts) > 2 {
			dlog.Errorf("Syntax error in block rules at line %d -- Unexpected @ character", 1+lineNo)
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
		if _, err := plugin.patternMatcher.Add(line, weeklyRanges, lineNo+1); err != nil {
			dlog.Error(err)
			continue
		}
	}
	if len(proxy.blockNameLogFile) == 0 {
		return nil
	}
	plugin.logger = &lumberjack.Logger{LocalTime: true, MaxSize: proxy.logMaxSize, MaxAge: proxy.logMaxAge, MaxBackups: proxy.logMaxBackups, Filename: proxy.blockNameLogFile, Compress: true}
	plugin.format = proxy.blockNameFormat

	return nil
}

func (plugin *PluginBlockName) Drop() error {
	return nil
}

func (plugin *PluginBlockName) Reload() error {
	return nil
}

func (plugin *PluginBlockName) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if pluginsState.sessionData["whitelisted"] != nil {
		return nil
	}
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	qName := strings.ToLower(StripTrailingDot(questions[0].Name))
	reject, reason, xweeklyRanges := plugin.patternMatcher.Eval(qName)
	var weeklyRanges *WeeklyRanges
	if xweeklyRanges != nil {
		weeklyRanges = xweeklyRanges.(*WeeklyRanges)
	}
	if reject {
		if weeklyRanges != nil && !weeklyRanges.Match() {
			reject = false
		}
	}
	if reject {
		pluginsState.action = PluginsActionReject
		pluginsState.returnCode = PluginsReturnCodeReject
		if plugin.logger != nil {
			var clientIPStr string
			if pluginsState.clientProto == "udp" {
				clientIPStr = (*pluginsState.clientAddr).(*net.UDPAddr).IP.String()
			} else {
				clientIPStr = (*pluginsState.clientAddr).(*net.TCPAddr).IP.String()
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
			plugin.logger.Write([]byte(line))
		}
	}
	return nil
}
