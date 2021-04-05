package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginAllowName struct {
	allWeeklyRanges *map[string]WeeklyRanges
	patternMatcher  *PatternMatcher
	logger          io.Writer
	format          string
}

func (plugin *PluginAllowName) Name() string {
	return "allow_name"
}

func (plugin *PluginAllowName) Description() string {
	return "Allow names matching patterns"
}

func (plugin *PluginAllowName) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of allowed names from [%s]", proxy.allowNameFile)
	bin, err := ReadTextFile(proxy.allowNameFile)
	if err != nil {
		return err
	}
	plugin.allWeeklyRanges = proxy.allWeeklyRanges
	plugin.patternMatcher = NewPatternMatcher()
	for lineNo, line := range strings.Split(string(bin), "\n") {
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
		if err := plugin.patternMatcher.Add(line, weeklyRanges, lineNo+1); err != nil {
			dlog.Error(err)
			continue
		}
	}
	if len(proxy.allowNameLogFile) == 0 {
		return nil
	}
	plugin.logger = Logger(proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups, proxy.allowNameLogFile)
	plugin.format = proxy.allowNameFormat

	return nil
}

func (plugin *PluginAllowName) Drop() error {
	return nil
}

func (plugin *PluginAllowName) Reload() error {
	return nil
}

func (plugin *PluginAllowName) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	qName := pluginsState.qName
	allowList, reason, xweeklyRanges := plugin.patternMatcher.Eval(qName)
	var weeklyRanges *WeeklyRanges
	if xweeklyRanges != nil {
		weeklyRanges = xweeklyRanges.(*WeeklyRanges)
	}
	if allowList {
		if weeklyRanges != nil && !weeklyRanges.Match() {
			allowList = false
		}
	}
	if allowList {
		pluginsState.sessionData["whitelisted"] = true
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
			_, _ = plugin.logger.Write([]byte(line))
		}
	}
	return nil
}
