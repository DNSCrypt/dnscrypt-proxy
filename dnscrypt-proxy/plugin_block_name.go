package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
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

type TimeRange struct {
	after  int
	before int
}

type WeeklyRanges struct {
	ranges [7][]TimeRange
}

type TimeRangeStr struct {
	After  string
	Before string
}

type WeeklyRangesStr struct {
	Sun, Mon, Tue, Wed, Thu, Fri, Sat []TimeRangeStr
}

func (plugin *PluginBlockName) Name() string {
	return "block_name"
}

func (plugin *PluginBlockName) Description() string {
	return "Block DNS queries matching name patterns"
}

func (plugin *PluginBlockName) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of blocking rules from [%s]", proxy.blockNameFile)
	bin, err := ioutil.ReadFile(proxy.blockNameFile)
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
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	qName := strings.ToLower(StripTrailingDot(questions[0].Name))
	reject, reason, xweeklyRanges := plugin.patternMatcher.Eval(qName)
	weeklyRanges := xweeklyRanges.(*WeeklyRanges)
	if reject {
		if weeklyRanges != nil && !weeklyRanges.Match() {
			reject = false
		}
	}
	if reject {
		pluginsState.action = PluginsActionReject
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

func daySecsFromStr(str string) (int, error) {
	parts := strings.Split(str, ":")
	if len(parts) != 2 {
		return -1, fmt.Errorf("Syntax error in a time expression: [%s]", str)
	}
	hours, err := strconv.Atoi(parts[0])
	if err != nil || hours < 0 || hours > 23 {
		return -1, fmt.Errorf("Syntax error in a time expression: [%s]", str)
	}
	minutes, err := strconv.Atoi(parts[1])
	if err != nil || minutes < 0 || minutes > 59 {
		return -1, fmt.Errorf("Syntax error in a time expression: [%s]", str)
	}
	return (hours*60 + minutes) * 60, nil
}

func parseTimeRanges(timeRangesStr []TimeRangeStr) ([]TimeRange, error) {
	timeRanges := []TimeRange{}
	for _, timeRangeStr := range timeRangesStr {
		after, err := daySecsFromStr(timeRangeStr.After)
		if err != nil {
			return timeRanges, err
		}
		before, err := daySecsFromStr(timeRangeStr.Before)
		if err != nil {
			return timeRanges, err
		}
		if after == before {
			after, before = -1, 86402
		}
		timeRanges = append(timeRanges, TimeRange{after: after, before: before})
	}
	return timeRanges, nil
}

func parseWeeklyRanges(weeklyRangesStr WeeklyRangesStr) (WeeklyRanges, error) {
	weeklyRanges := WeeklyRanges{}
	weeklyRangesStrX := [7][]TimeRangeStr{weeklyRangesStr.Sun, weeklyRangesStr.Mon, weeklyRangesStr.Tue, weeklyRangesStr.Wed, weeklyRangesStr.Thu, weeklyRangesStr.Fri, weeklyRangesStr.Sat}
	for day, weeklyRangeStrX := range weeklyRangesStrX {
		timeRanges, err := parseTimeRanges(weeklyRangeStrX)
		if err != nil {
			return weeklyRanges, err
		}
		weeklyRanges.ranges[day] = timeRanges
	}
	return weeklyRanges, nil
}

func ParseAllWeeklyRanges(allWeeklyRangesStr map[string]WeeklyRangesStr) (*map[string]WeeklyRanges, error) {
	allWeeklyRanges := make(map[string]WeeklyRanges)
	for weeklyRangesName, weeklyRangesStr := range allWeeklyRangesStr {
		weeklyRanges, err := parseWeeklyRanges(weeklyRangesStr)
		if err != nil {
			return nil, err
		}
		allWeeklyRanges[weeklyRangesName] = weeklyRanges
	}
	return &allWeeklyRanges, nil
}

func (weeklyRanges *WeeklyRanges) Match() bool {
	now := time.Now().Local()
	day := now.Weekday()
	weeklyRange := weeklyRanges.ranges[day]
	if len(weeklyRange) == 0 {
		return false
	}
	hour, min, _ := now.Clock()
	nowX := (hour*60 + min) * 60
	for _, timeRange := range weeklyRange {
		if timeRange.after > timeRange.before {
			if nowX >= timeRange.after || nowX <= timeRange.before {
				return true
			}
		} else if nowX >= timeRange.after && nowX <= timeRange.before {
			return true
		}
	}
	return false
}
