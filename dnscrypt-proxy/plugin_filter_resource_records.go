package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type FilterExpression struct {
	weeklyRanges *WeeklyRanges
	recordTypes  *[]uint16
}

type ResourceRecordFilter struct {
	allWeeklyRanges *map[string]WeeklyRanges
	patternMatcher  *PatternMatcher
	logger          *lumberjack.Logger
	format          string
}

func (resourceRecordFilter *ResourceRecordFilter) check(pluginsState *PluginsState, qName string, dnsType uint16, aliasFor *string) (bool, error) {
	reject, reason, xFilterExpression := resourceRecordFilter.patternMatcher.Eval(qName)
	if aliasFor != nil {
		reason = reason + " (alias for [" + *aliasFor + "])"
	}
	var filterExpression *FilterExpression
	if xFilterExpression != nil {
		filterExpression = xFilterExpression.(*FilterExpression)
	} else {
		return false, nil
	}
	if reject {
		if filterExpression.weeklyRanges != nil && !filterExpression.weeklyRanges.Match() {
			reject = false
		}
		if len(*filterExpression.recordTypes) != 0 {
			found := false
			for _, bannedRecordType := range *filterExpression.recordTypes {
				if bannedRecordType == dnsType {
					found = true
					break
				}
			}
			if !found {
				reject = false
			}
		}
	}
	if !reject {
		return false, nil
	}
	if resourceRecordFilter.logger != nil {
		var clientIPStr string
		if pluginsState.clientProto == "udp" {
			clientIPStr = (*pluginsState.clientAddr).(*net.UDPAddr).IP.String()
		} else {
			clientIPStr = (*pluginsState.clientAddr).(*net.TCPAddr).IP.String()
		}
		var line string
		if resourceRecordFilter.format == "tsv" {
			now := time.Now()
			year, month, day := now.Date()
			hour, minute, second := now.Clock()
			tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
			line = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", tsStr, clientIPStr, StringQuote(qName), StringQuote(strconv.FormatUint(uint64(dnsType), 10)), StringQuote(reason))
		} else if resourceRecordFilter.format == "ltsv" {
			line = fmt.Sprintf("time:%d\thost:%s\tqname:%s\trecordType:%s\tmessage:%s\n", time.Now().Unix(), clientIPStr, StringQuote(qName), StringQuote(strconv.FormatUint(uint64(dnsType), 10)), StringQuote(reason))
		} else {
			dlog.Fatalf("Unexpected log format: [%s]", resourceRecordFilter.format)
		}
		if resourceRecordFilter.logger == nil {
			return false, errors.New("Log file not initialized")
		}
		_, _ = resourceRecordFilter.logger.Write([]byte(line))
	}

	return true, nil
}

var resourceRecordFilter *ResourceRecordFilter

type PluginBlockResourceRecordsQueries struct{
}

func (plugin *PluginBlockResourceRecordsQueries) Name() string {
	return "block_record_queries"
}

func (plugin *PluginBlockResourceRecordsQueries) Description() string {
	return "Immediately return a synthetic response to filtered DNS resource record types queries."
}

func (plugin *PluginBlockResourceRecordsQueries) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of blocked resource record types from [%s]", proxy.resourceRecordFiltersFile)
	bin, err := ReadTextFile(proxy.resourceRecordFiltersFile)
	if err != nil {
		return err
	}
	xQueryBlackList := ResourceRecordFilter{
		allWeeklyRanges: proxy.allWeeklyRanges,
		patternMatcher: NewPatternPatcher(),
	}
	for lineNo, line := range strings.Split(bin, "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		parts := strings.Split(line, "@")
		timeRangeName := ""
		blockedRecordTypes := ""
		if len(parts) == 2 {
			line = strings.TrimFunc(parts[0], unicode.IsSpace)
			timeRangeName = strings.TrimFunc(parts[1], unicode.IsSpace)
		} else if len(parts) > 2 {
			dlog.Errorf("Syntax error in block rules at line %d -- Unexpected @ character", 1+lineNo)
			continue
		}
		parts = strings.Split(line, " ")
		if len(parts) == 2 {
			line = strings.TrimFunc(parts[0], unicode.IsSpace)
			blockedRecordTypes = strings.TrimFunc(parts[1], unicode.IsSpace)
		} else if len(parts) > 2 {
			dlog.Errorf("Syntax error in resource records filter rules at line %d -- Unexpected space character", 1+lineNo)
			continue
		}
		if len(line) == 0 {
			dlog.Errorf("Syntax error in resource records filter rules at line %d -- Missing name or blocked query types", 1+lineNo)
			continue
		}
		var weeklyRanges *WeeklyRanges
		if len(timeRangeName) > 0 {
			weeklyRangesX, ok := (*xQueryBlackList.allWeeklyRanges)[timeRangeName]
			if !ok {
				dlog.Errorf("Time range [%s] not found at line %d", timeRangeName, 1+lineNo)
			} else {
				weeklyRanges = &weeklyRangesX
			}
		}
		xBannedResourceRecords := make([]uint16, 0)
		bannedResourceRecords := &xBannedResourceRecords
		if len(blockedRecordTypes) != 0 {
			dnsTypes := strings.Split(blockedRecordTypes, ",")
			for _, dnsTypeStr := range dnsTypes {
				value, err := strconv.ParseUint(dnsTypeStr, 10, 16)
				if err != nil {
					dlog.Errorf("Failed to parse DNS resource record type %s at line %d", dnsTypeStr, 1+lineNo)
					return err
				}
				*bannedResourceRecords = append(*bannedResourceRecords, uint16(value))
			}
		}
		filterExpression := FilterExpression{
			weeklyRanges: weeklyRanges,
			recordTypes: bannedResourceRecords,
		}
		if err := xQueryBlackList.patternMatcher.Add(line, &filterExpression, lineNo+1); err != nil {
			dlog.Error(err)
			continue
		}
	}
	if len(proxy.resourceRecordFiltersLogFile) != 0 {
		xQueryBlackList.logger = &lumberjack.Logger{LocalTime: true, MaxSize: proxy.logMaxSize, MaxAge: proxy.logMaxAge, MaxBackups: proxy.logMaxBackups, Filename: proxy.resourceRecordFiltersLogFile, Compress: true}
		xQueryBlackList.format = proxy.resourceRecordFiltersFormat
	}
	resourceRecordFilter = &xQueryBlackList

	return nil
}

func (plugin *PluginBlockResourceRecordsQueries) Drop() error {
	return nil
}

func (plugin *PluginBlockResourceRecordsQueries) Reload() error {
	return nil
}

func (plugin *PluginBlockResourceRecordsQueries) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if resourceRecordFilter == nil {
		return nil
	}
	block, err := resourceRecordFilter.check(pluginsState, pluginsState.qName, msg.Question[0].Qtype, nil)
	if err != nil {
		return err
	}
	if block {
		pluginsState.action = PluginsActionReject
		pluginsState.returnCode = PluginsReturnCodeReject
	}
	return nil
}

type PluginFilterResourceRecordsResponses struct {
}

func (plugin *PluginFilterResourceRecordsResponses) Name() string {
	return "block_query_responses"
}

func (plugin *PluginFilterResourceRecordsResponses) Description() string {
	return "Filters blocked resource record types from DNS responses."
}

func (plugin *PluginFilterResourceRecordsResponses) Init(proxy *Proxy) error {
	return nil
}

func (plugin *PluginFilterResourceRecordsResponses) Drop() error {
	return nil
}

func (plugin *PluginFilterResourceRecordsResponses) Reload() error {
	return nil
}

func (plugin *PluginFilterResourceRecordsResponses) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if resourceRecordFilter == nil {
		return nil
	}
	filterResponseSection := func(src *[]dns.RR) error {
		i := 0
		for _, answer := range *src {
			qName := pluginsState.qName
			header := answer.Header()
			if header.Class != dns.ClassINET {
				continue
			}
			if header.Rrtype == dns.TypeCNAME {
				target, err := NormalizeQName(answer.(*dns.CNAME).Target)
				if err != nil {
					return err
				}
				qName = target
			}
			block, err := resourceRecordFilter.check(pluginsState, qName, header.Rrtype, &pluginsState.qName)
			if err != nil {
				return err
			}
			if !block {
				(*src)[i] = answer
				i++
			}
		}
		*src = (*src)[:i]

		return nil
	}
	err := filterResponseSection(&msg.Answer)
	if err != nil {
		return err
	}
	err = filterResponseSection(&msg.Extra)
	if err != nil {
		return err
	}
	if len(msg.Answer) < 1 {
		pluginsState.action = PluginsActionReject
		pluginsState.returnCode = PluginsReturnCodeReject
	}

	return nil
}
