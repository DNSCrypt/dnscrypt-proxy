package main

import (
	"errors"
	"fmt"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"gopkg.in/natefinch/lumberjack.v2"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type ResourceRecordFilter struct {
	patternMatcher *PatternMatcher
	logger         *lumberjack.Logger
	format         string
}

func (resourceRecordFilter *ResourceRecordFilter) ShouldBlock(name string, dnsClass uint16, dnsType uint16) (bool, error) {
	if dnsClass != dns.ClassINET {
		return false, nil
	}

	qName := strings.ToLower(StripTrailingDot(name))
	_, _, xBannedRecordTypes := resourceRecordFilter.patternMatcher.Eval(qName)
	bannedRecordTypes := xBannedRecordTypes.(*[]uint16)

	banned := false
	for _, bannedRecordType := range *bannedRecordTypes {
		if bannedRecordType == dnsType {
			banned = true
			var line string
			if resourceRecordFilter.format == "tsv" {
				now := time.Now()
				year, month, day := now.Date()
				hour, minute, second := now.Clock()
				tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
				line = fmt.Sprintf("%s\t%s\t%d\n", tsStr, StringQuote(qName), dnsType)
			} else if resourceRecordFilter.format == "ltsv" {
				line = fmt.Sprintf("time:%d\thost:%s\tdnsType:%d\n", time.Now().Unix(), StringQuote(qName), dnsType)
			} else {
				dlog.Fatalf("Unexpected log format: [%s]", resourceRecordFilter.format)
			}
			if resourceRecordFilter.logger == nil {
				return false, errors.New("log file not initialized")
			}

			_, err := resourceRecordFilter.logger.Write([]byte(line))
			if err != nil {
				return false, err
			}

			break
		}
	}

	return banned, nil
}

var resourceRecordFilter *ResourceRecordFilter

type PluginBlockResourceRecordsQueries struct{}

func (plugin *PluginBlockResourceRecordsQueries) Name() string {
	return "block_record_queries"
}

func (plugin *PluginBlockResourceRecordsQueries) Description() string {
	return "Immediately return a synthetic response to filtered DNS record type queries."
}

func (plugin *PluginBlockResourceRecordsQueries) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of blocked resource record types from [%s]", proxy.resourceRecordFiltersFile)
	bin, err := ReadTextFile(proxy.resourceRecordFiltersFile)
	if err != nil {
		return err
	}

	tempQueryBlackList := ResourceRecordFilter{
		patternMatcher: NewPatternPatcher(),
	}

	bannedResourceRecords := make(map[string]*[]uint16)

	for lineNo, line := range strings.Split(bin, "\n") {
		line = strings.TrimFunc(line, unicode.IsSpace)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		var blocklist string
		parts := strings.FieldsFunc(line, unicode.IsSpace)
		if len(parts) == 2 {
			line = strings.TrimFunc(parts[0], unicode.IsSpace)
			blocklist = strings.TrimFunc(parts[1], unicode.IsSpace)
		} else if len(parts) > 2 {
			dlog.Errorf("Syntax error in resource records filter rules at line %d -- Unexpected space character", 1+lineNo)
			continue
		}
		if len(line) == 0 || len(blocklist) == 0 {
			dlog.Errorf("Syntax error in resource records filter rules at line %d -- Missing name or blocked query types", 1+lineNo)
			continue
		}
		line = strings.ToLower(line)
		bannedResourceRecord, found := bannedResourceRecords[line]
		if !found {
			xBannedResourceRecord := make([]uint16, 0)
			bannedResourceRecord = &xBannedResourceRecord
		}

		isValidSeparator := func(char rune) bool {
			return char == ','
		}

		dnsTypes := strings.FieldsFunc(blocklist, isValidSeparator)

		for _, dnsTypeStr := range dnsTypes {
			value, err := strconv.ParseUint(dnsTypeStr, 10, 16)
			if err != nil {
				return err
			}

			*bannedResourceRecord = append(*bannedResourceRecord, uint16(value))
		}

		bannedResourceRecords[line] = bannedResourceRecord
	}

	i := 1
	for line, bannedResourceRecord := range bannedResourceRecords {
		err := tempQueryBlackList.patternMatcher.Add(line, bannedResourceRecord, i)
		if err != nil {
			dlog.Errorf("Error processing resource records filter rule %d", i)
			return err
		}

		i++
	}

	if len(proxy.blockNameLogFile) != 0 {
		tempQueryBlackList.logger = &lumberjack.Logger{LocalTime: true, MaxSize: proxy.logMaxSize, MaxAge: proxy.logMaxAge, MaxBackups: proxy.logMaxBackups, Filename: proxy.resourceRecordFiltersLogFile, Compress: true}
		tempQueryBlackList.format = proxy.resourceRecordFiltersFormat
	}

	resourceRecordFilter = &tempQueryBlackList

	return nil
}

func (plugin *PluginBlockResourceRecordsQueries) Drop() error {
	return nil
}

func (plugin *PluginBlockResourceRecordsQueries) Reload() error {
	return nil
}

func (plugin *PluginBlockResourceRecordsQueries) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	question := questions[0]
	block, err := resourceRecordFilter.ShouldBlock(question.Name, question.Qclass, question.Qtype)
	if err != nil {
		return err
	}

	if block {
		pluginsState.action = PluginsActionReject
		pluginsState.returnCode = PluginsReturnCodeReject
	}

	return nil
}

type PluginFilterResourceRecordsResponses struct
{

}

func (plugin *PluginFilterResourceRecordsResponses) Name() string {
	return "block_query_responses"
}

func (plugin *PluginFilterResourceRecordsResponses) Description() string {
	return "Filters responses for blocked DNS query types."
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
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	question := questions[0]

	filterResponseSection := func(src *[]dns.RR) error {
		i := 0
		for _, answer := range *src {
			header := answer.Header()
			block, err := resourceRecordFilter.ShouldBlock(question.Name, header.Class, header.Rrtype)
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

	if len(msg.Answer) < 1 && len(msg.Extra) < 1 {
		pluginsState.action = PluginsActionReject
		pluginsState.returnCode = PluginsReturnCodeReject
	}

	return nil
}
