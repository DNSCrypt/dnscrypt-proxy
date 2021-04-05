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

type BlockedNames struct {
	allWeeklyRanges *map[string]WeeklyRanges
	patternMatcher  *PatternMatcher
	logger          io.Writer
	format          string
}

const aliasesLimit = 8

var blockedNames *BlockedNames

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
		if pluginsState.clientProto == "udp" {
			clientIPStr = (*pluginsState.clientAddr).(*net.UDPAddr).IP.String()
		} else {
			clientIPStr = (*pluginsState.clientAddr).(*net.TCPAddr).IP.String()
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
	xBlockedNames := BlockedNames{
		allWeeklyRanges: proxy.allWeeklyRanges,
		patternMatcher:  NewPatternMatcher(),
	}
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
			dlog.Errorf("Syntax error in block rules at line %d -- Unexpected @ character", 1+lineNo)
			continue
		}
		var weeklyRanges *WeeklyRanges
		if len(timeRangeName) > 0 {
			weeklyRangesX, ok := (*xBlockedNames.allWeeklyRanges)[timeRangeName]
			if !ok {
				dlog.Errorf("Time range [%s] not found at line %d", timeRangeName, 1+lineNo)
			} else {
				weeklyRanges = &weeklyRangesX
			}
		}
		if err := xBlockedNames.patternMatcher.Add(line, weeklyRanges, lineNo+1); err != nil {
			dlog.Error(err)
			continue
		}
	}
	blockedNames = &xBlockedNames
	if len(proxy.blockNameLogFile) == 0 {
		return nil
	}
	blockedNames.logger = Logger(proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups, proxy.blockNameLogFile)
	blockedNames.format = proxy.blockNameFormat

	return nil
}

func (plugin *PluginBlockName) Drop() error {
	return nil
}

func (plugin *PluginBlockName) Reload() error {
	return nil
}

func (plugin *PluginBlockName) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if blockedNames == nil || pluginsState.sessionData["whitelisted"] != nil {
		return nil
	}
	_, err := blockedNames.check(pluginsState, pluginsState.qName, nil)
	return err
}

// ---

type PluginBlockNameResponse struct {
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
	return nil
}

func (plugin *PluginBlockNameResponse) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if blockedNames == nil || pluginsState.sessionData["whitelisted"] != nil {
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
		if blocked, err := blockedNames.check(pluginsState, target, &aliasFor); blocked || err != nil {
			return err
		}
		aliasesLeft--
		if aliasesLeft == 0 {
			break
		}
	}
	return nil
}
