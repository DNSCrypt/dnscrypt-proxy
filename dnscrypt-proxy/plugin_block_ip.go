package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/hashicorp/go-immutable-radix"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"gopkg.in/natefinch/lumberjack.v2"
)

type PluginBlockIP struct {
	blockedPrefixes *iradix.Tree
	blockedIPs      map[string]interface{}
	logger          *lumberjack.Logger
	format          string
}

func (plugin *PluginBlockIP) Name() string {
	return "block_ip"
}

func (plugin *PluginBlockIP) Description() string {
	return "Block responses containing specific IP addresses"
}

func (plugin *PluginBlockIP) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of IP blocking rules from [%s]", proxy.blockIPFile)
	bin, err := ReadTextFile(proxy.blockIPFile)
	if err != nil {
		return err
	}
	plugin.blockedPrefixes = iradix.New()
	plugin.blockedIPs = make(map[string]interface{})
	for lineNo, line := range strings.Split(string(bin), "\n") {
		line = strings.TrimFunc(line, unicode.IsSpace)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		ip := net.ParseIP(line)
		trailingStar := strings.HasSuffix(line, "*")
		if len(line) < 2 || (ip != nil && trailingStar) {
			dlog.Errorf("Suspicious IP blocking rule [%s] at line %d", line, lineNo)
			continue
		}
		if trailingStar {
			line = line[:len(line)-1]
		}
		if strings.HasSuffix(line, ":") || strings.HasSuffix(line, ".") {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			dlog.Errorf("Empty IP blocking rule at line %d", lineNo)
			continue
		}
		if strings.Contains(line, "*") {
			dlog.Errorf("Invalid rule: [%s] - wildcards can only be used as a suffix at line %d", line, lineNo)
			continue
		}
		line = strings.ToLower(line)
		if trailingStar {
			plugin.blockedPrefixes, _, _ = plugin.blockedPrefixes.Insert([]byte(line), 0)
		} else {
			plugin.blockedIPs[line] = true
		}
	}
	if len(proxy.blockIPLogFile) == 0 {
		return nil
	}
	plugin.logger = &lumberjack.Logger{LocalTime: true, MaxSize: proxy.logMaxSize, MaxAge: proxy.logMaxAge, MaxBackups: proxy.logMaxBackups, Filename: proxy.blockIPLogFile, Compress: true}
	plugin.format = proxy.blockIPFormat

	return nil
}

func (plugin *PluginBlockIP) Drop() error {
	return nil
}

func (plugin *PluginBlockIP) Reload() error {
	return nil
}

func (plugin *PluginBlockIP) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if pluginsState.sessionData["whitelisted"] != nil {
		return nil
	}
	answers := msg.Answer
	if len(answers) == 0 {
		return nil
	}
	reject, reason, ipStr := false, "", ""
	for _, answer := range answers {
		header := answer.Header()
		Rrtype := header.Rrtype
		if header.Class != dns.ClassINET || (Rrtype != dns.TypeA && Rrtype != dns.TypeAAAA) {
			continue
		}
		if Rrtype == dns.TypeA {
			ipStr = answer.(*dns.A).A.String()
		} else if Rrtype == dns.TypeAAAA {
			ipStr = answer.(*dns.AAAA).AAAA.String() // IPv4-mapped IPv6 addresses are converted to IPv4
		}
		if _, found := plugin.blockedIPs[ipStr]; found {
			reject, reason = true, ipStr
			break
		}
		match, _, found := plugin.blockedPrefixes.Root().LongestPrefix([]byte(ipStr))
		if found {
			if len(match) == len(ipStr) || (ipStr[len(match)] == '.' || ipStr[len(match)] == ':') {
				reject, reason = true, string(match)+"*"
				break
			}
		}
	}
	if reject {
		pluginsState.action = PluginsActionReject
		pluginsState.returnCode = PluginsReturnCodeReject
		if plugin.logger != nil {
			questions := msg.Question
			if len(questions) != 1 {
				return nil
			}
			qName := strings.ToLower(StripTrailingDot(questions[0].Name))
			if len(qName) < 2 {
				return nil
			}
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
				line = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", tsStr, clientIPStr, StringQuote(qName), StringQuote(ipStr), StringQuote(reason))
			} else if plugin.format == "ltsv" {
				line = fmt.Sprintf("time:%d\thost:%s\tqname:%s\tip:%s\tmessage:%s\n", time.Now().Unix(), clientIPStr, StringQuote(qName), StringQuote(ipStr), StringQuote(reason))
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
