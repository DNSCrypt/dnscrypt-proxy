package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	iradix "github.com/hashicorp/go-immutable-radix"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginAllowedIP struct {
	allowedPrefixes *iradix.Tree
	allowedIPs      map[string]interface{}
	logger          io.Writer
	format          string
}

func (plugin *PluginAllowedIP) Name() string {
	return "allow_ip"
}

func (plugin *PluginAllowedIP) Description() string {
	return "Allows DNS queries containing specific IP addresses"
}

func (plugin *PluginAllowedIP) Init(proxy *Proxy) error {
	dlog.Noticef("Loading the set of allowed IP rules from [%s]", proxy.allowedIPFile)
	bin, err := ReadTextFile(proxy.allowedIPFile)
	if err != nil {
		return err
	}
	plugin.allowedPrefixes = iradix.New()
	plugin.allowedIPs = make(map[string]interface{})
	for lineNo, line := range strings.Split(string(bin), "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		ip := net.ParseIP(line)
		trailingStar := strings.HasSuffix(line, "*")
		if len(line) < 2 || (ip != nil && trailingStar) {
			dlog.Errorf("Suspicious allowed IP rule [%s] at line %d", line, lineNo)
			continue
		}
		if trailingStar {
			line = line[:len(line)-1]
		}
		if strings.HasSuffix(line, ":") || strings.HasSuffix(line, ".") {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			dlog.Errorf("Empty allowed IP rule at line %d", lineNo)
			continue
		}
		if strings.Contains(line, "*") {
			dlog.Errorf("Invalid rule: [%s] - wildcards can only be used as a suffix at line %d", line, lineNo)
			continue
		}
		line = strings.ToLower(line)
		if trailingStar {
			plugin.allowedPrefixes, _, _ = plugin.allowedPrefixes.Insert([]byte(line), 0)
		} else {
			plugin.allowedIPs[line] = true
		}
	}
	if len(proxy.allowedIPLogFile) == 0 {
		return nil
	}
	plugin.logger = Logger(proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups, proxy.allowedIPLogFile)
	plugin.format = proxy.allowedIPFormat

	return nil
}

func (plugin *PluginAllowedIP) Drop() error {
	return nil
}

func (plugin *PluginAllowedIP) Reload() error {
	return nil
}

func (plugin *PluginAllowedIP) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	answers := msg.Answer
	if len(answers) == 0 {
		return nil
	}
	allowed, reason, ipStr := false, "", ""
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
		if _, found := plugin.allowedIPs[ipStr]; found {
			allowed, reason = true, ipStr
			break
		}
		match, _, found := plugin.allowedPrefixes.Root().LongestPrefix([]byte(ipStr))
		if found {
			if len(match) == len(ipStr) || (ipStr[len(match)] == '.' || ipStr[len(match)] == ':') {
				allowed, reason = true, string(match)+"*"
				break
			}
		}
	}
	if allowed {
		pluginsState.sessionData["whitelisted"] = true
		if plugin.logger != nil {
			qName := pluginsState.qName
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
			_, _ = plugin.logger.Write([]byte(line))
		}
	}
	return nil
}
