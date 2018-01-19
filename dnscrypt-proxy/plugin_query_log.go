package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginQueryLog struct {
	sync.Mutex
	outFd        *os.File
	format       string
	loggedQTypes []string
}

func (plugin *PluginQueryLog) Name() string {
	return "query_log"
}

func (plugin *PluginQueryLog) Description() string {
	return "Log DNS queries."
}

func (plugin *PluginQueryLog) Init(proxy *Proxy) error {
	plugin.Lock()
	defer plugin.Unlock()
	outFd, err := os.OpenFile(proxy.queryLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	plugin.outFd = outFd
	plugin.format = proxy.queryLogFormat
	plugin.loggedQTypes = proxy.queryLogLoggedQtypes

	return nil
}

func (plugin *PluginQueryLog) Drop() error {
	return nil
}

func (plugin *PluginQueryLog) Reload() error {
	return nil
}

func (plugin *PluginQueryLog) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	questions := msg.Question
	if len(questions) == 0 {
		return nil
	}
	question := questions[0]
	qType, ok := dns.TypeToString[question.Qtype]
	if !ok {
		qType = string(qType)
	}
	if len(plugin.loggedQTypes) > 0 {
		found := false
		for _, loggedQtype := range plugin.loggedQTypes {
			if strings.EqualFold(loggedQtype, qType) {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	var clientIPStr string
	if pluginsState.clientProto == "udp" {
		clientIPStr = (*pluginsState.clientAddr).(*net.UDPAddr).IP.String()
	} else {
		clientIPStr = (*pluginsState.clientAddr).(*net.TCPAddr).IP.String()
	}
	qName := StripTrailingDot(question.Name)

	var line string
	if plugin.format == "tsv" {
		now := time.Now()
		year, month, day := now.Date()
		hour, minute, second := now.Clock()
		tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
		line = fmt.Sprintf("%s\t%s\t%s\t%s\n", tsStr, clientIPStr, StringQuote(qName), qType)
	} else if plugin.format == "ltsv" {
		line = fmt.Sprintf("time:%d\thost:%s\tmessage:%s\ttype:%s\n",
			time.Now().Unix(), clientIPStr, StringQuote(qName), qType)
	} else {
		dlog.Fatalf("Unexpected log format: [%s]", plugin.format)
	}
	plugin.Lock()
	if plugin.outFd == nil {
		return errors.New("Log file not initialized")
	}
	plugin.outFd.WriteString(line)
	defer plugin.Unlock()
	return nil
}
