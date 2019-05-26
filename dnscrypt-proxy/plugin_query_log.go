package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type PluginQueryLog struct {
	logger        *lumberjack.Logger
	format        string
	ignoredQtypes []string
}

func (plugin *PluginQueryLog) Name() string {
	return "query_log"
}

func (plugin *PluginQueryLog) Description() string {
	return "Log DNS queries."
}

func (plugin *PluginQueryLog) Init(proxy *Proxy) error {
	plugin.logger = &lumberjack.Logger{LocalTime: true, MaxSize: proxy.logMaxSize, MaxAge: proxy.logMaxAge, MaxBackups: proxy.logMaxBackups, Filename: proxy.queryLogFile, Compress: true}
	plugin.format = proxy.queryLogFormat
	plugin.ignoredQtypes = proxy.queryLogIgnoredQtypes

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
	if len(plugin.ignoredQtypes) > 0 {
		for _, ignoredQtype := range plugin.ignoredQtypes {
			if strings.EqualFold(ignoredQtype, qType) {
				return nil
			}
		}
	}
	var clientIPStr string
	if pluginsState.clientProto == "udp" {
		clientIPStr = (*pluginsState.clientAddr).(*net.UDPAddr).IP.String()
	} else {
		clientIPStr = (*pluginsState.clientAddr).(*net.TCPAddr).IP.String()
	}
	qName := StripTrailingDot(question.Name)
	returnCode, ok := PluginsReturnCodeToString[pluginsState.returnCode]
	if !ok {
		returnCode = string(returnCode)
	}

	var requestDuration, forwardDuration time.Duration
	if !pluginsState.requestStart.IsZero() && !pluginsState.requestEnd.IsZero() {
		requestDuration = pluginsState.requestEnd.Sub(pluginsState.requestStart)
	}
	forwardDuration = pluginsState.forwardDuration

	var line string
	if plugin.format == "tsv" {
		now := time.Now()
		year, month, day := now.Date()
		hour, minute, second := now.Clock()
		tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
		line = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%v\t%v\n", tsStr, clientIPStr, StringQuote(qName), qType, returnCode, requestDuration, forwardDuration)
	} else if plugin.format == "ltsv" {
		line = fmt.Sprintf("time:%d\thost:%s\tmessage:%s\ttype:%s\treturn:%s\treqDuration:%d\tfwdDuration:%d\n",
			time.Now().Unix(), clientIPStr, StringQuote(qName), qType, returnCode, requestDuration.Nanoseconds(), forwardDuration.Nanoseconds())
	} else {
		dlog.Fatalf("Unexpected log format: [%s]", plugin.format)
	}
	if plugin.logger == nil {
		return errors.New("Log file not initialized")
	}
	plugin.logger.Write([]byte(line))
	return nil
}
