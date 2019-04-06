package main

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type PluginNxLog struct {
	logger *lumberjack.Logger
	format string
}

func (plugin *PluginNxLog) Name() string {
	return "nx_log"
}

func (plugin *PluginNxLog) Description() string {
	return "Log DNS queries for nonexistent zones."
}

func NewPluginNxLog() Plugin {
	return Plugin(new(PluginNxLog))
}

func PluginNxLogEnabled(proxy *Proxy) bool {
	return len(proxy.nxLogFile) != 0
}

func (plugin *PluginNxLog) Init(proxy *Proxy, old *Plugin) error {
	plugin.logger = &lumberjack.Logger{LocalTime: true, MaxSize: proxy.logMaxSize, MaxAge: proxy.logMaxAge, MaxBackups: proxy.logMaxBackups, Filename: proxy.nxLogFile, Compress: true}
	plugin.format = proxy.nxLogFormat

	return nil
}

func (plugin *PluginNxLog) Drop() error {
	return nil
}

func (plugin *PluginNxLog) Reload() error {
	return nil
}

func (plugin *PluginNxLog) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if msg.Rcode != dns.RcodeNameError {
		return nil
	}
	questions := msg.Question
	if len(questions) == 0 {
		return nil
	}
	question := questions[0]
	qType, ok := dns.TypeToString[question.Qtype]
	if !ok {
		qType = string(qType)
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
	if plugin.logger == nil {
		return errors.New("Log file not initialized")
	}
	plugin.logger.Write([]byte(line))

	return nil
}
