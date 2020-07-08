package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginNxLog struct {
	logger io.Writer
	format string
}

func (plugin *PluginNxLog) Name() string {
	return "nx_log"
}

func (plugin *PluginNxLog) Description() string {
	return "Log DNS queries for nonexistent zones."
}

func (plugin *PluginNxLog) Init(proxy *Proxy) error {
	plugin.logger = Logger(proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups, proxy.nxLogFile)
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
	question := msg.Question[0]
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
	qName := pluginsState.qName

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
	_, _ = plugin.logger.Write([]byte(line))

	return nil
}
