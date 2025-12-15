package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
)

type PluginQueryLog struct {
	logger        io.Writer
	format        string
	ignoredQtypes []string
	ipCryptConfig *IPCryptConfig
}

func (plugin *PluginQueryLog) Name() string {
	return "query_log"
}

func (plugin *PluginQueryLog) Description() string {
	return "Log DNS queries."
}

func (plugin *PluginQueryLog) Init(proxy *Proxy) error {
	plugin.logger = Logger(proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups, proxy.queryLogFile)
	plugin.format = proxy.queryLogFormat
	plugin.ignoredQtypes = proxy.queryLogIgnoredQtypes
	plugin.ipCryptConfig = proxy.ipCryptConfig

	return nil
}

func (plugin *PluginQueryLog) Drop() error {
	return nil
}

func (plugin *PluginQueryLog) Reload() error {
	return nil
}

func (plugin *PluginQueryLog) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	clientIPStr, ok := ExtractClientIPStrEncrypted(pluginsState, plugin.ipCryptConfig)
	if !ok {
		// Ignore internal flow.
		return nil
	}
	question := msg.Question[0]
	qType, ok := dns.TypeToString[dns.RRToType(question)]
	if !ok {
		qType = fmt.Sprintf("%d", dns.RRToType(question))
	}
	if len(plugin.ignoredQtypes) > 0 {
		for _, ignoredQtype := range plugin.ignoredQtypes {
			if strings.EqualFold(ignoredQtype, qType) {
				return nil
			}
		}
	}
	qName := pluginsState.qName

	if pluginsState.cacheHit {
		pluginsState.serverName = "-"
	} else {
		switch pluginsState.returnCode {
		case PluginsReturnCodeSynth, PluginsReturnCodeCloak, PluginsReturnCodeParseError:
			pluginsState.serverName = "-"
		}
	}
	returnCode, ok := PluginsReturnCodeToString[pluginsState.returnCode]
	if !ok {
		returnCode = fmt.Sprintf("%d", pluginsState.returnCode)
	}

	var requestDuration time.Duration
	if !pluginsState.requestStart.IsZero() && !pluginsState.requestEnd.IsZero() {
		requestDuration = pluginsState.requestEnd.Sub(pluginsState.requestStart)
	} else {
		// For incomplete queries, use timeout duration
		requestDuration = pluginsState.timeout
	}

	// Cap at timeout to handle system sleep/suspend
	// Max: UDP + TCP, Dial + (write + read)
	triedUDPTCPTimeout := 4 * pluginsState.timeout
	if requestDuration > triedUDPTCPTimeout {
		requestDuration = triedUDPTCPTimeout
	}
	var line string
	if plugin.format == "tsv" {
		now := time.Now()
		year, month, day := now.Date()
		hour, minute, second := now.Clock()
		tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)
		line = fmt.Sprintf(
			"%s\t%s\t%s\t%s\t%s\t%dms\t%s\n",
			tsStr,
			clientIPStr,
			StringQuote(qName),
			qType,
			returnCode,
			requestDuration/time.Millisecond,
			StringQuote(pluginsState.serverName),
		)
	} else if plugin.format == "ltsv" {
		cached := 0
		if pluginsState.cacheHit {
			cached = 1
		}
		line = fmt.Sprintf("time:%d\thost:%s\tmessage:%s\ttype:%s\treturn:%s\tcached:%d\tduration:%d\tserver:%s\n",
			time.Now().Unix(), clientIPStr, StringQuote(qName), qType, returnCode, cached, requestDuration/time.Millisecond, StringQuote(pluginsState.serverName))
	} else {
		dlog.Fatalf("Unexpected log format: [%s]", plugin.format)
	}
	if plugin.logger == nil {
		return errors.New("Log file not initialized")
	}
	_, _ = plugin.logger.Write([]byte(line))

	return nil
}
