package main

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
)

type PluginQueryLog struct {
	logger          io.Writer
	format          string
	ignoredQtypes   []string
	ignoredQtypeMap map[string]struct{} // O(1) lookup for ignored query types
	ipCryptConfig   *IPCryptConfig
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

	// Build O(1) lookup map for ignored query types
	if len(plugin.ignoredQtypes) > 0 {
		plugin.ignoredQtypeMap = make(map[string]struct{}, len(plugin.ignoredQtypes))
		for _, qt := range plugin.ignoredQtypes {
			plugin.ignoredQtypeMap[strings.ToUpper(qt)] = struct{}{}
		}
	}

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
		qType = strconv.FormatUint(uint64(dns.RRToType(question)), 10)
	}
	if len(plugin.ignoredQtypeMap) > 0 {
		if _, ignored := plugin.ignoredQtypeMap[strings.ToUpper(qType)]; ignored {
			return nil
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
		returnCode = strconv.Itoa(int(pluginsState.returnCode))
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
	relayName := pluginsState.relayName
	if relayName == "" {
		relayName = "-"
	}

	var b strings.Builder
	if plugin.format == "tsv" {
		b.Grow(128 + len(qName) + len(pluginsState.serverName) + len(relayName))
		b.WriteString(formatTimestampTSV(time.Now()))
		b.WriteByte('\t')
		b.WriteString(clientIPStr)
		b.WriteByte('\t')
		b.WriteString(StringQuote(qName))
		b.WriteByte('\t')
		b.WriteString(qType)
		b.WriteByte('\t')
		b.WriteString(returnCode)
		b.WriteByte('\t')
		b.WriteString(strconv.FormatInt(int64(requestDuration/time.Millisecond), 10))
		b.WriteString("ms\t")
		b.WriteString(StringQuote(pluginsState.serverName))
		b.WriteByte('\t')
		b.WriteString(StringQuote(relayName))
		b.WriteByte('\n')
	} else if plugin.format == "ltsv" {
		cached := "0"
		if pluginsState.cacheHit {
			cached = "1"
		}
		b.Grow(128 + len(qName) + len(pluginsState.serverName) + len(relayName))
		b.WriteString("time:")
		b.WriteString(strconv.FormatInt(time.Now().Unix(), 10))
		b.WriteString("\thost:")
		b.WriteString(clientIPStr)
		b.WriteString("\tmessage:")
		b.WriteString(StringQuote(qName))
		b.WriteString("\ttype:")
		b.WriteString(qType)
		b.WriteString("\treturn:")
		b.WriteString(returnCode)
		b.WriteString("\tcached:")
		b.WriteString(cached)
		b.WriteString("\tduration:")
		b.WriteString(strconv.FormatInt(int64(requestDuration/time.Millisecond), 10))
		b.WriteString("\tserver:")
		b.WriteString(StringQuote(pluginsState.serverName))
		b.WriteString("\trelay:")
		b.WriteString(StringQuote(relayName))
		b.WriteByte('\n')
	} else {
		dlog.Fatalf("Unexpected log format: [%s]", plugin.format)
	}
	if plugin.logger == nil {
		return errors.New("Log file not initialized")
	}
	_, _ = io.WriteString(plugin.logger, b.String())

	return nil
}
