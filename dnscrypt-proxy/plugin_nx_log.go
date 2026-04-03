package main

import (
	"io"
	"strconv"

	"codeberg.org/miekg/dns"
)

type PluginNxLog struct {
	logger        io.Writer
	format        string
	ipCryptConfig *IPCryptConfig
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
	plugin.ipCryptConfig = proxy.ipCryptConfig

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
	qName := pluginsState.qName

	if err := WritePluginLog(plugin.logger, plugin.format, clientIPStr, qName, qType); err != nil {
		return err
	}

	return nil
}
