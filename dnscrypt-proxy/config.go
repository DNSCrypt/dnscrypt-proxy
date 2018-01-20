package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jedisct1/dlog"
)

type Config struct {
	LogLevel            int      `toml:"log_level"`
	LogFile             *string  `toml:"log_file"`
	UseSyslog           bool     `toml:"use_syslog"`
	ServerNames         []string `toml:"server_names"`
	ListenAddresses     []string `toml:"listen_addresses"`
	Daemonize           bool
	ForceTCP            bool `toml:"force_tcp"`
	Timeout             int  `toml:"timeout_ms"`
	CertRefreshDelay    int  `toml:"cert_refresh_delay"`
	BlockIPv6           bool `toml:"block_ipv6"`
	Cache               bool
	CacheSize           int                     `toml:"cache_size"`
	CacheNegTTL         uint32                  `toml:"cache_neg_ttl"`
	CacheMinTTL         uint32                  `toml:"cache_min_ttl"`
	CacheMaxTTL         uint32                  `toml:"cache_max_ttl"`
	QueryLog            QueryLogConfig          `toml:"query_log"`
	NxLog               NxLogConfig             `toml:"nx_log"`
	BlockName           BlockNameConfig         `toml:"blacklist"`
	ForwardFile         string                  `toml:"forwarding_rules"`
	ServersConfig       map[string]ServerConfig `toml:"servers"`
	SourcesConfig       map[string]SourceConfig `toml:"sources"`
	SourceRequireDNSSEC bool                    `toml:"require_dnssec"`
	SourceRequireNoLog  bool                    `toml:"require_nolog"`
	SourceIPv4          bool                    `toml:"ipv4_servers"`
	SourceIPv6          bool                    `toml:"ipv6_servers"`
}

func newConfig() Config {
	return Config{
		LogLevel:           int(dlog.LogLevel()),
		ListenAddresses:    []string{"127.0.0.1:53"},
		Timeout:            2500,
		CertRefreshDelay:   30,
		Cache:              true,
		CacheSize:          256,
		CacheNegTTL:        60,
		CacheMinTTL:        60,
		CacheMaxTTL:        8600,
		SourceRequireNoLog: true,
		SourceIPv4:         true,
		SourceIPv6:         false,
	}
}

type ServerConfig struct {
	Stamp        string
	ProviderName string `toml:"provider_name"`
	Address      string
	PublicKey    string `toml:"public_key"`
	DNSSEC       bool   `toml:"dnssec"`
	NoLog        bool   `toml:"no_log"`
	IPv4         bool   `toml:"ipv4"`
	IPv6         bool   `toml:"ipv6"`
}

type SourceConfig struct {
	URL            string
	MinisignKeyStr string `toml:"minisign_key"`
	CacheFile      string `toml:"cache_file"`
	FormatStr      string `toml:"format"`
	RefreshDelay   int    `toml:"refresh_delay"`
	Prefix         string
}

type QueryLogConfig struct {
	File          string
	Format        string
	IgnoredQtypes []string `toml:"ignored_qtypes"`
}

type NxLogConfig struct {
	File   string
	Format string
}

type BlockNameConfig struct {
	File    string `toml:"blacklist_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

func ConfigLoad(proxy *Proxy, svcFlag *string, config_file string) error {
	version := flag.Bool("version", false, "prints current proxy version")
	configFile := flag.String("config", "dnscrypt-proxy.toml", "path to the configuration file")
	flag.Parse()
	if *svcFlag == "stop" || *svcFlag == "uninstall" {
		return nil
	}
	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}
	config := newConfig()
	if _, err := toml.DecodeFile(*configFile, &config); err != nil {
		return err
	}
	if config.LogLevel >= 0 && config.LogLevel < int(dlog.SeverityLast) {
		dlog.SetLogLevel(dlog.Severity(config.LogLevel))
	}
	if dlog.LogLevel() <= dlog.SeverityDebug && os.Getenv("DEBUG") == "" {
		dlog.SetLogLevel(dlog.SeverityInfo)
	}
	if config.UseSyslog {
		dlog.UseSyslog(true)
	} else if config.LogFile != nil {
		dlog.UseLogFile(*config.LogFile)
	}
	proxy.timeout = time.Duration(config.Timeout) * time.Millisecond
	proxy.mainProto = "udp"
	if config.ForceTCP {
		proxy.mainProto = "tcp"
	}
	proxy.certRefreshDelay = time.Duration(config.CertRefreshDelay) * time.Minute
	proxy.certRefreshDelayAfterFailure = time.Duration(10 * time.Second)
	if len(config.ListenAddresses) == 0 {
		return errors.New("No local IP/port configured")
	}
	proxy.listenAddresses = config.ListenAddresses
	proxy.daemonize = config.Daemonize
	proxy.pluginBlockIPv6 = config.BlockIPv6
	proxy.cache = config.Cache
	proxy.cacheSize = config.CacheSize
	proxy.cacheNegTTL = config.CacheNegTTL
	proxy.cacheMinTTL = config.CacheMinTTL
	proxy.cacheMaxTTL = config.CacheMaxTTL

	if len(config.QueryLog.Format) == 0 {
		config.QueryLog.Format = "tsv"
	} else {
		config.QueryLog.Format = strings.ToLower(config.QueryLog.Format)
	}
	if config.QueryLog.Format != "tsv" && config.QueryLog.Format != "ltsv" {
		return errors.New("Unsupported query log format")
	}
	proxy.queryLogFile = config.QueryLog.File
	proxy.queryLogFormat = config.QueryLog.Format
	proxy.queryLogIgnoredQtypes = config.QueryLog.IgnoredQtypes

	if len(config.NxLog.Format) == 0 {
		config.NxLog.Format = "tsv"
	} else {
		config.NxLog.Format = strings.ToLower(config.NxLog.Format)
	}
	if config.NxLog.Format != "tsv" && config.NxLog.Format != "ltsv" {
		return errors.New("Unsupported NX log format")
	}
	proxy.nxLogFile = config.NxLog.File
	proxy.nxLogFormat = config.NxLog.Format

	if len(config.BlockName.Format) == 0 {
		config.BlockName.Format = "tsv"
	} else {
		config.BlockName.Format = strings.ToLower(config.BlockName.Format)
	}
	if config.BlockName.Format != "tsv" && config.BlockName.Format != "ltsv" {
		return errors.New("Unsupported block log format")
	}
	proxy.blockNameFile = config.BlockName.File
	proxy.blockNameFormat = config.BlockName.Format
	proxy.blockNameLogFile = config.BlockName.LogFile

	proxy.forwardFile = config.ForwardFile

	requiredProps := ServerInformalProperties(0)
	if config.SourceRequireDNSSEC {
		requiredProps |= ServerInformalPropertyDNSSEC
	}
	if config.SourceRequireNoLog {
		requiredProps |= ServerInformalPropertyNoLog
	}

	for cfgSourceName, cfgSource := range config.SourcesConfig {
		if cfgSource.URL == "" {
			return fmt.Errorf("Missing URL for source [%s]", cfgSourceName)
		}
		if cfgSource.MinisignKeyStr == "" {
			return fmt.Errorf("Missing Minisign key for source [%s]", cfgSourceName)
		}
		if cfgSource.CacheFile == "" {
			return fmt.Errorf("Missing cache file for source [%s]", cfgSourceName)
		}
		if cfgSource.FormatStr == "" {
			return fmt.Errorf("Missing format for source [%s]", cfgSourceName)
		}
		if cfgSource.RefreshDelay <= 0 {
			cfgSource.RefreshDelay = 24
		}
		source, sourceUrlsToPrefetch, err := NewSource(cfgSource.URL, cfgSource.MinisignKeyStr, cfgSource.CacheFile, cfgSource.FormatStr, time.Duration(cfgSource.RefreshDelay)*time.Hour)
		proxy.urlsToPrefetch = append(proxy.urlsToPrefetch, sourceUrlsToPrefetch...)
		if err != nil {
			dlog.Criticalf("Unable use source [%s]: [%s]", cfgSourceName, err)
			continue
		}
		registeredServers, err := source.Parse(cfgSource.Prefix)
		if err != nil {
			dlog.Criticalf("Unable use source [%s]: [%s]", cfgSourceName, err)
			continue
		}
		for _, registeredServer := range registeredServers {
			if len(config.ServerNames) > 0 {
				if !includesName(config.ServerNames, registeredServer.name) {
					continue
				}
			} else if registeredServer.stamp.props&requiredProps != requiredProps {
				continue
			}
			if config.SourceIPv4 || config.SourceIPv6 {
				isIPv4, isIPv6 := true, false
				if strings.HasPrefix(registeredServer.stamp.serverAddrStr, "[") {
					isIPv4, isIPv6 = false, true
				}
				if !(config.SourceIPv4 == isIPv4 || config.SourceIPv6 == isIPv6) {
					continue
				}
			}
			dlog.Debugf("Adding [%s] to the set of wanted resolvers", registeredServer.name)
			proxy.registeredServers = append(proxy.registeredServers, registeredServer)
		}
	}
	if len(config.ServerNames) == 0 {
		for serverName := range config.ServersConfig {
			config.ServerNames = append(config.ServerNames, serverName)
		}
	}
	for _, serverName := range config.ServerNames {
		serverConfig, ok := config.ServersConfig[serverName]
		if !ok {
			continue
		}
		var stamp ServerStamp
		var err error
		if len(serverConfig.Stamp) > 0 {
			stamp, err = NewServerStampFromString(serverConfig.Stamp)
		} else {
			props := ServerInformalProperties(0)
			if serverConfig.DNSSEC {
				props |= ServerInformalPropertyDNSSEC
			}
			if serverConfig.NoLog {
				props |= ServerInformalPropertyNoLog
			}
			stamp, err = NewServerStampFromLegacy(serverConfig.Address, serverConfig.PublicKey, serverConfig.ProviderName, props)
		}
		if err != nil {
			return err
		}
		proxy.registeredServers = append(proxy.registeredServers,
			RegisteredServer{name: serverName, stamp: stamp})
	}
	if len(proxy.registeredServers) == 0 {
		return errors.New("No servers configured")
	}
	return nil
}

func includesName(names []string, name string) bool {
	for _, found := range names {
		if strings.EqualFold(found, name) {
			return true
		}
	}
	return false
}
