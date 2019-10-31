package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jedisct1/dlog"
	"github.com/jedisct1/dnscrypt-proxy/dnscrypt"
	stamps "github.com/jedisct1/go-dnsstamps"
	netproxy "golang.org/x/net/proxy"
)

const (
	DefaultNetprobeAddress = "9.9.9.9:53"
)

type Config struct {
	LogLevel                 int      `toml:"log_level"`
	LogFile                  *string  `toml:"log_file"`
	UseSyslog                bool     `toml:"use_syslog"`
	ServerNames              []string `toml:"server_names"`
	DisabledServerNames      []string `toml:"disabled_server_names"`
	ListenAddresses          []string `toml:"listen_addresses"`
	Daemonize                bool
	UserName                 string `toml:"user_name"`
	ForceTCP                 bool   `toml:"force_tcp"`
	Timeout                  int    `toml:"timeout"`
	KeepAlive                int    `toml:"keepalive"`
	Proxy                    string `toml:"proxy"`
	CertRefreshDelay         int    `toml:"cert_refresh_delay"`
	CertIgnoreTimestamp      bool   `toml:"cert_ignore_timestamp"`
	EphemeralKeys            bool   `toml:"dnscrypt_ephemeral_keys"`
	LBStrategy               string `toml:"lb_strategy"`
	LBEstimator              bool   `toml:"lb_estimator"`
	BlockIPv6                bool   `toml:"block_ipv6"`
	Cache                    bool
	CacheSize                int                                 `toml:"cache_size"`
	CacheNegTTL              uint32                              `toml:"cache_neg_ttl"`
	CacheNegMinTTL           uint32                              `toml:"cache_neg_min_ttl"`
	CacheNegMaxTTL           uint32                              `toml:"cache_neg_max_ttl"`
	CacheMinTTL              uint32                              `toml:"cache_min_ttl"`
	CacheMaxTTL              uint32                              `toml:"cache_max_ttl"`
	RejectTTL                uint32                              `toml:"reject_ttl"`
	CloakTTL                 uint32                              `toml:"cloak_ttl"`
	QueryLog                 QueryLogConfig                      `toml:"query_log"`
	NxLog                    NxLogConfig                         `toml:"nx_log"`
	BlockName                BlockNameConfig                     `toml:"blacklist"`
	WhitelistName            WhitelistNameConfig                 `toml:"whitelist"`
	BlockIP                  BlockIPConfig                       `toml:"ip_blacklist"`
	ForwardFile              string                              `toml:"forwarding_rules"`
	CloakFile                string                              `toml:"cloaking_rules"`
	StaticsConfig            map[string]StaticConfig             `toml:"static"`
	SourcesConfig            map[string]SourceConfig             `toml:"sources"`
	SourceRequireDNSSEC      bool                                `toml:"require_dnssec"`
	SourceRequireNoLog       bool                                `toml:"require_nolog"`
	SourceRequireNoFilter    bool                                `toml:"require_nofilter"`
	SourceDNSCrypt           bool                                `toml:"dnscrypt_servers"`
	SourceDoH                bool                                `toml:"doh_servers"`
	SourceIPv4               bool                                `toml:"ipv4_servers"`
	SourceIPv6               bool                                `toml:"ipv6_servers"`
	MaxClients               uint32                              `toml:"max_clients"`
	FallbackResolver         string                              `toml:"fallback_resolver"`
	IgnoreSystemDNS          bool                                `toml:"ignore_system_dns"`
	AllWeeklyRanges          map[string]dnscrypt.WeeklyRangesStr `toml:"schedules"`
	LogMaxSize               int                                 `toml:"log_files_max_size"`
	LogMaxAge                int                                 `toml:"log_files_max_age"`
	LogMaxBackups            int                                 `toml:"log_files_max_backups"`
	TLSDisableSessionTickets bool                                `toml:"tls_disable_session_tickets"`
	TLSCipherSuite           []uint16                            `toml:"tls_cipher_suite"`
	NetprobeAddress          string                              `toml:"netprobe_address"`
	NetprobeTimeout          int                                 `toml:"netprobe_timeout"`
	OfflineMode              bool                                `toml:"offline_mode"`
	HTTPProxyURL             string                              `toml:"http_proxy"`
	RefusedCodeInResponses   bool                                `toml:"refused_code_in_responses"`
	BlockedQueryResponse     string                              `toml:"blocked_query_response"`
	QueryMeta                []string                            `toml:"query_meta"`
	AnonymizedDNS            AnonymizedDNSConfig                 `toml:"anonymized_dns"`
}

func newConfig() Config {
	return Config{
		LogLevel:                 int(dlog.LogLevel()),
		ListenAddresses:          []string{"127.0.0.1:53"},
		Timeout:                  5000,
		KeepAlive:                5,
		CertRefreshDelay:         240,
		CertIgnoreTimestamp:      false,
		EphemeralKeys:            false,
		Cache:                    true,
		CacheSize:                512,
		CacheNegTTL:              0,
		CacheNegMinTTL:           60,
		CacheNegMaxTTL:           600,
		CacheMinTTL:              60,
		CacheMaxTTL:              86400,
		RejectTTL:                600,
		CloakTTL:                 600,
		SourceRequireNoLog:       true,
		SourceRequireNoFilter:    true,
		SourceIPv4:               true,
		SourceIPv6:               false,
		SourceDNSCrypt:           true,
		SourceDoH:                true,
		MaxClients:               250,
		FallbackResolver:         dnscrypt.DefaultFallbackResolver,
		IgnoreSystemDNS:          false,
		LogMaxSize:               10,
		LogMaxAge:                7,
		LogMaxBackups:            1,
		TLSDisableSessionTickets: false,
		TLSCipherSuite:           nil,
		NetprobeTimeout:          60,
		OfflineMode:              false,
		RefusedCodeInResponses:   false,
		LBEstimator:              true,
		BlockedQueryResponse:     "hinfo",
	}
}

type StaticConfig struct {
	Stamp string
}

type SourceConfig struct {
	URL            string
	URLs           []string
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

type WhitelistNameConfig struct {
	File    string `toml:"whitelist_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

type BlockIPConfig struct {
	File    string `toml:"blacklist_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

type AnonymizedDNSRouteConfig struct {
	ServerName string   `toml:"server_name"`
	RelayNames []string `toml:"via"`
}

type AnonymizedDNSConfig struct {
	Routes []AnonymizedDNSRouteConfig `toml:"routes"`
}

type ServerSummary struct {
	Name        string   `json:"name"`
	Proto       string   `json:"proto"`
	IPv6        bool     `json:"ipv6"`
	Addrs       []string `json:"addrs,omitempty"`
	Ports       []int    `json:"ports"`
	DNSSEC      bool     `json:"dnssec"`
	NoLog       bool     `json:"nolog"`
	NoFilter    bool     `json:"nofilter"`
	Description string   `json:"description,omitempty"`
	Stamp       string   `json:"stamp"`
}

func findConfigFile(configFile *string) (string, error) {
	if _, err := os.Stat(*configFile); os.IsNotExist(err) {
		cdLocal()
		if _, err := os.Stat(*configFile); err != nil {
			return "", err
		}
	}
	pwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(*configFile) {
		return *configFile, nil
	}
	return path.Join(pwd, *configFile), nil
}

func ConfigLoad(proxy *dnscrypt.Proxy, svcFlag *string) error {
	version := flag.Bool("version", false, "print current proxy version")
	resolve := flag.String("resolve", "", "resolve a name using system libraries")
	list := flag.Bool("list", false, "print the list of available resolvers for the enabled filters")
	listAll := flag.Bool("list-all", false, "print the complete list of available resolvers, ignoring filters")
	jsonOutput := flag.Bool("json", false, "output list as JSON")
	check := flag.Bool("check", false, "check the configuration file and exit")
	configFile := flag.String("config", DefaultConfigFileName, "Path to the configuration file")
	child := flag.Bool("child", false, "Invokes program as a child process")
	netprobeTimeoutOverride := flag.Int("netprobe-timeout", 60, "Override the netprobe timeout")
	showCerts := flag.Bool("show-certs", false, "print DoH certificate chain hashes")

	flag.Parse()

	if *svcFlag == "stop" || *svcFlag == "uninstall" {
		return nil
	}
	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}
	if resolve != nil && len(*resolve) > 0 {
		dnscrypt.Resolve(*resolve)
		os.Exit(0)
	}

	foundConfigFile, err := findConfigFile(configFile)
	if err != nil {
		dlog.Fatalf("Unable to load the configuration file [%s] -- Maybe use the -config command-line switch?", *configFile)
	}
	config := newConfig()
	md, err := toml.DecodeFile(foundConfigFile, &config)
	if err != nil {
		return err
	}
	undecoded := md.Undecoded()
	if len(undecoded) > 0 {
		return fmt.Errorf("Unsupported key in configuration file: [%s]", undecoded[0])
	}
	cdFileDir(foundConfigFile)
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
		if !*child {
			dnscrypt.FileDescriptors = append(
				dnscrypt.FileDescriptors, dlog.GetFileDescriptor())
		} else {
			dnscrypt.FileDescriptorNum++
			dlog.SetFileDescriptor(os.NewFile(uintptr(3), "logFile"))
		}
	}
	proxy.LogMaxSize = config.LogMaxSize
	proxy.LogMaxAge = config.LogMaxAge
	proxy.LogMaxBackups = config.LogMaxBackups

	proxy.UserName = config.UserName

	proxy.Child = *child
	proxy.XTransport = dnscrypt.NewXTransport()
	proxy.XTransport.TLSDisableSessionTickets = config.TLSDisableSessionTickets
	proxy.XTransport.TLSCipherSuite = config.TLSCipherSuite
	proxy.XTransport.MainProto = proxy.MainProto
	if len(config.FallbackResolver) > 0 {
		if err := dnscrypt.CheckResolver(config.FallbackResolver); err != nil {
			dlog.Fatalf("fallback_resolver [%v]", err)
		}
		proxy.XTransport.IgnoreSystemDNS = config.IgnoreSystemDNS
	}
	proxy.XTransport.FallbackResolver = config.FallbackResolver
	proxy.XTransport.UseIPv4 = config.SourceIPv4
	proxy.XTransport.UseIPv6 = config.SourceIPv6
	proxy.XTransport.KeepAlive = time.Duration(config.KeepAlive) * time.Second
	if len(config.HTTPProxyURL) > 0 {
		httpProxyURL, err := url.Parse(config.HTTPProxyURL)
		if err != nil {
			dlog.Fatalf("Unable to parse the HTTP proxy URL [%v]", config.HTTPProxyURL)
		}
		proxy.XTransport.HTTPProxyFunction = http.ProxyURL(httpProxyURL)
	}

	if len(config.Proxy) > 0 {
		proxyDialerURL, err := url.Parse(config.Proxy)
		if err != nil {
			dlog.Fatalf("Unable to parse the proxy URL [%v]", config.Proxy)
		}
		proxyDialer, err := netproxy.FromURL(proxyDialerURL, netproxy.Direct)
		if err != nil {
			dlog.Fatalf("Unable to use the proxy: [%v]", err)
		}
		proxy.XTransport.ProxyDialer = &proxyDialer
		proxy.MainProto = "tcp"
	}

	proxy.XTransport.RebuildTransport()

	if md.IsDefined("refused_code_in_responses") {
		dlog.Notice("config option `refused_code_in_responses` is deprecated, use `blocked_query_response`")
		if config.RefusedCodeInResponses {
			config.BlockedQueryResponse = "refused"
		} else {
			config.BlockedQueryResponse = "hinfo"
		}
	}
	proxy.BlockedQueryResponse = config.BlockedQueryResponse
	proxy.Timeout = time.Duration(config.Timeout) * time.Millisecond
	proxy.MaxClients = config.MaxClients
	proxy.MainProto = "udp"
	if config.ForceTCP {
		proxy.MainProto = "tcp"
	}
	proxy.CertRefreshDelay = time.Duration(config.CertRefreshDelay) * time.Minute
	proxy.CertRefreshDelayAfterFailure = time.Duration(10 * time.Second)
	proxy.CertIgnoreTimestamp = config.CertIgnoreTimestamp
	proxy.EphemeralKeys = config.EphemeralKeys
	if len(config.ListenAddresses) == 0 {
		dlog.Debug("No local IP/port configured")
	}

	lbStrategy := dnscrypt.DefaultLBStrategy
	switch strings.ToLower(config.LBStrategy) {
	case "":
		// default
	case "p2":
		lbStrategy = dnscrypt.LBStrategyP2
	case "ph":
		lbStrategy = dnscrypt.LBStrategyPH
	case "fastest":
	case "first":
		lbStrategy = dnscrypt.LBStrategyFirst
	case "random":
		lbStrategy = dnscrypt.LBStrategyRandom
	default:
		dlog.Warnf("Unknown load balancing strategy: [%s]", config.LBStrategy)
	}
	proxy.ServersInfo.LBStrategy = lbStrategy
	proxy.ServersInfo.LBEstimator = config.LBEstimator

	proxy.ListenAddresses = config.ListenAddresses
	proxy.Daemonize = config.Daemonize
	proxy.PluginBlockIPv6 = config.BlockIPv6
	proxy.Cache = config.Cache
	proxy.CacheSize = config.CacheSize

	if config.CacheNegTTL > 0 {
		proxy.CacheNegMinTTL = config.CacheNegTTL
		proxy.CacheNegMaxTTL = config.CacheNegTTL
	} else {
		proxy.CacheNegMinTTL = config.CacheNegMinTTL
		proxy.CacheNegMaxTTL = config.CacheNegMaxTTL
	}

	proxy.CacheMinTTL = config.CacheMinTTL
	proxy.CacheMaxTTL = config.CacheMaxTTL
	proxy.RejectTTL = config.RejectTTL
	proxy.CloakTTL = config.CloakTTL

	proxy.QueryMeta = config.QueryMeta

	if len(config.QueryLog.Format) == 0 {
		config.QueryLog.Format = "tsv"
	} else {
		config.QueryLog.Format = strings.ToLower(config.QueryLog.Format)
	}
	if config.QueryLog.Format != "tsv" && config.QueryLog.Format != "ltsv" {
		return errors.New("Unsupported query log format")
	}
	proxy.QueryLogFile = config.QueryLog.File
	proxy.QueryLogFormat = config.QueryLog.Format
	proxy.QueryLogIgnoredQtypes = config.QueryLog.IgnoredQtypes

	if len(config.NxLog.Format) == 0 {
		config.NxLog.Format = "tsv"
	} else {
		config.NxLog.Format = strings.ToLower(config.NxLog.Format)
	}
	if config.NxLog.Format != "tsv" && config.NxLog.Format != "ltsv" {
		return errors.New("Unsupported NX log format")
	}
	proxy.NXLogFile = config.NxLog.File
	proxy.NXLogFormat = config.NxLog.Format

	if len(config.BlockName.Format) == 0 {
		config.BlockName.Format = "tsv"
	} else {
		config.BlockName.Format = strings.ToLower(config.BlockName.Format)
	}
	if config.BlockName.Format != "tsv" && config.BlockName.Format != "ltsv" {
		return errors.New("Unsupported block log format")
	}
	proxy.BlockNameFile = config.BlockName.File
	proxy.BlockNameFormat = config.BlockName.Format
	proxy.BlockNameLogFile = config.BlockName.LogFile

	if len(config.WhitelistName.Format) == 0 {
		config.WhitelistName.Format = "tsv"
	} else {
		config.WhitelistName.Format = strings.ToLower(config.WhitelistName.Format)
	}
	if config.WhitelistName.Format != "tsv" && config.WhitelistName.Format != "ltsv" {
		return errors.New("Unsupported whitelist log format")
	}
	proxy.WhitelistNameFile = config.WhitelistName.File
	proxy.WhitelistNameFormat = config.WhitelistName.Format
	proxy.WhitelistNameLogFile = config.WhitelistName.LogFile

	if len(config.BlockIP.Format) == 0 {
		config.BlockIP.Format = "tsv"
	} else {
		config.BlockIP.Format = strings.ToLower(config.BlockIP.Format)
	}
	if config.BlockIP.Format != "tsv" && config.BlockIP.Format != "ltsv" {
		return errors.New("Unsupported IP block log format")
	}
	proxy.BlockIPFile = config.BlockIP.File
	proxy.BlockIPFormat = config.BlockIP.Format
	proxy.BlockIPLogFile = config.BlockIP.LogFile

	proxy.ForwardFile = config.ForwardFile
	proxy.CloakFile = config.CloakFile

	allWeeklyRanges, err := dnscrypt.ParseAllWeeklyRanges(config.AllWeeklyRanges)
	if err != nil {
		return err
	}
	proxy.AllWeeklyRanges = allWeeklyRanges

	if configRoutes := config.AnonymizedDNS.Routes; configRoutes != nil {
		routes := make(map[string][]string)
		for _, configRoute := range configRoutes {
			routes[configRoute.ServerName] = configRoute.RelayNames
		}
		proxy.Routes = &routes
	}

	if *listAll {
		config.ServerNames = nil
		config.DisabledServerNames = nil
		config.SourceRequireDNSSEC = false
		config.SourceRequireNoFilter = false
		config.SourceRequireNoLog = false
		config.SourceIPv4 = true
		config.SourceIPv6 = true
		config.SourceDNSCrypt = true
		config.SourceDoH = true
	}

	netprobeTimeout := config.NetprobeTimeout
	flag.Visit(func(flag *flag.Flag) {
		if flag.Name == "netprobe-timeout" && netprobeTimeoutOverride != nil {
			netprobeTimeout = *netprobeTimeoutOverride
		}
	})
	netprobeAddress := DefaultNetprobeAddress
	if len(config.NetprobeAddress) > 0 {
		netprobeAddress = config.NetprobeAddress
	} else if len(config.FallbackResolver) > 0 {
		netprobeAddress = config.FallbackResolver
	}
	proxy.ShowCerts = *showCerts || len(os.Getenv("SHOW_CERTS")) > 0
	if proxy.ShowCerts {
		proxy.ListenAddresses = proxy.ListenAddresses[0:0]
	}
	dlog.Noticef("dnscrypt-proxy %s", AppVersion)
	if err := dnscrypt.NetProbe(netprobeAddress, netprobeTimeout); err != nil {
		return err
	}
	if !config.OfflineMode {
		if err := config.loadSources(proxy); err != nil {
			return err
		}
		if len(proxy.RegisteredServers) == 0 {
			return errors.New("No servers configured")
		}
	}
	if *list || *listAll {
		config.printRegisteredServers(proxy, *jsonOutput)
		os.Exit(0)
	}
	if proxy.Routes != nil && len(*proxy.Routes) > 0 {
		hasSpecificRoutes := false
		for _, server := range proxy.RegisteredServers {
			if via, ok := (*proxy.Routes)[server.Name]; ok {
				if server.Stamp.Proto != stamps.StampProtoTypeDNSCrypt {
					dlog.Errorf("DNS anonymization is only supported with the DNSCrypt protocol - Connections to [%v] cannot be anonymized", server.Name)
				} else {
					dlog.Noticef("Anonymized DNS: routing [%v] via %v", server.Name, via)
				}
				hasSpecificRoutes = true
			}
		}
		if via, ok := (*proxy.Routes)["*"]; ok {
			if hasSpecificRoutes {
				dlog.Noticef("Anonymized DNS: routing everything else via %v", via)
			} else {
				dlog.Noticef("Anonymized DNS: routing everything via %v", via)
			}
		}
	}
	if *check {
		dlog.Notice("Configuration successfully checked")
		os.Exit(0)
	}
	return nil
}

func (config *Config) printRegisteredServers(proxy *dnscrypt.Proxy, jsonOutput bool) {
	var summary []ServerSummary
	for _, registeredServer := range proxy.RegisteredServers {
		addrStr, port := registeredServer.Stamp.ServerAddrStr, stamps.DefaultPort
		var hostAddr string
		hostAddr, port = dnscrypt.ExtractHostAndPort(addrStr, port)
		addrs := make([]string, 0)
		if registeredServer.Stamp.Proto == stamps.StampProtoTypeDoH && len(registeredServer.Stamp.ProviderName) > 0 {
			providerName := registeredServer.Stamp.ProviderName
			var host string
			host, port = dnscrypt.ExtractHostAndPort(providerName, port)
			addrs = append(addrs, host)
		}
		if len(addrStr) > 0 {
			addrs = append(addrs, hostAddr)
		}
		serverSummary := ServerSummary{
			Name:        registeredServer.Name,
			Proto:       registeredServer.Stamp.Proto.String(),
			IPv6:        strings.HasPrefix(addrStr, "["),
			Ports:       []int{port},
			Addrs:       addrs,
			DNSSEC:      registeredServer.Stamp.Props&stamps.ServerInformalPropertyDNSSEC != 0,
			NoLog:       registeredServer.Stamp.Props&stamps.ServerInformalPropertyNoLog != 0,
			NoFilter:    registeredServer.Stamp.Props&stamps.ServerInformalPropertyNoFilter != 0,
			Description: registeredServer.Description,
			Stamp:       registeredServer.Stamp.String(),
		}
		if jsonOutput {
			summary = append(summary, serverSummary)
		} else {
			fmt.Println(serverSummary.Name)
		}
	}
	if jsonOutput {
		jsonStr, err := json.MarshalIndent(summary, "", " ")
		if err != nil {
			dlog.Fatal(err)
		}
		fmt.Print(string(jsonStr))
	}
}

func (config *Config) loadSources(proxy *dnscrypt.Proxy) error {
	var requiredProps stamps.ServerInformalProperties
	if config.SourceRequireDNSSEC {
		requiredProps |= stamps.ServerInformalPropertyDNSSEC
	}
	if config.SourceRequireNoLog {
		requiredProps |= stamps.ServerInformalPropertyNoLog
	}
	if config.SourceRequireNoFilter {
		requiredProps |= stamps.ServerInformalPropertyNoFilter
	}
	for cfgSourceName, cfgSource := range config.SourcesConfig {
		if err := config.loadSource(proxy, requiredProps, cfgSourceName, &cfgSource); err != nil {
			return err
		}
	}
	if len(config.ServerNames) == 0 {
		for serverName := range config.StaticsConfig {
			config.ServerNames = append(config.ServerNames, serverName)
		}
	}
	for _, serverName := range config.ServerNames {
		staticConfig, ok := config.StaticsConfig[serverName]
		if !ok {
			continue
		}
		if len(staticConfig.Stamp) == 0 {
			dlog.Fatalf("Missing stamp for the static [%s] definition", serverName)
		}
		stamp, err := stamps.NewServerStampFromString(staticConfig.Stamp)
		if err != nil {
			dlog.Fatalf("Stamp error for the static [%s] definition: [%v]", serverName, err)
		}
		proxy.RegisteredServers = append(proxy.RegisteredServers,
			dnscrypt.RegisteredServer{Name: serverName, Stamp: stamp})
	}
	rand.Shuffle(len(proxy.RegisteredServers), func(i, j int) {
		proxy.RegisteredServers[i], proxy.RegisteredServers[j] = proxy.RegisteredServers[j], proxy.RegisteredServers[i]
	})

	return nil
}

func (config *Config) loadSource(proxy *dnscrypt.Proxy, requiredProps stamps.ServerInformalProperties, cfgSourceName string, cfgSource *SourceConfig) error {
	if len(cfgSource.URLs) == 0 {
		if len(cfgSource.URL) == 0 {
			dlog.Debugf("Missing URLs for source [%s]", cfgSourceName)
		} else {
			cfgSource.URLs = []string{cfgSource.URL}
		}
	}
	if cfgSource.MinisignKeyStr == "" {
		return fmt.Errorf("Missing Minisign key for source [%s]", cfgSourceName)
	}
	if cfgSource.CacheFile == "" {
		return fmt.Errorf("Missing cache file for source [%s]", cfgSourceName)
	}
	if cfgSource.FormatStr == "" {
		cfgSource.FormatStr = "v2"
	}
	if cfgSource.RefreshDelay <= 0 {
		cfgSource.RefreshDelay = 72
	}
	source, sourceUrlsToPrefetch, err := dnscrypt.NewSource(proxy.XTransport, cfgSource.URLs, cfgSource.MinisignKeyStr, cfgSource.CacheFile, cfgSource.FormatStr, time.Duration(cfgSource.RefreshDelay)*time.Hour)
	if err != nil {
		dlog.Criticalf("Unable to retrieve source [%s]: [%s]", cfgSourceName, err)
		return err
	}
	proxy.URLsToPrefetch = append(proxy.URLsToPrefetch, sourceUrlsToPrefetch...)
	registeredServers, err := source.Parse(cfgSource.Prefix)
	if err != nil {
		if len(registeredServers) == 0 {
			dlog.Criticalf("Unable to use source [%s]: [%s]", cfgSourceName, err)
			return err
		}
		dlog.Warnf("Error in source [%s]: [%s] -- Continuing with reduced server count [%d]", cfgSourceName, err, len(registeredServers))
	}
	for _, registeredServer := range registeredServers {
		if registeredServer.Stamp.Proto != stamps.StampProtoTypeDNSCryptRelay {
			if len(config.ServerNames) > 0 {
				if !includesName(config.ServerNames, registeredServer.Name) {
					continue
				}
			} else if registeredServer.Stamp.Props&requiredProps != requiredProps {
				continue
			}
		}
		if includesName(config.DisabledServerNames, registeredServer.Name) {
			continue
		}
		if config.SourceIPv4 || config.SourceIPv6 {
			isIPv4, isIPv6 := true, false
			if registeredServer.Stamp.Proto == stamps.StampProtoTypeDoH {
				isIPv4, isIPv6 = true, true
			}
			if strings.HasPrefix(registeredServer.Stamp.ServerAddrStr, "[") {
				isIPv4, isIPv6 = false, true
			}
			if !(config.SourceIPv4 == isIPv4 || config.SourceIPv6 == isIPv6) {
				continue
			}
		}
		if registeredServer.Stamp.Proto == stamps.StampProtoTypeDNSCryptRelay {
			dlog.Debugf("Adding [%s] to the set of available relays", registeredServer.Name)
			proxy.RegisteredRelays = append(proxy.RegisteredRelays, registeredServer)
		} else {
			if !((config.SourceDNSCrypt && registeredServer.Stamp.Proto == stamps.StampProtoTypeDNSCrypt) ||
				(config.SourceDoH && registeredServer.Stamp.Proto == stamps.StampProtoTypeDoH)) {
				continue
			}
			dlog.Debugf("Adding [%s] to the set of wanted resolvers", registeredServer.Name)
			proxy.RegisteredServers = append(proxy.RegisteredServers, registeredServer)
		}
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

func cdFileDir(fileName string) {
	os.Chdir(filepath.Dir(fileName))
}

func cdLocal() {
	exeFileName, err := os.Executable()
	if err != nil {
		dlog.Warnf("Unable to determine the executable directory: [%s] -- You will need to specify absolute paths in the configuration file", err)
		return
	}
	os.Chdir(filepath.Dir(exeFileName))
}
