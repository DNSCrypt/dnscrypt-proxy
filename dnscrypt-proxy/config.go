package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	netproxy "golang.org/x/net/proxy"
)

const (
	MaxTimeout             = 3600
	DefaultNetprobeAddress = "9.9.9.9:53"
)

type Config struct {
	LogLevel                 int            `toml:"log_level"`
	LogFile                  *string        `toml:"log_file"`
	LogFileLatest            bool           `toml:"log_file_latest"`
	UseSyslog                bool           `toml:"use_syslog"`
	ServerNames              []string       `toml:"server_names"`
	DisabledServerNames      []string       `toml:"disabled_server_names"`
	ListenAddresses          []string       `toml:"listen_addresses"`
	LocalDoH                 LocalDoHConfig `toml:"local_doh"`
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
	BlockUnqualified         bool   `toml:"block_unqualified"`
	BlockUndelegated         bool   `toml:"block_undelegated"`
	Cache                    bool
	CacheSize                int                         `toml:"cache_size"`
	CacheNegTTL              uint32                      `toml:"cache_neg_ttl"`
	CacheNegMinTTL           uint32                      `toml:"cache_neg_min_ttl"`
	CacheNegMaxTTL           uint32                      `toml:"cache_neg_max_ttl"`
	CacheMinTTL              uint32                      `toml:"cache_min_ttl"`
	CacheMaxTTL              uint32                      `toml:"cache_max_ttl"`
	RejectTTL                uint32                      `toml:"reject_ttl"`
	CloakTTL                 uint32                      `toml:"cloak_ttl"`
	QueryLog                 QueryLogConfig              `toml:"query_log"`
	NxLog                    NxLogConfig                 `toml:"nx_log"`
	BlockName                BlockNameConfig             `toml:"blocked_names"`
	BlockNameLegacy          BlockNameConfigLegacy       `toml:"blacklist"`
	WhitelistNameLegacy      WhitelistNameConfigLegacy   `toml:"whitelist"`
	AllowedName              AllowedNameConfig           `toml:"allowed_names"`
	BlockIP                  BlockIPConfig               `toml:"blocked_ips"`
	BlockIPLegacy            BlockIPConfigLegacy         `toml:"ip_blacklist"`
	AllowIP                  AllowIPConfig               `toml:"allowed_ips"`
	ForwardFile              string                      `toml:"forwarding_rules"`
	CloakFile                string                      `toml:"cloaking_rules"`
	CaptivePortals           CaptivePortalsConfig        `toml:"captive_portals"`
	StaticsConfig            map[string]StaticConfig     `toml:"static"`
	SourcesConfig            map[string]SourceConfig     `toml:"sources"`
	BrokenImplementations    BrokenImplementationsConfig `toml:"broken_implementations"`
	SourceRequireDNSSEC      bool                        `toml:"require_dnssec"`
	SourceRequireNoLog       bool                        `toml:"require_nolog"`
	SourceRequireNoFilter    bool                        `toml:"require_nofilter"`
	SourceDNSCrypt           bool                        `toml:"dnscrypt_servers"`
	SourceDoH                bool                        `toml:"doh_servers"`
	SourceIPv4               bool                        `toml:"ipv4_servers"`
	SourceIPv6               bool                        `toml:"ipv6_servers"`
	MaxClients               uint32                      `toml:"max_clients"`
	FallbackResolver         string                      `toml:"fallback_resolver"`
	FallbackResolvers        []string                    `toml:"fallback_resolvers"`
	IgnoreSystemDNS          bool                        `toml:"ignore_system_dns"`
	AllWeeklyRanges          map[string]WeeklyRangesStr  `toml:"schedules"`
	LogMaxSize               int                         `toml:"log_files_max_size"`
	LogMaxAge                int                         `toml:"log_files_max_age"`
	LogMaxBackups            int                         `toml:"log_files_max_backups"`
	TLSDisableSessionTickets bool                        `toml:"tls_disable_session_tickets"`
	TLSCipherSuite           []uint16                    `toml:"tls_cipher_suite"`
	NetprobeAddress          string                      `toml:"netprobe_address"`
	NetprobeTimeout          int                         `toml:"netprobe_timeout"`
	OfflineMode              bool                        `toml:"offline_mode"`
	HTTPProxyURL             string                      `toml:"http_proxy"`
	RefusedCodeInResponses   bool                        `toml:"refused_code_in_responses"`
	BlockedQueryResponse     string                      `toml:"blocked_query_response"`
	QueryMeta                []string                    `toml:"query_meta"`
	AnonymizedDNS            AnonymizedDNSConfig         `toml:"anonymized_dns"`
	DoHClientX509Auth        DoHClientX509AuthConfig     `toml:"doh_client_x509_auth"`
	DoHClientX509AuthLegacy  DoHClientX509AuthConfig     `toml:"tls_client_auth"`
	DNS64                    DNS64Config                 `toml:"dns64"`
	EDNSClientSubnet         []string                    `toml:"edns_client_subnet"`
}

func newConfig() Config {
	return Config{
		LogLevel:                 int(dlog.LogLevel()),
		LogFileLatest:            true,
		ListenAddresses:          []string{"127.0.0.1:53"},
		LocalDoH:                 LocalDoHConfig{Path: "/dns-query"},
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
		FallbackResolvers:        []string{DefaultFallbackResolver},
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
		BrokenImplementations: BrokenImplementationsConfig{
			FragmentsBlocked: []string{
				"cisco", "cisco-ipv6", "cisco-familyshield", "cisco-familyshield-ipv6",
				"cleanbrowsing-adult", "cleanbrowsing-adult-ipv6", "cleanbrowsing-family", "cleanbrowsing-family-ipv6", "cleanbrowsing-security", "cleanbrowsing-security-ipv6",
			},
		},
		AnonymizedDNS: AnonymizedDNSConfig{
			DirectCertFallback: true,
			RelayRandomization: false,
		},
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
	File    string `toml:"blocked_names_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

type BlockNameConfigLegacy struct {
	File    string `toml:"blacklist_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

type WhitelistNameConfigLegacy struct {
	File    string `toml:"whitelist_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

type AllowedNameConfig struct {
	File    string `toml:"allowed_names_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

type BlockIPConfig struct {
	File    string `toml:"blocked_ips_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

type BlockIPConfigLegacy struct {
	File    string `toml:"blacklist_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

type AllowIPConfig struct {
	File    string `toml:"allowed_ips_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

type AnonymizedDNSRouteConfig struct {
	ServerName string   `toml:"server_name"`
	RelayNames []string `toml:"via"`
}

type AnonymizedDNSConfig struct {
	Routes             []AnonymizedDNSRouteConfig `toml:"routes"`
	SkipIncompatible   bool                       `toml:"skip_incompatible"`
	DirectCertFallback bool                       `toml:"direct_cert_fallback"`
	RelayRandomization bool                       `toml:"relay_randomization"`
}

type BrokenImplementationsConfig struct {
	BrokenQueryPadding []string `toml:"broken_query_padding"`
	FragmentsBlocked   []string `toml:"fragments_blocked"`
}

type LocalDoHConfig struct {
	ListenAddresses []string `toml:"listen_addresses"`
	Path            string   `toml:"path"`
	CertFile        string   `toml:"cert_file"`
	CertKeyFile     string   `toml:"cert_key_file"`
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

type TLSClientAuthCredsConfig struct {
	ServerName string `toml:"server_name"`
	ClientCert string `toml:"client_cert"`
	ClientKey  string `toml:"client_key"`
	RootCA     string `toml:"root_ca"`
}

type DoHClientX509AuthConfig struct {
	Creds []TLSClientAuthCredsConfig `toml:"creds"`
}

type DNS64Config struct {
	Prefixes  []string `toml:"prefix"`
	Resolvers []string `toml:"resolver"`
}

type CaptivePortalsConfig struct {
	MapFile string `toml:"map_file"`
}

type ConfigFlags struct {
	Resolve                 *string
	List                    *bool
	ListAll                 *bool
	JSONOutput              *bool
	Check                   *bool
	ConfigFile              *string
	Child                   *bool
	NetprobeTimeoutOverride *int
	ShowCerts               *bool
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

func ConfigLoad(proxy *Proxy, flags *ConfigFlags) error {
	foundConfigFile, err := findConfigFile(flags.ConfigFile)
	if err != nil {
		return fmt.Errorf("Unable to load the configuration file [%s] -- Maybe use the -config command-line switch?", *flags.ConfigFile)
	}
	config := newConfig()
	md, err := toml.DecodeFile(foundConfigFile, &config)
	if err != nil {
		return err
	}

	if flags.Resolve != nil && len(*flags.Resolve) > 0 {
		addr := "127.0.0.1:53"
		if len(config.ListenAddresses) > 0 {
			addr = config.ListenAddresses[0]
		}
		Resolve(addr, *flags.Resolve, len(config.ServerNames) == 1)
		os.Exit(0)
	}

	if err := cdFileDir(foundConfigFile); err != nil {
		return err
	}
	if config.LogLevel >= 0 && config.LogLevel < int(dlog.SeverityLast) {
		dlog.SetLogLevel(dlog.Severity(config.LogLevel))
	}
	if dlog.LogLevel() <= dlog.SeverityDebug && os.Getenv("DEBUG") == "" {
		dlog.SetLogLevel(dlog.SeverityInfo)
	}
	dlog.TruncateLogFile(config.LogFileLatest)
	if config.UseSyslog {
		dlog.UseSyslog(true)
	} else if config.LogFile != nil {
		dlog.UseLogFile(*config.LogFile)
		if !*flags.Child {
			FileDescriptors = append(FileDescriptors, dlog.GetFileDescriptor())
		} else {
			FileDescriptorNum++
			dlog.SetFileDescriptor(os.NewFile(uintptr(3), "logFile"))
		}
	}
	if !*flags.Child {
		dlog.Noticef("dnscrypt-proxy %s", AppVersion)
	}
	undecoded := md.Undecoded()
	if len(undecoded) > 0 {
		return fmt.Errorf("Unsupported key in configuration file: [%s]", undecoded[0])
	}

	proxy.logMaxSize = config.LogMaxSize
	proxy.logMaxAge = config.LogMaxAge
	proxy.logMaxBackups = config.LogMaxBackups

	proxy.userName = config.UserName

	proxy.child = *flags.Child
	proxy.xTransport = NewXTransport()
	proxy.xTransport.tlsDisableSessionTickets = config.TLSDisableSessionTickets
	proxy.xTransport.tlsCipherSuite = config.TLSCipherSuite
	proxy.xTransport.mainProto = proxy.mainProto
	if len(config.FallbackResolver) > 0 {
		config.FallbackResolvers = []string{config.FallbackResolver}
	}
	if len(config.FallbackResolvers) > 0 {
		for _, resolver := range config.FallbackResolvers {
			if err := isIPAndPort(resolver); err != nil {
				return fmt.Errorf("Fallback resolver [%v]: %v", resolver, err)
			}
		}
		proxy.xTransport.ignoreSystemDNS = config.IgnoreSystemDNS
	}
	proxy.xTransport.fallbackResolvers = config.FallbackResolvers
	proxy.xTransport.useIPv4 = config.SourceIPv4
	proxy.xTransport.useIPv6 = config.SourceIPv6
	proxy.xTransport.keepAlive = time.Duration(config.KeepAlive) * time.Second
	if len(config.HTTPProxyURL) > 0 {
		httpProxyURL, err := url.Parse(config.HTTPProxyURL)
		if err != nil {
			return fmt.Errorf("Unable to parse the HTTP proxy URL [%v]", config.HTTPProxyURL)
		}
		proxy.xTransport.httpProxyFunction = http.ProxyURL(httpProxyURL)
	}

	if len(config.Proxy) > 0 {
		proxyDialerURL, err := url.Parse(config.Proxy)
		if err != nil {
			return fmt.Errorf("Unable to parse the proxy URL [%v]", config.Proxy)
		}
		proxyDialer, err := netproxy.FromURL(proxyDialerURL, netproxy.Direct)
		if err != nil {
			return fmt.Errorf("Unable to use the proxy: [%v]", err)
		}
		proxy.xTransport.proxyDialer = &proxyDialer
		proxy.mainProto = "tcp"
	}

	proxy.xTransport.rebuildTransport()

	if md.IsDefined("refused_code_in_responses") {
		dlog.Notice("config option `refused_code_in_responses` is deprecated, use `blocked_query_response`")
		if config.RefusedCodeInResponses {
			config.BlockedQueryResponse = "refused"
		} else {
			config.BlockedQueryResponse = "hinfo"
		}
	}
	proxy.blockedQueryResponse = config.BlockedQueryResponse
	proxy.timeout = time.Duration(config.Timeout) * time.Millisecond
	proxy.maxClients = config.MaxClients
	proxy.mainProto = "udp"
	if config.ForceTCP {
		proxy.mainProto = "tcp"
	}
	proxy.certRefreshDelay = time.Duration(Max(60, config.CertRefreshDelay)) * time.Minute
	proxy.certRefreshDelayAfterFailure = time.Duration(10 * time.Second)
	proxy.certIgnoreTimestamp = config.CertIgnoreTimestamp
	proxy.ephemeralKeys = config.EphemeralKeys
	if len(config.ListenAddresses) == 0 && len(config.LocalDoH.ListenAddresses) == 0 {
		dlog.Debug("No local IP/port configured")
	}
	lbStrategy := LBStrategy(DefaultLBStrategy)
	switch lbStrategyStr := strings.ToLower(config.LBStrategy); lbStrategyStr {
	case "":
		// default
	case "p2":
		lbStrategy = LBStrategyP2{}
	case "ph":
		lbStrategy = LBStrategyPH{}
	case "fastest":
	case "first":
		lbStrategy = LBStrategyFirst{}
	case "random":
		lbStrategy = LBStrategyRandom{}
	default:
		if strings.HasPrefix(lbStrategyStr, "p") {
			n, err := strconv.ParseInt(strings.TrimPrefix(lbStrategyStr, "p"), 10, 32)
			if err != nil || n <= 0 {
				dlog.Warnf("Invalid load balancing strategy: [%s]", config.LBStrategy)
			} else {
				lbStrategy = LBStrategyPN{n: int(n)}
			}
		} else {
			dlog.Warnf("Unknown load balancing strategy: [%s]", config.LBStrategy)
		}
	}
	proxy.serversInfo.lbStrategy = lbStrategy
	proxy.serversInfo.lbEstimator = config.LBEstimator

	proxy.listenAddresses = config.ListenAddresses
	proxy.localDoHListenAddresses = config.LocalDoH.ListenAddresses
	if len(config.LocalDoH.Path) > 0 && config.LocalDoH.Path[0] != '/' {
		return fmt.Errorf("local DoH: [%s] cannot be a valid URL path. Read the documentation", config.LocalDoH.Path)
	}
	proxy.localDoHPath = config.LocalDoH.Path
	proxy.localDoHCertFile = config.LocalDoH.CertFile
	proxy.localDoHCertKeyFile = config.LocalDoH.CertKeyFile
	proxy.daemonize = config.Daemonize
	proxy.pluginBlockIPv6 = config.BlockIPv6
	proxy.pluginBlockUnqualified = config.BlockUnqualified
	proxy.pluginBlockUndelegated = config.BlockUndelegated
	proxy.cache = config.Cache
	proxy.cacheSize = config.CacheSize

	if config.CacheNegTTL > 0 {
		proxy.cacheNegMinTTL = config.CacheNegTTL
		proxy.cacheNegMaxTTL = config.CacheNegTTL
	} else {
		proxy.cacheNegMinTTL = config.CacheNegMinTTL
		proxy.cacheNegMaxTTL = config.CacheNegMaxTTL
	}

	proxy.cacheMinTTL = config.CacheMinTTL
	proxy.cacheMaxTTL = config.CacheMaxTTL
	proxy.rejectTTL = config.RejectTTL
	proxy.cloakTTL = config.CloakTTL

	proxy.queryMeta = config.QueryMeta

	if len(config.EDNSClientSubnet) != 0 {
		proxy.ednsClientSubnets = make([]*net.IPNet, 0)
		for _, cidr := range config.EDNSClientSubnet {
			_, net, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("Invalid EDNS-client-subnet CIDR: [%v]", cidr)
			}
			proxy.ednsClientSubnets = append(proxy.ednsClientSubnets, net)
		}
	}

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

	if len(config.BlockName.File) > 0 && len(config.BlockNameLegacy.File) > 0 {
		return errors.New("Don't specify both [blocked_names] and [blacklist] sections - Update your config file")
	}
	if len(config.BlockNameLegacy.File) > 0 {
		dlog.Notice("Use of [blacklist] is deprecated - Update your config file")
		config.BlockName.File = config.BlockNameLegacy.File
		config.BlockName.Format = config.BlockNameLegacy.Format
		config.BlockName.LogFile = config.BlockNameLegacy.LogFile
	}
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

	if len(config.AllowedName.File) > 0 && len(config.WhitelistNameLegacy.File) > 0 {
		return errors.New("Don't specify both [whitelist] and [allowed_names] sections - Update your config file")
	}
	if len(config.WhitelistNameLegacy.File) > 0 {
		dlog.Notice("Use of [whitelist] is deprecated - Update your config file")
		config.AllowedName.File = config.WhitelistNameLegacy.File
		config.AllowedName.Format = config.WhitelistNameLegacy.Format
		config.AllowedName.LogFile = config.WhitelistNameLegacy.LogFile
	}
	if len(config.AllowedName.Format) == 0 {
		config.AllowedName.Format = "tsv"
	} else {
		config.AllowedName.Format = strings.ToLower(config.AllowedName.Format)
	}
	if config.AllowedName.Format != "tsv" && config.AllowedName.Format != "ltsv" {
		return errors.New("Unsupported allowed_names log format")
	}
	proxy.whitelistNameFile = config.AllowedName.File
	proxy.whitelistNameFormat = config.AllowedName.Format
	proxy.whitelistNameLogFile = config.AllowedName.LogFile

	if len(config.BlockIP.File) > 0 && len(config.BlockIPLegacy.File) > 0 {
		return errors.New("Don't specify both [blocked_ips] and [ip_blacklist] sections - Update your config file")
	}
	if len(config.BlockIPLegacy.File) > 0 {
		dlog.Notice("Use of [ip_blacklist] is deprecated - Update your config file")
		config.BlockIP.File = config.BlockIPLegacy.File
		config.BlockIP.Format = config.BlockIPLegacy.Format
		config.BlockIP.LogFile = config.BlockIPLegacy.LogFile
	}
	if len(config.BlockIP.Format) == 0 {
		config.BlockIP.Format = "tsv"
	} else {
		config.BlockIP.Format = strings.ToLower(config.BlockIP.Format)
	}
	if config.BlockIP.Format != "tsv" && config.BlockIP.Format != "ltsv" {
		return errors.New("Unsupported IP block log format")
	}
	proxy.blockIPFile = config.BlockIP.File
	proxy.blockIPFormat = config.BlockIP.Format
	proxy.blockIPLogFile = config.BlockIP.LogFile

	if len(config.AllowIP.Format) == 0 {
		config.AllowIP.Format = "tsv"
	} else {
		config.AllowIP.Format = strings.ToLower(config.AllowIP.Format)
	}
	if config.AllowIP.Format != "tsv" && config.AllowIP.Format != "ltsv" {
		return errors.New("Unsupported allowed_ips log format")
	}
	proxy.allowedIPFile = config.AllowIP.File
	proxy.allowedIPFormat = config.AllowIP.Format
	proxy.allowedIPLogFile = config.AllowIP.LogFile

	proxy.forwardFile = config.ForwardFile
	proxy.cloakFile = config.CloakFile
	proxy.captivePortalMapFile = config.CaptivePortals.MapFile

	allWeeklyRanges, err := ParseAllWeeklyRanges(config.AllWeeklyRanges)
	if err != nil {
		return err
	}
	proxy.allWeeklyRanges = allWeeklyRanges

	if configRoutes := config.AnonymizedDNS.Routes; configRoutes != nil {
		routes := make(map[string][]string)
		for _, configRoute := range configRoutes {
			routes[configRoute.ServerName] = configRoute.RelayNames
		}
		proxy.routes = &routes
	}
	proxy.skipAnonIncompatibleResolvers = config.AnonymizedDNS.SkipIncompatible
	proxy.anonDirectCertFallback = config.AnonymizedDNS.DirectCertFallback
	proxy.anonRelayRandomization = config.AnonymizedDNS.RelayRandomization

	if config.DoHClientX509AuthLegacy.Creds != nil {
		return errors.New("[tls_client_auth] has been renamed to [doh_client_x509_auth] - Update your config file")
	}
	configClientCreds := config.DoHClientX509Auth.Creds
	creds := make(map[string]DOHClientCreds)
	for _, configClientCred := range configClientCreds {
		credFiles := DOHClientCreds{
			clientCert: configClientCred.ClientCert,
			clientKey:  configClientCred.ClientKey,
			rootCA:     configClientCred.RootCA,
		}
		creds[configClientCred.ServerName] = credFiles
	}
	proxy.dohCreds = &creds

	// Backwards compatibility
	config.BrokenImplementations.FragmentsBlocked = append(config.BrokenImplementations.FragmentsBlocked, config.BrokenImplementations.BrokenQueryPadding...)

	proxy.serversBlockingFragments = config.BrokenImplementations.FragmentsBlocked

	proxy.dns64Prefixes = config.DNS64.Prefixes
	proxy.dns64Resolvers = config.DNS64.Resolvers

	if *flags.ListAll {
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
	proxy.requiredProps = requiredProps
	proxy.ServerNames = config.ServerNames
	proxy.DisabledServerNames = config.DisabledServerNames
	proxy.SourceIPv4 = config.SourceIPv4
	proxy.SourceIPv6 = config.SourceIPv6
	proxy.SourceDNSCrypt = config.SourceDNSCrypt
	proxy.SourceDoH = config.SourceDoH

	netprobeTimeout := config.NetprobeTimeout
	flag.Visit(func(flag *flag.Flag) {
		if flag.Name == "netprobe-timeout" && flags.NetprobeTimeoutOverride != nil {
			netprobeTimeout = *flags.NetprobeTimeoutOverride
		}
	})
	netprobeAddress := DefaultNetprobeAddress
	if len(config.NetprobeAddress) > 0 {
		netprobeAddress = config.NetprobeAddress
	} else if len(config.FallbackResolvers) > 0 {
		netprobeAddress = config.FallbackResolvers[0]
	}
	proxy.showCerts = *flags.ShowCerts || len(os.Getenv("SHOW_CERTS")) > 0
	if !*flags.Check && !*flags.ShowCerts && !*flags.List && !*flags.ListAll {
		if err := NetProbe(proxy, netprobeAddress, netprobeTimeout); err != nil {
			return err
		}
		for _, listenAddrStr := range proxy.listenAddresses {
			proxy.addDNSListener(listenAddrStr)
		}
		for _, listenAddrStr := range proxy.localDoHListenAddresses {
			proxy.addLocalDoHListener(listenAddrStr)
		}
		if err := proxy.addSystemDListeners(); err != nil {
			return err
		}
	}
	// if 'userName' is set and we are the parent process drop privilege and exit
	if len(proxy.userName) > 0 && !proxy.child {
		proxy.dropPrivilege(proxy.userName, FileDescriptors)
		return errors.New("Dropping privileges is not supporting on this operating system. Unset `user_name` in the configuration file")
	}
	if !config.OfflineMode {
		if err := config.loadSources(proxy); err != nil {
			return err
		}
		if len(proxy.registeredServers) == 0 {
			return errors.New("No servers configured")
		}
	}
	if *flags.List || *flags.ListAll {
		if err := config.printRegisteredServers(proxy, *flags.JSONOutput); err != nil {
			return err
		}
		os.Exit(0)
	}
	if proxy.routes != nil && len(*proxy.routes) > 0 {
		hasSpecificRoutes := false
		for _, server := range proxy.registeredServers {
			if via, ok := (*proxy.routes)[server.name]; ok {
				if server.stamp.Proto != stamps.StampProtoTypeDNSCrypt {
					dlog.Errorf("DNS anonymization is only supported with the DNSCrypt protocol - Connections to [%v] cannot be anonymized", server.name)
				} else {
					dlog.Noticef("Anonymized DNS: routing [%v] via %v", server.name, via)
				}
				hasSpecificRoutes = true
			}
		}
		if via, ok := (*proxy.routes)["*"]; ok {
			if hasSpecificRoutes {
				dlog.Noticef("Anonymized DNS: routing everything else via %v", via)
			} else {
				dlog.Noticef("Anonymized DNS: routing everything via %v", via)
			}
		}
		if proxy.anonRelayRandomization {
			dlog.Noticef("Anonymized DNS: relay randomization turned on")
		}
	}
	if *flags.Check {
		dlog.Notice("Configuration successfully checked")
		os.Exit(0)
	}
	return nil
}

func (config *Config) printRegisteredServers(proxy *Proxy, jsonOutput bool) error {
	var summary []ServerSummary
	for _, registeredServer := range proxy.registeredServers {
		addrStr, port := registeredServer.stamp.ServerAddrStr, stamps.DefaultPort
		var hostAddr string
		hostAddr, port = ExtractHostAndPort(addrStr, port)
		addrs := make([]string, 0)
		if registeredServer.stamp.Proto == stamps.StampProtoTypeDoH && len(registeredServer.stamp.ProviderName) > 0 {
			providerName := registeredServer.stamp.ProviderName
			var host string
			host, port = ExtractHostAndPort(providerName, port)
			addrs = append(addrs, host)
		}
		if len(addrStr) > 0 {
			addrs = append(addrs, hostAddr)
		}
		serverSummary := ServerSummary{
			Name:        registeredServer.name,
			Proto:       registeredServer.stamp.Proto.String(),
			IPv6:        strings.HasPrefix(addrStr, "["),
			Ports:       []int{port},
			Addrs:       addrs,
			DNSSEC:      registeredServer.stamp.Props&stamps.ServerInformalPropertyDNSSEC != 0,
			NoLog:       registeredServer.stamp.Props&stamps.ServerInformalPropertyNoLog != 0,
			NoFilter:    registeredServer.stamp.Props&stamps.ServerInformalPropertyNoFilter != 0,
			Description: registeredServer.description,
			Stamp:       registeredServer.stamp.String(),
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
			return err
		}
		fmt.Print(string(jsonStr))
	}
	return nil
}

func (config *Config) loadSources(proxy *Proxy) error {
	for cfgSourceName, cfgSource_ := range config.SourcesConfig {
		cfgSource := cfgSource_
		if err := config.loadSource(proxy, cfgSourceName, &cfgSource); err != nil {
			return err
		}
	}
	for name, config := range config.StaticsConfig {
		if stamp, err := stamps.NewServerStampFromString(config.Stamp); err == nil {
			if stamp.Proto == stamps.StampProtoTypeDNSCryptRelay || stamp.Proto == stamps.StampProtoTypeODoHRelay {
				dlog.Debugf("Adding [%s] to the set of available static relays", name)
				registeredServer := RegisteredServer{name: name, stamp: stamp, description: "static relay"}
				proxy.registeredRelays = append(proxy.registeredRelays, registeredServer)
			}
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
			return fmt.Errorf("Missing stamp for the static [%s] definition", serverName)
		}
		stamp, err := stamps.NewServerStampFromString(staticConfig.Stamp)
		if err != nil {
			return fmt.Errorf("Stamp error for the static [%s] definition: [%v]", serverName, err)
		}
		proxy.registeredServers = append(proxy.registeredServers, RegisteredServer{name: serverName, stamp: stamp})
	}
	proxy.updateRegisteredServers()
	rs1 := proxy.registeredServers
	rs2 := proxy.serversInfo.registeredServers
	rand.Shuffle(len(rs1), func(i, j int) {
		rs1[i], rs1[j] = rs1[j], rs1[i]
	})
	rand.Shuffle(len(rs2), func(i, j int) {
		rs2[i], rs2[j] = rs2[j], rs2[i]
	})
	return nil
}

func (config *Config) loadSource(proxy *Proxy, cfgSourceName string, cfgSource *SourceConfig) error {
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
	} else if cfgSource.RefreshDelay > 168 {
		cfgSource.RefreshDelay = 168
	}
	source, err := NewSource(cfgSourceName, proxy.xTransport, cfgSource.URLs, cfgSource.MinisignKeyStr, cfgSource.CacheFile, cfgSource.FormatStr, time.Duration(cfgSource.RefreshDelay)*time.Hour, cfgSource.Prefix)
	if err != nil {
		if len(source.in) <= 0 {
			dlog.Criticalf("Unable to retrieve source [%s]: [%s]", cfgSourceName, err)
			return err
		}
		dlog.Infof("Downloading [%s] failed: %v, using cache file to startup", source.name, err)
	}
	proxy.sources = append(proxy.sources, source)
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

func cdFileDir(fileName string) error {
	return os.Chdir(filepath.Dir(fileName))
}

func cdLocal() {
	exeFileName, err := os.Executable()
	if err != nil {
		dlog.Warnf("Unable to determine the executable directory: [%s] -- You will need to specify absolute paths in the configuration file", err)
	} else if err := os.Chdir(filepath.Dir(exeFileName)); err != nil {
		dlog.Warnf("Unable to change working directory to [%s]: %s", exeFileName, err)
	}
}

func isIPAndPort(addrStr string) error {
	host, port := ExtractHostAndPort(addrStr, -1)
	if ip := ParseIP(host); ip == nil {
		return fmt.Errorf("Host does not parse as IP '%s'", addrStr)
	} else if port == -1 {
		return fmt.Errorf("Port missing '%s'", addrStr)
	} else if _, err := strconv.ParseUint(strconv.Itoa(port), 10, 16); err != nil {
		return fmt.Errorf("Port does not parse '%s' [%v]", addrStr, err)
	}
	return nil
}
