package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
)

const (
	MaxTimeout             = 3600
	DefaultNetprobeAddress = "9.9.9.9:53"
)

type Config struct {
	LogLevel                 int                `toml:"log_level"`
	LogFile                  *string            `toml:"log_file"`
	LogFileLatest            bool               `toml:"log_file_latest"`
	UseSyslog                bool               `toml:"use_syslog"`
	ServerNames              []string           `toml:"server_names"`
	DisabledServerNames      []string           `toml:"disabled_server_names"`
	ListenAddresses          []string           `toml:"listen_addresses"`
	LocalDoH                 LocalDoHConfig     `toml:"local_doh"`
	MonitoringUI             MonitoringUIConfig `toml:"monitoring_ui"`
	UserName                 string             `toml:"user_name"`
	ForceTCP                 bool               `toml:"force_tcp"`
	HTTP3                    bool               `toml:"http3"`
	HTTP3Probe               bool               `toml:"http3_probe"`
	Timeout                  int                `toml:"timeout"`
	KeepAlive                int                `toml:"keepalive"`
	Proxy                    string             `toml:"proxy"`
	CertRefreshConcurrency   int                `toml:"cert_refresh_concurrency"`
	CertRefreshDelay         int                `toml:"cert_refresh_delay"`
	CertIgnoreTimestamp      bool               `toml:"cert_ignore_timestamp"`
	EphemeralKeys            bool               `toml:"dnscrypt_ephemeral_keys"`
	LBStrategy               string             `toml:"lb_strategy"`
	LBEstimator              bool               `toml:"lb_estimator"`
	BlockIPv6                bool               `toml:"block_ipv6"`
	BlockUnqualified         bool               `toml:"block_unqualified"`
	BlockUndelegated         bool               `toml:"block_undelegated"`
	EnableHotReload          bool               `toml:"enable_hot_reload"`
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
	SourceODoH               bool                        `toml:"odoh_servers"`
	SourceIPv4               bool                        `toml:"ipv4_servers"`
	SourceIPv6               bool                        `toml:"ipv6_servers"`
	MaxClients               uint32                      `toml:"max_clients"`
	BootstrapResolversLegacy []string                    `toml:"fallback_resolvers"`
	BootstrapResolvers       []string                    `toml:"bootstrap_resolvers"`
	IgnoreSystemDNS          bool                        `toml:"ignore_system_dns"`
	AllWeeklyRanges          map[string]WeeklyRangesStr  `toml:"schedules"`
	LogMaxSize               int                         `toml:"log_files_max_size"`
	LogMaxAge                int                         `toml:"log_files_max_age"`
	LogMaxBackups            int                         `toml:"log_files_max_backups"`
	TLSDisableSessionTickets bool                        `toml:"tls_disable_session_tickets"`
	TLSCipherSuite           []uint16                    `toml:"tls_cipher_suite"`
	TLSKeyLogFile            string                      `toml:"tls_key_log_file"`
	NetprobeAddress          string                      `toml:"netprobe_address"`
	NetprobeTimeout          int                         `toml:"netprobe_timeout"`
	OfflineMode              bool                        `toml:"offline_mode"`
	HTTPProxyURL             string                      `toml:"http_proxy"`
	RefusedCodeInResponses   bool                        `toml:"refused_code_in_responses"`
	BlockedQueryResponse     string                      `toml:"blocked_query_response"`
	QueryMeta                []string                    `toml:"query_meta"`
	CloakedPTR               bool                        `toml:"cloak_ptr"`
	AnonymizedDNS            AnonymizedDNSConfig         `toml:"anonymized_dns"`
	DoHClientX509Auth        DoHClientX509AuthConfig     `toml:"doh_client_x509_auth"`
	DoHClientX509AuthLegacy  DoHClientX509AuthConfig     `toml:"tls_client_auth"`
	DNS64                    DNS64Config                 `toml:"dns64"`
	EDNSClientSubnet         []string                    `toml:"edns_client_subnet"`
	IPEncryption             IPEncryptionConfig          `toml:"ip_encryption"`
}

func newConfig() Config {
	return Config{
		LogLevel:        int(dlog.LogLevel()),
		LogFileLatest:   true,
		ListenAddresses: []string{"127.0.0.1:53"},
		LocalDoH:        LocalDoHConfig{Path: "/dns-query"},
		MonitoringUI: MonitoringUIConfig{
			Enabled:        false,
			ListenAddress:  "127.0.0.1:8080",
			Username:       "admin", // Set to empty string to disable authentication
			Password:       "changeme",
			EnableQueryLog: false,
			PrivacyLevel:   2,
		},
		Timeout:                  5000,
		KeepAlive:                5,
		CertRefreshConcurrency:   10,
		CertRefreshDelay:         240,
		HTTP3:                    false,
		HTTP3Probe:               false,
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
		SourceODoH:               false,
		MaxClients:               250,
		BootstrapResolvers:       []string{DefaultBootstrapResolver},
		IgnoreSystemDNS:          false,
		LogMaxSize:               10,
		LogMaxAge:                7,
		LogMaxBackups:            1,
		TLSDisableSessionTickets: false,
		TLSCipherSuite:           nil,
		TLSKeyLogFile:            "",
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
		},
		CloakedPTR: false,
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
	DNSSEC      *bool    `json:"dnssec,omitempty"`
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

type IPEncryptionConfig struct {
	Key       string `toml:"key"`
	Algorithm string `toml:"algorithm"`
}

type CaptivePortalsConfig struct {
	MapFile string `toml:"map_file"`
}

type ConfigFlags struct {
	Resolve                 *string
	List                    *bool
	ListAll                 *bool
	IncludeRelays           *bool
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
		return fmt.Errorf(
			"Unable to load the configuration file [%s] -- Maybe use the -config command-line switch?",
			*flags.ConfigFile,
		)
	}
	WarnIfMaybeWritableByOtherUsers(foundConfigFile)
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

	// Check for unsupported keys in configuration
	undecoded := md.Undecoded()
	if len(undecoded) > 0 {
		return fmt.Errorf("Unsupported key in configuration file: [%s]", undecoded[0])
	}

	// Set up basic proxy properties
	proxy.showCerts = *flags.ShowCerts || len(os.Getenv("SHOW_CERTS")) > 0
	proxy.logMaxSize = config.LogMaxSize
	proxy.logMaxAge = config.LogMaxAge
	proxy.logMaxBackups = config.LogMaxBackups
	proxy.userName = config.UserName
	proxy.child = *flags.Child
	proxy.enableHotReload = config.EnableHotReload
	proxy.xTransport = NewXTransport()

	// Configure logging
	configureLogging(proxy, flags, &config)

	// Configure XTransport
	if err := configureXTransport(proxy, &config); err != nil {
		return err
	}

	// Configure DoH client authentication
	if err := configureDoHClientAuth(proxy, &config); err != nil {
		return err
	}

	// Configure server parameters
	configureServerParams(proxy, &config)

	// Configure load balancing
	configureLoadBalancing(proxy, &config)

	// Configure plugins
	configurePlugins(proxy, &config)

	// Configure EDNS client subnet
	if err := configureEDNSClientSubnet(proxy, &config); err != nil {
		return err
	}

	// Configure query logging
	if err := configureQueryLog(proxy, &config); err != nil {
		return err
	}

	// Configure NX domain logging
	if err := configureNXLog(proxy, &config); err != nil {
		return err
	}

	// Configure blocked names
	if err := configureBlockedNames(proxy, &config); err != nil {
		return err
	}

	// Configure allowed names
	if err := configureAllowedNames(proxy, &config); err != nil {
		return err
	}

	// Configure blocked IPs
	if err := configureBlockedIPs(proxy, &config); err != nil {
		return err
	}

	// Configure allowed IPs
	if err := configureAllowedIPs(proxy, &config); err != nil {
		return err
	}

	// Configure additional files
	configureAdditionalFiles(proxy, &config)

	// Configure weekly ranges
	if err := configureWeeklyRanges(proxy, &config); err != nil {
		return err
	}

	// Configure anonymized DNS
	configureAnonymizedDNS(proxy, &config)

	// Configure broken implementations
	configureBrokenImplementations(proxy, &config)

	// Configure DNS64
	configureDNS64(proxy, &config)

	// Configure IP encryption
	if err := configureIPEncryption(proxy, &config); err != nil {
		return err
	}

	// Configure source restrictions
	configureSourceRestrictions(proxy, flags, &config)

	// Initialize networking
	if err := initializeNetworking(proxy, flags, &config); err != nil {
		return err
	}

	// if 'userName' is set and we are the parent process drop privilege and exit
	if len(proxy.userName) > 0 && !proxy.child {
		proxy.dropPrivilege(proxy.userName, FileDescriptors)
		return errors.New(
			"Dropping privileges is not supported on this operating system. Unset `user_name` in the configuration file",
		)
	}

	// Load sources and verify servers
	if !config.OfflineMode {
		if err := config.loadSources(proxy); err != nil {
			return err
		}
		if len(proxy.registeredServers) == 0 {
			return errors.New("None of the servers listed in the server_names list were found in the configured sources.")
		}
	}

	// Handle listing servers if requested
	if *flags.List || *flags.ListAll {
		if err := config.printRegisteredServers(proxy, *flags.JSONOutput, *flags.IncludeRelays); err != nil {
			return err
		}
		os.Exit(0)
	}

	// Log anonymized DNS routes
	if proxy.routes != nil && len(*proxy.routes) > 0 {
		hasSpecificRoutes := false
		for _, server := range proxy.registeredServers {
			if via, ok := (*proxy.routes)[server.name]; ok {
				if server.stamp.Proto != stamps.StampProtoTypeDNSCrypt &&
					server.stamp.Proto != stamps.StampProtoTypeODoHTarget {
					dlog.Errorf(
						"DNS anonymization is only supported with the DNSCrypt and ODoH protocols - Connections to [%v] cannot be anonymized",
						server.name,
					)
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
	}

	// Exit if just checking configuration
	if *flags.Check {
		dlog.Notice("Configuration successfully checked")
		os.Exit(0)
	}

	return nil
}

// GetRefusedFlag - Returns whether the config has defined refused_code_in_responses
func (config *Config) GetRefusedFlag(configFile string) (bool, bool) {
	var refused bool
	md, err := toml.DecodeFile(configFile, &refused)
	if err != nil {
		return false, false
	}
	return refused, md.IsDefined("refused_code_in_responses")
}

// configureBrokenImplementations - Helper function for IsDefined check
func configureBrokenImplementations(proxy *Proxy, config *Config) {
	// Backwards compatibility
	config.BrokenImplementations.FragmentsBlocked = append(
		config.BrokenImplementations.FragmentsBlocked,
		config.BrokenImplementations.BrokenQueryPadding...)

	proxy.serversBlockingFragments = config.BrokenImplementations.FragmentsBlocked
}

// configureDNS64 - Helper function for DNS64
func configureDNS64(proxy *Proxy, config *Config) {
	proxy.dns64Prefixes = config.DNS64.Prefixes
	proxy.dns64Resolvers = config.DNS64.Resolvers
}

// configureIPEncryption - Helper function for IP encryption
func configureIPEncryption(proxy *Proxy, config *Config) error {
	ipCryptConfig, err := NewIPCryptConfig(
		config.IPEncryption.Key,
		config.IPEncryption.Algorithm,
	)
	if err != nil {
		return fmt.Errorf("IP encryption configuration error: %w", err)
	}
	proxy.ipCryptConfig = ipCryptConfig
	return nil
}

func (config *Config) printRegisteredServers(proxy *Proxy, jsonOutput bool, includeRelays bool) error {
	var summary []ServerSummary
	if includeRelays {
		for _, registeredRelay := range proxy.registeredRelays {
			addrStr, port := registeredRelay.stamp.ServerAddrStr, stamps.DefaultPort
			var hostAddr string
			hostAddr, port = ExtractHostAndPort(addrStr, port)
			addrs := make([]string, 0)
			if (registeredRelay.stamp.Proto == stamps.StampProtoTypeDoH || registeredRelay.stamp.Proto == stamps.StampProtoTypeODoHTarget) &&
				len(registeredRelay.stamp.ProviderName) > 0 {
				providerName := registeredRelay.stamp.ProviderName
				var host string
				host, port = ExtractHostAndPort(providerName, port)
				addrs = append(addrs, host)
			}
			if len(addrStr) > 0 {
				addrs = append(addrs, hostAddr)
			}
			nolog := true
			nofilter := true
			if registeredRelay.stamp.Proto == stamps.StampProtoTypeODoHRelay {
				nolog = registeredRelay.stamp.Props&stamps.ServerInformalPropertyNoLog != 0
			}
			serverSummary := ServerSummary{
				Name:        registeredRelay.name,
				Proto:       registeredRelay.stamp.Proto.String(),
				IPv6:        strings.HasPrefix(addrStr, "["),
				Ports:       []int{port},
				Addrs:       addrs,
				NoLog:       nolog,
				NoFilter:    nofilter,
				Description: registeredRelay.description,
				Stamp:       registeredRelay.stamp.String(),
			}
			if jsonOutput {
				summary = append(summary, serverSummary)
			} else {
				fmt.Println(serverSummary.Name)
			}
		}
	}
	for _, registeredServer := range proxy.registeredServers {
		addrStr, port := registeredServer.stamp.ServerAddrStr, stamps.DefaultPort
		var hostAddr string
		hostAddr, port = ExtractHostAndPort(addrStr, port)
		addrs := make([]string, 0)
		if (registeredServer.stamp.Proto == stamps.StampProtoTypeDoH || registeredServer.stamp.Proto == stamps.StampProtoTypeODoHTarget) &&
			len(registeredServer.stamp.ProviderName) > 0 {
			providerName := registeredServer.stamp.ProviderName
			var host string
			host, port = ExtractHostAndPort(providerName, port)
			addrs = append(addrs, host)
		}
		if len(addrStr) > 0 {
			addrs = append(addrs, hostAddr)
		}
		dnssec := registeredServer.stamp.Props&stamps.ServerInformalPropertyDNSSEC != 0
		serverSummary := ServerSummary{
			Name:        registeredServer.name,
			Proto:       registeredServer.stamp.Proto.String(),
			IPv6:        strings.HasPrefix(addrStr, "["),
			Ports:       []int{port},
			Addrs:       addrs,
			DNSSEC:      &dnssec,
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
		rand.Shuffle(len(cfgSource.URLs), func(i, j int) {
			cfgSource.URLs[i], cfgSource.URLs[j] = cfgSource.URLs[j], cfgSource.URLs[i]
		})
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
	if err := proxy.updateRegisteredServers(); err != nil {
		return err
	}
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
	}
	cfgSource.RefreshDelay = Min(169, Max(25, cfgSource.RefreshDelay))
	source, err := NewSource(
		cfgSourceName,
		proxy.xTransport,
		cfgSource.URLs,
		cfgSource.MinisignKeyStr,
		cfgSource.CacheFile,
		cfgSource.FormatStr,
		time.Duration(cfgSource.RefreshDelay)*time.Hour,
		cfgSource.Prefix,
	)
	if err != nil {
		if len(source.bin) <= 0 {
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
		dlog.Warnf(
			"Unable to determine the executable directory: [%s] -- You will need to specify absolute paths in the configuration file",
			err,
		)
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
