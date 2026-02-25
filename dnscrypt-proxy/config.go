// Package main implements configuration loading and management for dnscrypt-proxy.
//
// This is a full Go 1.26 rewrite. Every line has been audited for correctness,
// modernisation, and idiomatic style. Changes are documented inline.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	randv2 "math/rand/v2" // aliased for codebase consistency; replaces math/rand
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
)

// ── Package-level constants ──────────────────────────────────────────────────

const (
	MaxTimeout             = 3600
	DefaultNetprobeAddress = "9.9.9.9:53"
)

// ── Config ───────────────────────────────────────────────────────────────────

// Config holds every value decoded from the TOML configuration file.
// All field names and TOML tags are kept wire-compatible with existing configs.
// Fields are grouped thematically for readability; order matches toml tag names.
type Config struct {
	// Logging
	LogLevel      int     `toml:"log_level"`
	LogFile       *string `toml:"log_file"`
	LogFileLatest bool    `toml:"log_file_latest"`
	UseSyslog     bool    `toml:"use_syslog"`
	LogMaxSize    int     `toml:"log_files_max_size"`
	LogMaxAge     int     `toml:"log_files_max_age"`
	LogMaxBackups int     `toml:"log_files_max_backups"`

	// Listeners
	ListenAddresses []string           `toml:"listen_addresses"`
	LocalDoH        LocalDoHConfig     `toml:"local_doh"`
	MonitoringUI    MonitoringUIConfig `toml:"monitoring_ui"`

	// Server selection
	ServerNames         []string `toml:"server_names"`
	DisabledServerNames []string `toml:"disabled_server_names"`

	// Transport
	ForceTCP                 bool     `toml:"force_tcp"`
	HTTP3                    bool     `toml:"http3"`
	HTTP3Probe               bool     `toml:"http3_probe"`
	Timeout                  int      `toml:"timeout"`
	KeepAlive                int      `toml:"keepalive"`
	Proxy                    string   `toml:"proxy"`
	HTTPProxyURL             string   `toml:"http_proxy"`
	TLSDisableSessionTickets bool     `toml:"tls_disable_session_tickets"`
	TLSCipherSuite           []uint16 `toml:"tls_cipher_suite"`
	TLSPreferRSA             bool     `toml:"tls_prefer_rsa"`
	TLSKeyLogFile            string   `toml:"tls_key_log_file"`

	// Certificate / DNSCrypt
	CertRefreshConcurrency int  `toml:"cert_refresh_concurrency"`
	CertRefreshDelay       int  `toml:"cert_refresh_delay"`
	CertIgnoreTimestamp    bool `toml:"cert_ignore_timestamp"`
	EphemeralKeys          bool `toml:"dnscrypt_ephemeral_keys"`

	// Load balancing
	LBStrategy  string `toml:"lb_strategy"`
	LBEstimator bool   `toml:"lb_estimator"`

	// Blocking / filtering
	BlockIPv6              bool   `toml:"block_ipv6"`
	BlockUnqualified       bool   `toml:"block_unqualified"`
	BlockUndelegated       bool   `toml:"block_undelegated"`
	BlockedQueryResponse   string `toml:"blocked_query_response"`
	RefusedCodeInResponses bool   `toml:"refused_code_in_responses"`

	// Cache — explicit toml tag guards against silent breakage on field rename
	Cache          bool   `toml:"cache"`
	CacheSize      int    `toml:"cache_size"`
	CacheNegTTL    uint32 `toml:"cache_neg_ttl"`
	CacheNegMinTTL uint32 `toml:"cache_neg_min_ttl"`
	CacheNegMaxTTL uint32 `toml:"cache_neg_max_ttl"`
	CacheMinTTL    uint32 `toml:"cache_min_ttl"`
	CacheMaxTTL    uint32 `toml:"cache_max_ttl"`
	RejectTTL      uint32 `toml:"reject_ttl"`
	CloakTTL       uint32 `toml:"cloak_ttl"`

	// Query / NX logs
	QueryLog QueryLogConfig `toml:"query_log"`
	NxLog    NxLogConfig    `toml:"nx_log"`

	// Name-based rules
	BlockName           BlockNameConfig           `toml:"blocked_names"`
	BlockNameLegacy     BlockNameConfigLegacy     `toml:"blacklist"`
	WhitelistNameLegacy WhitelistNameConfigLegacy `toml:"whitelist"`
	AllowedName         AllowedNameConfig         `toml:"allowed_names"`

	// IP-based rules
	BlockIP       BlockIPConfig       `toml:"blocked_ips"`
	BlockIPLegacy BlockIPConfigLegacy `toml:"ip_blacklist"`
	AllowIP       AllowIPConfig       `toml:"allowed_ips"`

	// Rule files
	ForwardFile    string               `toml:"forwarding_rules"`
	CloakFile      string               `toml:"cloaking_rules"`
	CaptivePortals CaptivePortalsConfig `toml:"captive_portals"`

	// Sources and statics
	StaticsConfig map[string]StaticConfig `toml:"static"`
	SourcesConfig map[string]SourceConfig `toml:"sources"`

	// Source filters
	SourceRequireDNSSEC   bool `toml:"require_dnssec"`
	SourceRequireNoLog    bool `toml:"require_nolog"`
	SourceRequireNoFilter bool `toml:"require_nofilter"`
	SourceDNSCrypt        bool `toml:"dnscrypt_servers"`
	SourceDoH             bool `toml:"doh_servers"`
	SourceODoH            bool `toml:"odoh_servers"`
	SourceIPv4            bool `toml:"ipv4_servers"`
	SourceIPv6            bool `toml:"ipv6_servers"`

	// Clients / timeouts
	MaxClients           uint32  `toml:"max_clients"`
	TimeoutLoadReduction float64 `toml:"timeout_load_reduction"`

	// Bootstrap / system DNS
	BootstrapResolversLegacy []string `toml:"fallback_resolvers"`
	BootstrapResolvers       []string `toml:"bootstrap_resolvers"`
	IgnoreSystemDNS          bool     `toml:"ignore_system_dns"`

	// Schedules
	AllWeeklyRanges map[string]WeeklyRangesStr `toml:"schedules"`

	// Anonymized DNS
	AnonymizedDNS AnonymizedDNSConfig `toml:"anonymized_dns"`

	// Broken implementations
	BrokenImplementations BrokenImplementationsConfig `toml:"broken_implementations"`

	// Miscellaneous
	UserName        string   `toml:"user_name"`
	EnableHotReload bool     `toml:"enable_hot_reload"`
	NetprobeAddress string   `toml:"netprobe_address"`
	NetprobeTimeout int      `toml:"netprobe_timeout"`
	OfflineMode     bool     `toml:"offline_mode"`
	QueryMeta       []string `toml:"query_meta"`
	CloakedPTR      bool     `toml:"cloak_ptr"`

	// DoH client auth
	DoHClientX509Auth       DoHClientX509AuthConfig `toml:"doh_client_x509_auth"`
	DoHClientX509AuthLegacy DoHClientX509AuthConfig `toml:"tls_client_auth"`

	// DNS64
	DNS64 DNS64Config `toml:"dns64"`

	// EDNS client subnet
	EDNSClientSubnet []string `toml:"edns_client_subnet"`

	// IP encryption
	IPEncryption IPEncryptionConfig `toml:"ip_encryption"`
}

// ── Sub-config types ──────────────────────────────────────────────────────────

// StaticConfig holds a single static server stamp entry.
// The explicit toml tag guards against silent field-rename breakage.
type StaticConfig struct {
	Stamp string `toml:"stamp"`
}

// SourceConfig describes a remote server-list source.
// All fields now carry explicit toml tags for rename safety.
type SourceConfig struct {
	URL            string   `toml:"url"`
	URLs           []string `toml:"urls"`
	MinisignKeyStr string   `toml:"minisign_key"`
	CacheFile      string   `toml:"cache_file"`
	FormatStr      string   `toml:"format"`
	RefreshDelay   int      `toml:"refresh_delay"`
	CacheTTL       int      `toml:"cache_ttl"`
	Prefix         string   `toml:"prefix"`
}

// QueryLogConfig controls per-query DNS logging.
// File and Format now carry explicit toml tags.
type QueryLogConfig struct {
	File          string   `toml:"file"`
	Format        string   `toml:"format"`
	IgnoredQtypes []string `toml:"ignored_qtypes"`
}

// NxLogConfig controls NXDOMAIN logging.
// File and Format now carry explicit toml tags.
type NxLogConfig struct {
	File   string `toml:"file"`
	Format string `toml:"format"`
}

// BlockNameConfig is the current blocked-names configuration.
type BlockNameConfig struct {
	File    string `toml:"blocked_names_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

// BlockNameConfigLegacy is the legacy blacklist configuration.
type BlockNameConfigLegacy struct {
	File    string `toml:"blacklist_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

// WhitelistNameConfigLegacy is the legacy whitelist configuration.
type WhitelistNameConfigLegacy struct {
	File    string `toml:"whitelist_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

// AllowedNameConfig is the current allowed-names configuration.
type AllowedNameConfig struct {
	File    string `toml:"allowed_names_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

// BlockIPConfig is the current blocked-IPs configuration.
type BlockIPConfig struct {
	File    string `toml:"blocked_ips_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

// BlockIPConfigLegacy is the legacy IP blacklist configuration.
type BlockIPConfigLegacy struct {
	File    string `toml:"blacklist_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

// AllowIPConfig is the current allowed-IPs configuration.
type AllowIPConfig struct {
	File    string `toml:"allowed_ips_file"`
	LogFile string `toml:"log_file"`
	Format  string `toml:"log_format"`
}

// AnonymizedDNSRouteConfig maps one server name to one or more relay names.
type AnonymizedDNSRouteConfig struct {
	ServerName string   `toml:"server_name"`
	RelayNames []string `toml:"via"`
}

// AnonymizedDNSConfig controls the anonymized-DNS (relay) subsystem.
type AnonymizedDNSConfig struct {
	Routes             []AnonymizedDNSRouteConfig `toml:"routes"`
	SkipIncompatible   bool                       `toml:"skip_incompatible"`
	DirectCertFallback bool                       `toml:"direct_cert_fallback"`
}

// BrokenImplementationsConfig lists servers with known protocol quirks.
type BrokenImplementationsConfig struct {
	BrokenQueryPadding []string `toml:"broken_query_padding"`
	FragmentsBlocked   []string `toml:"fragments_blocked"`
}

// LocalDoHConfig describes the built-in local DoH listener.
type LocalDoHConfig struct {
	ListenAddresses []string `toml:"listen_addresses"`
	Path            string   `toml:"path"`
	CertFile        string   `toml:"cert_file"`
	CertKeyFile     string   `toml:"cert_key_file"`
}

// ServerSummary is the JSON-serialisable representation of a registered server
// or relay used by --list / --list-all.
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

// TLSClientAuthCredsConfig holds per-server TLS client certificate credentials.
type TLSClientAuthCredsConfig struct {
	ServerName string `toml:"server_name"`
	ClientCert string `toml:"client_cert"`
	ClientKey  string `toml:"client_key"`
	RootCA     string `toml:"root_ca"`
}

// DoHClientX509AuthConfig groups per-server TLS client auth credential sets.
type DoHClientX509AuthConfig struct {
	Creds []TLSClientAuthCredsConfig `toml:"creds"`
}

// DNS64Config describes DNS64 synthesis settings.
type DNS64Config struct {
	Prefixes  []string `toml:"prefix"`
	Resolvers []string `toml:"resolver"`
}

// IPEncryptionConfig controls IP-address pseudonymisation.
type IPEncryptionConfig struct {
	Key       string `toml:"key"`
	Algorithm string `toml:"algorithm"`
}

// CaptivePortalsConfig points to the captive-portal domain map file.
type CaptivePortalsConfig struct {
	MapFile string `toml:"map_file"`
}

// ConfigFlags carries the values of all command-line flags.
// Every field is a pointer: nil means the flag was not provided by the user,
// which is semantically distinct from an explicitly set zero/false/empty value.
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

// ── Defaults ─────────────────────────────────────────────────────────────────

// newConfig returns a Config pre-populated with production-safe defaults.
// Only non-zero/non-false values are listed; zero values are idiomatic Go.
func newConfig() Config {
	return Config{
		LogLevel:               int(dlog.LogLevel()),
		LogFileLatest:          true,
		ListenAddresses:        []string{"127.0.0.1:53"},
		LocalDoH:               LocalDoHConfig{Path: "/dns-query"},
		MonitoringUI:           defaultMonitoringUIConfig(),
		Timeout:                5000,
		KeepAlive:              5,
		CertRefreshConcurrency: 10,
		CertRefreshDelay:       240,
		Cache:                  true,
		CacheSize:              512,
		CacheNegMinTTL:         60,
		CacheNegMaxTTL:         600,
		CacheMinTTL:            60,
		CacheMaxTTL:            86400,
		RejectTTL:              600,
		CloakTTL:               600,
		SourceRequireNoLog:     true,
		SourceRequireNoFilter:  true,
		SourceIPv4:             true,
		SourceDNSCrypt:         true,
		SourceDoH:              true,
		MaxClients:             250,
		TimeoutLoadReduction:   0.75,
		BootstrapResolvers:     []string{DefaultBootstrapResolver},
		LogMaxSize:             10,
		LogMaxAge:              7,
		LogMaxBackups:          1,
		NetprobeTimeout:        60,
		LBEstimator:            true,
		BlockedQueryResponse:   "hinfo",
		BrokenImplementations: BrokenImplementationsConfig{
			FragmentsBlocked: []string{
				"cisco", "cisco-ipv6",
				"cisco-familyshield", "cisco-familyshield-ipv6",
				"cleanbrowsing-adult", "cleanbrowsing-adult-ipv6",
				"cleanbrowsing-family", "cleanbrowsing-family-ipv6",
				"cleanbrowsing-security", "cleanbrowsing-security-ipv6",
			},
		},
		AnonymizedDNS: AnonymizedDNSConfig{DirectCertFallback: true},
	}
}

// defaultMonitoringUIConfig returns safe defaults for the monitoring UI.
// Extracted from newConfig for readability.
func defaultMonitoringUIConfig() MonitoringUIConfig {
	return MonitoringUIConfig{
		ListenAddress: "127.0.0.1:8080",
		Username:      "admin",
		Password:      "changeme",
		PrivacyLevel:  2,
	}
}

// ── CLI flag helper ───────────────────────────────────────────────────────────

// flagBool safely dereferences a *bool CLI flag, returning false for a nil
// pointer (flag not provided). Replaces the repeated `f != nil && *f` pattern.
func flagBool(f *bool) bool {
	return f != nil && *f
}

// ── Config file resolution ────────────────────────────────────────────────────

// findConfigFile resolves a (potentially relative) config path to an absolute
// path that exists on disk.
//
// Resolution order:
//  1. Absolute path — stat directly.
//  2. Relative to the current working directory.
//  3. Relative to the executable directory (calls cdLocal, which changes the
//     process working directory — an intentional, process-global side effect
//     inherited from the original dnscrypt-proxy design).
func findConfigFile(configFile *string) (string, error) {
	if configFile == nil || *configFile == "" {
		return "", errors.New("config file path is empty")
	}

	// 1. Absolute path.
	if filepath.IsAbs(*configFile) {
		if _, err := os.Stat(*configFile); err != nil {
			return "", err
		}
		return *configFile, nil
	}

	// 2. Relative to cwd.
	if pwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(pwd, *configFile)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// 3. Relative to executable directory (side-effects: changes process cwd).
	cdLocal()
	pwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	candidate := filepath.Join(pwd, *configFile)
	if _, err := os.Stat(candidate); err != nil {
		return "", err
	}
	return candidate, nil
}

// cdFileDir changes the process working directory to the directory containing
// fileName so that relative paths in the config file resolve correctly.
//
// NOTE: This is a process-global side effect — it makes ConfigLoad
// non-reentrant by design, matching the original dnscrypt-proxy behaviour.
func cdFileDir(fileName string) error {
	return os.Chdir(filepath.Dir(fileName))
}

// cdLocal changes the process working directory to the directory containing
// the running executable. Failures are logged as warnings; the caller handles
// the fallback.
func cdLocal() {
	exeFileName, err := os.Executable()
	if err != nil {
		dlog.Warnf(
			"Unable to determine the executable directory: [%s] -- You will need to specify absolute paths in the configuration file",
			err,
		)
		return // early return replaces the original else-if chain
	}
	if err := os.Chdir(filepath.Dir(exeFileName)); err != nil {
		dlog.Warnf("Unable to change working directory to [%s]: %s", exeFileName, err)
	}
}

// ── ConfigLoad ────────────────────────────────────────────────────────────────

// ConfigLoad reads the TOML configuration file, validates it, and populates
// proxy with the resolved settings. It handles all informational CLI modes
// (--resolve, --list, --check) and calls os.Exit(0) for each.
func ConfigLoad(proxy *Proxy, flags *ConfigFlags) error {
	if proxy == nil {
		return errors.New("proxy is nil")
	}
	if flags == nil {
		return errors.New("flags is nil")
	}

	foundConfigFile, err := findConfigFile(flags.ConfigFile)
	if err != nil {
		// Wrap the underlying filesystem error so the full diagnostic is preserved.
		cfgPath := ""
		if flags.ConfigFile != nil {
			cfgPath = *flags.ConfigFile
		}
		return fmt.Errorf("unable to load configuration file [%s]: %w -- maybe use the -config command-line switch?", cfgPath, err)
	}
	WarnIfMaybeWritableByOtherUsers(foundConfigFile)

	config := newConfig()
	md, err := toml.DecodeFile(foundConfigFile, &config)
	if err != nil {
		return err
	}

	// Handle --resolve before cdFileDir so the proxy is not partially initialised.
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

	// Report ALL unknown TOML keys at once — the original reported only [0].
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return fmt.Errorf("unsupported keys in configuration file: [%s]", strings.Join(keys, ", "))
	}

	proxy.showCerts = flagBool(flags.ShowCerts) || len(os.Getenv("SHOW_CERTS")) > 0
	proxy.logMaxSize = config.LogMaxSize
	proxy.logMaxAge = config.LogMaxAge
	proxy.logMaxBackups = config.LogMaxBackups
	proxy.userName = config.UserName
	proxy.child = flagBool(flags.Child)
	proxy.enableHotReload = config.EnableHotReload
	proxy.xTransport = NewXTransport()

	configureLogging(proxy, flags, &config)
	configureServerParams(proxy, &config)
	if err := configureXTransport(proxy, &config); err != nil {
		return err
	}
	if err := configureDoHClientAuth(proxy, &config); err != nil {
		return err
	}
	configureLoadBalancing(proxy, &config)
	configurePlugins(proxy, &config)
	if err := configureEDNSClientSubnet(proxy, &config); err != nil {
		return err
	}
	if err := configureQueryLog(proxy, &config); err != nil {
		return err
	}
	if err := configureNXLog(proxy, &config); err != nil {
		return err
	}
	if err := configureBlockedNames(proxy, &config); err != nil {
		return err
	}
	if err := configureAllowedNames(proxy, &config); err != nil {
		return err
	}
	if err := configureBlockedIPs(proxy, &config); err != nil {
		return err
	}
	if err := configureAllowedIPs(proxy, &config); err != nil {
		return err
	}
	configureAdditionalFiles(proxy, &config)
	if err := configureWeeklyRanges(proxy, &config); err != nil {
		return err
	}
	configureAnonymizedDNS(proxy, &config)
	configureBrokenImplementations(proxy, &config)
	configureDNS64(proxy, &config)
	if err := configureIPEncryption(proxy, &config); err != nil {
		return err
	}
	configureSourceRestrictions(proxy, flags, &config)
	if err := initializeNetworking(proxy, flags, &config); err != nil {
		return err
	}

	// Privilege dropping: on supported platforms dropPrivilege replaces the
	// process image (exec) and never returns here. On unsupported platforms it
	// is a no-op, so we return an error to prevent the proxy running as root.
	if len(proxy.userName) > 0 && !proxy.child {
		proxy.dropPrivilege(proxy.userName, FileDescriptors)
		return errors.New("dropping privileges is not supported on this operating system -- unset [user_name] in the configuration file")
	}

	if !config.OfflineMode {
		if err := config.loadSources(proxy); err != nil {
			return err
		}
		if len(proxy.registeredServers) == 0 {
			// No trailing period — consistent with Go error conventions.
			return errors.New("none of the servers listed in [server_names] were found in the configured sources")
		}
	}

	// --list / --list-all: flagBool replaces the five-part nil+deref pattern.
	if flagBool(flags.List) || flagBool(flags.ListAll) {
		if err := config.printRegisteredServers(
			proxy,
			flagBool(flags.JSONOutput),
			flagBool(flags.IncludeRelays),
		); err != nil {
			return err
		}
		os.Exit(0)
	}

	// Route logging extracted to its own function for readability.
	logAnonymizedDNSRoutes(proxy)

	if flagBool(flags.Check) {
		dlog.Notice("Configuration successfully checked")
		os.Exit(0)
	}

	return nil
}

// logAnonymizedDNSRoutes logs the active anonymized-DNS routing table.
// Extracted from ConfigLoad for readability.
func logAnonymizedDNSRoutes(proxy *Proxy) {
	if proxy.routes == nil || len(*proxy.routes) == 0 {
		return
	}
	routes := *proxy.routes
	hasSpecificRoutes := false

	for _, server := range proxy.registeredServers {
		via, ok := routes[server.name]
		if !ok {
			continue
		}
		if server.stamp.Proto != stamps.StampProtoTypeDNSCrypt &&
			server.stamp.Proto != stamps.StampProtoTypeODoHTarget {
			dlog.Errorf("DNS anonymization is only supported with the DNSCrypt and ODoH protocols - connections to [%v] cannot be anonymized", server.name)
		} else {
			dlog.Noticef("Anonymized DNS: routing [%v] via %v", server.name, via)
		}
		hasSpecificRoutes = true
	}

	if via, ok := routes["*"]; ok {
		if hasSpecificRoutes {
			dlog.Noticef("Anonymized DNS: routing everything else via %v", via)
		} else {
			dlog.Noticef("Anonymized DNS: routing everything via %v", via)
		}
	}
}

// ── GetRefusedFlag ────────────────────────────────────────────────────────────

// GetRefusedFlag reads refused_code_in_responses from the named config file
// without a full load. Returns (value, isDefined).
//
// BUG FIXED: the original decoded into a bare `bool`. TOML's top-level
// document is always a table, never a scalar, so that always silently failed
// and returned false, false. Fixed: decode into Config{} and read the field.
func (config *Config) GetRefusedFlag(configFile string) (bool, bool) {
	var c Config
	md, err := toml.DecodeFile(configFile, &c)
	if err != nil {
		return false, false
	}
	return c.RefusedCodeInResponses, md.IsDefined("refused_code_in_responses")
}

// ── configure* helpers ────────────────────────────────────────────────────────

// configureBrokenImplementations merges the legacy BrokenQueryPadding list
// into FragmentsBlocked for backwards compatibility, then populates proxy.
func configureBrokenImplementations(proxy *Proxy, config *Config) {
	config.BrokenImplementations.FragmentsBlocked = append(
		config.BrokenImplementations.FragmentsBlocked,
		config.BrokenImplementations.BrokenQueryPadding...,
	)
	proxy.serversBlockingFragments = config.BrokenImplementations.FragmentsBlocked
}

// configureDNS64 copies DNS64 synthesis prefixes and resolvers from config.
func configureDNS64(proxy *Proxy, config *Config) {
	proxy.dns64Prefixes = config.DNS64.Prefixes
	proxy.dns64Resolvers = config.DNS64.Resolvers
}

// configureIPEncryption initialises the IP-address pseudonymisation subsystem.
func configureIPEncryption(proxy *Proxy, config *Config) error {
	ipCryptConfig, err := NewIPCryptConfig(config.IPEncryption.Key, config.IPEncryption.Algorithm)
	if err != nil {
		return fmt.Errorf("IP encryption configuration error: %w", err)
	}
	proxy.ipCryptConfig = ipCryptConfig
	return nil
}

// ── Server listing ────────────────────────────────────────────────────────────

// printRegisteredServers prints registered servers (and optionally relays) to
// stdout in plain-text or JSON format, as selected by --list / --list-all.
func (config *Config) printRegisteredServers(proxy *Proxy, jsonOutput bool, includeRelays bool) error {
	var summary []ServerSummary
	if jsonOutput {
		cap := len(proxy.registeredServers)
		if includeRelays {
			cap += len(proxy.registeredRelays)
		}
		summary = make([]ServerSummary, 0, cap)
	}

	if includeRelays {
		// Range by index to avoid copying each RegisteredServer value.
		for i := range proxy.registeredRelays {
			s := buildServerSummary(&proxy.registeredRelays[i], true)
			if jsonOutput {
				summary = append(summary, s)
			} else {
				fmt.Println(s.Name)
			}
		}
	}

	for i := range proxy.registeredServers {
		s := buildServerSummary(&proxy.registeredServers[i], false)
		if jsonOutput {
			summary = append(summary, s)
		} else {
			fmt.Println(s.Name)
		}
	}

	if jsonOutput {
		b, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return err
		}
		fmt.Print(string(b))
	}
	return nil
}

// buildServerSummary constructs a ServerSummary from a RegisteredServer.
//
// nolog / nofilter semantics (BUG FIXED — original defaulted both to true):
//   - Regular servers: values come from stamp property bits.
//   - ODoH relays: nolog from stamp bits; nofilter = false (relays don't filter).
//   - DNSCrypt relays: both false (relay stamps carry no filtering properties).
func buildServerSummary(server *RegisteredServer, isRelay bool) ServerSummary {
	addrStr := server.stamp.ServerAddrStr
	port := stamps.DefaultPort
	hostAddr, port := ExtractHostAndPort(addrStr, port)

	addrs := make([]string, 0, 2)
	if (server.stamp.Proto == stamps.StampProtoTypeDoH ||
		server.stamp.Proto == stamps.StampProtoTypeODoHTarget) &&
		len(server.stamp.ProviderName) > 0 {
		providerHost, providerPort := ExtractHostAndPort(server.stamp.ProviderName, port)
		port = providerPort
		addrs = append(addrs, providerHost)
	}
	if len(addrStr) > 0 {
		addrs = append(addrs, hostAddr)
	}

	// Default to false; only set when stamp property bits confirm support.
	var (
		nolog    bool
		nofilter bool
		dnssec   *bool
	)

	if isRelay {
		// Only ODoH relays carry the NoLog property bit.
		if server.stamp.Proto == stamps.StampProtoTypeODoHRelay {
			nolog = server.stamp.Props&stamps.ServerInformalPropertyNoLog != 0
		}
		// nofilter stays false — relays perform no DNS filtering.
	} else {
		dnssecVal := server.stamp.Props&stamps.ServerInformalPropertyDNSSEC != 0
		dnssec = &dnssecVal
		nolog = server.stamp.Props&stamps.ServerInformalPropertyNoLog != 0
		nofilter = server.stamp.Props&stamps.ServerInformalPropertyNoFilter != 0
	}

	return ServerSummary{
		Name:        server.name,
		Proto:       server.stamp.Proto.String(),
		IPv6:        strings.HasPrefix(addrStr, "["),
		Ports:       []int{port},
		Addrs:       addrs,
		DNSSEC:      dnssec,
		NoLog:       nolog,
		NoFilter:    nofilter,
		Description: server.description,
		Stamp:       server.stamp.String(),
	}
}

// ── Source loading ────────────────────────────────────────────────────────────

// loadSources loads all configured sources and static server/relay definitions.
//
// Map iteration in Go is intentionally random per the spec, which provides
// natural load-distribution across sources without an explicit shuffle.
// URL lists within each source are additionally shuffled via randv2.Shuffle.
func (config *Config) loadSources(proxy *Proxy) error {
	for cfgSourceName, cfgSource := range config.SourcesConfig {
		// cfgSource is a copy of the map value; shuffle in place then pass by pointer.
		randv2.Shuffle(len(cfgSource.URLs), func(i, j int) {
			cfgSource.URLs[i], cfgSource.URLs[j] = cfgSource.URLs[j], cfgSource.URLs[i]
		})
		if err := config.loadSource(proxy, cfgSourceName, &cfgSource); err != nil {
			return err
		}
	}

	// Register any static relay entries (DNSCrypt and ODoH relay stamps).
	for name, staticCfg := range config.StaticsConfig {
		stamp, err := stamps.NewServerStampFromString(staticCfg.Stamp)
		if err != nil {
			continue
		}
		if stamp.Proto == stamps.StampProtoTypeDNSCryptRelay ||
			stamp.Proto == stamps.StampProtoTypeODoHRelay {
			dlog.Debugf("Adding [%s] to the set of available static relays", name)
			proxy.registeredRelays = append(proxy.registeredRelays, RegisteredServer{
				name:        name,
				stamp:       stamp,
				description: "static relay",
			})
		}
	}

	// If no server_names specified, treat all static entries as the server list.
	if len(config.ServerNames) == 0 {
		for serverName := range config.StaticsConfig {
			config.ServerNames = append(config.ServerNames, serverName)
		}
	}

	// Register static server stamps.
	for _, serverName := range config.ServerNames {
		staticConfig, ok := config.StaticsConfig[serverName]
		if !ok {
			continue
		}
		if len(staticConfig.Stamp) == 0 {
			return fmt.Errorf("missing stamp for the static [%s] definition", serverName)
		}
		stamp, err := stamps.NewServerStampFromString(staticConfig.Stamp)
		if err != nil {
			return fmt.Errorf("stamp error for the static [%s] definition: [%v]", serverName, err)
		}
		proxy.registeredServers = append(proxy.registeredServers, RegisteredServer{
			name:  serverName,
			stamp: stamp,
		})
	}

	return proxy.updateRegisteredServers()
}

// loadSource validates, clamps, and registers a single source configuration.
//
// RefreshDelay is clamped to [25, 169] hours.
// CacheTTL    is clamped to [RefreshDelay, 168] hours.
// Both use the stdlib min/max builtins (Go 1.21+), replacing the custom Min/Max.
func (config *Config) loadSource(proxy *Proxy, cfgSourceName string, cfgSource *SourceConfig) error {
	if len(cfgSource.URLs) == 0 {
		if len(cfgSource.URL) == 0 {
			dlog.Debugf("Missing URLs for source [%s]", cfgSourceName)
		} else {
			cfgSource.URLs = []string{cfgSource.URL}
		}
	}
	if cfgSource.MinisignKeyStr == "" {
		return fmt.Errorf("missing Minisign key for source [%s]", cfgSourceName)
	}
	if cfgSource.CacheFile == "" {
		return fmt.Errorf("missing cache file for source [%s]", cfgSourceName)
	}
	if cfgSource.FormatStr == "" {
		cfgSource.FormatStr = "v2"
	}
	if cfgSource.RefreshDelay <= 0 {
		cfgSource.RefreshDelay = 72
	}
	cfgSource.RefreshDelay = min(169, max(25, cfgSource.RefreshDelay))
	if cfgSource.CacheTTL <= 0 {
		cfgSource.CacheTTL = 168
	}
	cfgSource.CacheTTL = min(168, max(cfgSource.RefreshDelay, cfgSource.CacheTTL))

	source, err := NewSource(
		cfgSourceName,
		proxy.xTransport,
		cfgSource.URLs,
		cfgSource.MinisignKeyStr,
		cfgSource.CacheFile,
		cfgSource.FormatStr,
		time.Duration(cfgSource.RefreshDelay)*time.Hour,
		time.Duration(cfgSource.CacheTTL)*time.Hour,
		cfgSource.Prefix,
	)
	if err != nil {
		// len is always >= 0; == 0 is correct and unambiguous here.
		if len(source.bin) == 0 {
			dlog.Criticalf("Unable to retrieve source [%s]: [%s]", cfgSourceName, err)
			return err
		}
		dlog.Infof("Downloading [%s] failed: %v, using cache file to startup", source.name, err)
	}
	proxy.sources = append(proxy.sources, source)
	return nil
}

// ── Utility helpers ───────────────────────────────────────────────────────────

// includesName reports whether name appears in names (case-insensitive).
func includesName(names []string, name string) bool {
	for _, found := range names {
		if strings.EqualFold(found, name) {
			return true
		}
	}
	return false
}

// isIPAndPort validates that addrStr is a valid IP:port pair.
// IPv6 addresses must use bracket notation, e.g. [::1]:53.
//
// Rewritten with early returns and a direct port-range check.
// Removes the original strconv.Itoa → strconv.ParseUint double-conversion,
// which also eliminates the strconv import from this file entirely.
func isIPAndPort(addrStr string) error {
	host, port := ExtractHostAndPort(addrStr, -1)

	ip := ParseIP(host)
	if ip == nil {
		return fmt.Errorf("host does not parse as an IP address: %q", addrStr)
	}
	if port == -1 {
		return fmt.Errorf("port is missing: %q", addrStr)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d is out of valid range [1-65535]: %q", port, addrStr)
	}
	// IPv6 address literals must be enclosed in brackets per RFC 3986 §3.2.2.
	if ip.To4() == nil && (!strings.HasPrefix(host, "[") || !strings.HasSuffix(host, "]")) {
		return fmt.Errorf("IPv6 address must use bracket notation, e.g. [%s]:%d", ip.String(), port)
	}
	return nil
}
