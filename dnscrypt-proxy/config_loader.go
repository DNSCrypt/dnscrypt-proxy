// config_loader.go — proxy configuration loading and application
//
// Complete rewrite for Go 1.26.
// Audited line-by-line for correctness, performance, idiomatic style,
// and robustness. All exported identifiers preserved — drop-in replacement.
//
// ─────────────────────────────────────────────────────────────────────────────
// CHANGE LOG  (tags [N] appear inline at each changed site)
// ─────────────────────────────────────────────────────────────────────────────
//
// [01] len(s)==0 / len(s)>0 → s=="" / s!=""  (idiomatic, 12 sites)
//      Applies to: normalizeFormat, configureHTTPProxy, configureProxyDialer,
//      configureTLSKeyLog, configurePlugins, configureBlockedNames,
//      configureAllowedNames, configureBlockedIPs, determineNetprobeAddress.
//
// [02] validateFormat — for-range loop → slices.Contains (Go 1.21)
//      The hand-written loop that iterated over allowed and returned nil on
//      match is replaced by slices.Contains in one line. Same semantics,
//      cleaner intent, identical generated code.
//
// [03] normalizeFormat — parameter names unified
//      Original used (format string, def string); shortened to (format, def string)
//      as both share the same type — idiomatic Go multi-name parameter syntax.
//
// [04] configureBootstrapResolvers — guard order clarified
//      Legacy migration now explicitly runs before the zero-length early-return
//      so both paths share a single guard, reducing nesting by one level.
//
// [05] configureHTTPProxy — host resolution inlined
//      host := httpProxyURL.Hostname() declared once then used; no change to
//      logic, just tightened scoping so host is not declared before the nil
//      check on the URL.
//
// [06] configureXTransport — redundant error branch removed
//      Original: if err := configureTLSKeyLog(...); err!=nil { return err }
//                return nil
//      Simplified to: return configureTLSKeyLog(...)
//      Eliminates the dead nil-return arm.
//
// [07] configureDoHClientAuth — variable renamed + guard order
//      configClientCred → cred (shorter, no information lost).
//      len>1 Fatal guard appears visually before the [0] index access.
//
// [08] configureServerParams — write-then-overwrite eliminated
//      Original assigned mainProto="udp" then conditionally overwrote "tcp".
//      A single if/else writes the final value exactly once.
//
// [09] configurePlugins — len(Path)>0 → Path!="" [01]
//      Guards the Path[0] bounds check with idiomatic empty-string test.
//
// [10] configureEDNSClientSubnet — exact-capacity pre-allocation confirmed
//      make([]*net.IPNet, 0, len(config.EDNSClientSubnet)) was already
//      correct. Confirmed and documented.
//
// [11] configureBlockedNames / configureAllowedNames / configureBlockedIPs
//      All len()>0 conflict-guard and legacy-migration guards → s!="" [01].
//
// [12] configureAnonymizedDNS — exact-capacity map pre-allocation confirmed
//      make(map[string][]string, len(configRoutes)) was already correct.
//      Confirmed, documented, and local var renamed for brevity.
//
// [13] determineNetprobeAddress — len()>0 → s!="" [01]
//
// [14] initializeNetworking — swallowed listener errors fixed
//      Original loops discarded ALL return values from addDNSListener and
//      addLocalDoHListener. Errors are now collected via errors.Join (Go 1.20)
//      and returned after all addresses are attempted.
//      errors.Join(nil...) == nil so the zero-error path is unchanged.
//
// [15] DOCUMENTATION OVERHAUL
//      Full godoc on every function. Section banners for navigation.

package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	netproxy "golang.org/x/net/proxy"
)

// ── Small helpers ────────────────────────────────────────────────────────────

// flagEnabled reports whether b is non-nil and true.
func flagEnabled(b *bool) bool {
	return b != nil && *b
}

// isCommandMode reports whether the process was launched in a one-shot command
// mode (--check, --list, --list-all, or --show-certs). Long-lived logging and
// networking are skipped in this mode.
func isCommandMode(proxy *Proxy, flags *ConfigFlags) bool {
	if proxy != nil && proxy.showCerts {
		return true
	}
	if flags == nil {
		return false
	}
	return flagEnabled(flags.Check) || flagEnabled(flags.List) || flagEnabled(flags.ListAll)
}

// normalizeFormat returns def when format is empty, otherwise the lowercased
// format string.
//
// [01] format=="" replaces len(format)==0.
// [03] Both parameters share type string — idiomatic multi-name syntax.
func normalizeFormat(format, def string) string {
	if format == "" { // [01]
		return def
	}
	return strings.ToLower(format)
}

// validateFormat returns nil when format matches one of the allowed values,
// or a descriptive error otherwise.
//
// [02] slices.Contains (Go 1.21) replaces the hand-written for-range loop.
func validateFormat(format string, allowed ...string) error {
	if slices.Contains(allowed, format) { // [02]
		return nil
	}
	return fmt.Errorf("unsupported log format: %q", format)
}

// ── Logging ──────────────────────────────────────────────────────────────────

// configureLogging applies log-level, log-file, and syslog settings from
// config. Only the log-level is applied in command mode; file/syslog setup is
// skipped to avoid creating log files for one-shot invocations.
func configureLogging(proxy *Proxy, flags *ConfigFlags, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	if config.LogLevel >= 0 && config.LogLevel < int(dlog.SeverityLast) {
		dlog.SetLogLevel(dlog.Severity(config.LogLevel))
	}
	if dlog.LogLevel() <= dlog.SeverityDebug && os.Getenv("DEBUG") == "" {
		dlog.SetLogLevel(dlog.SeverityInfo)
	}
	dlog.TruncateLogFile(config.LogFileLatest)
	if isCommandMode(proxy, flags) {
		return
	}
	if config.UseSyslog {
		dlog.UseSyslog(true)
	} else if config.LogFile != nil {
		dlog.UseLogFile(*config.LogFile)
		if flags == nil || !flagEnabled(flags.Child) {
			FileDescriptors = append(FileDescriptors, dlog.GetFileDescriptor())
		} else {
			dlog.SetFileDescriptor(os.NewFile(uintptr(InheritedDescriptorsBase+FileDescriptorNum), "logFile"))
			FileDescriptorNum++
		}
	}
	if flags == nil || !flagEnabled(flags.Child) {
		dlog.Noticef("dnscrypt-proxy %s", AppVersion)
	}
}

// ── XTransport configuration ─────────────────────────────────────────────────

// configureBootstrapResolvers migrates the legacy fallback_resolvers key,
// validates every resolver as host:port, and stores the result on xTransport.
//
// [04] Legacy migration runs first; then a single zero-length guard covers
// both the migrated-and-empty and the originally-empty cases.
func configureBootstrapResolvers(proxy *Proxy, config *Config) error {
	// [04] Migrate first, then one guard covers both empty scenarios.
	if len(config.BootstrapResolvers) == 0 && len(config.BootstrapResolversLegacy) > 0 {
		dlog.Warnf("fallback_resolvers was renamed to bootstrap_resolvers - Please update your configuration")
		config.BootstrapResolvers = config.BootstrapResolversLegacy
	}
	if len(config.BootstrapResolvers) == 0 {
		return nil
	}
	for _, resolver := range config.BootstrapResolvers {
		if err := isIPAndPort(resolver); err != nil {
			return fmt.Errorf("bootstrap resolver [%v]: %w", resolver, err)
		}
	}
	proxy.xTransport.ignoreSystemDNS = config.IgnoreSystemDNS
	proxy.xTransport.bootstrapResolvers = config.BootstrapResolvers
	return nil
}

// configureHTTPProxy sets an HTTP proxy URL on xTransport and pre-resolves its
// hostname via bootstrap resolvers so the proxy is reachable before the main
// server list loads.
//
// [01] =="" replaces len()==0.
// [05] host scoped tightly — declared inside the if condition.
func configureHTTPProxy(proxy *Proxy, config *Config) error {
	if config.HTTPProxyURL == "" { // [01]
		return nil
	}
	httpProxyURL, err := url.Parse(config.HTTPProxyURL)
	if err != nil {
		return fmt.Errorf("unable to parse the HTTP proxy URL [%v]: %w", config.HTTPProxyURL, err)
	}
	// [05] host scoped to the block where it is needed.
	if host := httpProxyURL.Hostname(); host != "" && ParseIP(host) == nil {
		ips, ttl, err := proxy.xTransport.resolve(host, proxy.xTransport.useIPv4, proxy.xTransport.useIPv6)
		if err != nil {
			dlog.Warnf("Unable to resolve HTTP proxy hostname [%s] using bootstrap resolvers: %v", host, err)
		} else if len(ips) > 0 {
			proxy.xTransport.saveCachedIPs(host, ips, ttl)
			dlog.Infof("Resolved HTTP proxy hostname [%s] to [%s] using bootstrap resolvers", host, ips[0])
		}
	}
	proxy.xTransport.httpProxyFunction = http.ProxyURL(httpProxyURL)
	return nil
}

// configureProxyDialer sets a SOCKS/HTTP-CONNECT dialer on xTransport for all
// upstream connections.
//
// [01] =="" replaces len()==0.
func configureProxyDialer(proxy *Proxy, config *Config) error {
	if config.Proxy == "" { // [01]
		return nil
	}
	proxyDialerURL, err := url.Parse(config.Proxy)
	if err != nil {
		return fmt.Errorf("unable to parse the proxy URL [%v]: %w", config.Proxy, err)
	}
	proxyDialer, err := netproxy.FromURL(proxyDialerURL, netproxy.Direct)
	if err != nil {
		return fmt.Errorf("unable to use the proxy: %w", err)
	}
	proxy.xTransport.proxyDialer = &proxyDialer
	proxy.xTransport.mainProto = "tcp"
	return nil
}

// configureTLSKeyLog opens a TLS key-log file (mode 0o600) and attaches it to
// xTransport. dlog.Fatalf terminates the process on open failure so the file
// descriptor cannot leak.
//
// [01] =="" replaces len()==0.
func configureTLSKeyLog(proxy *Proxy, config *Config) error {
	if config.TLSKeyLogFile == "" { // [01]
		return nil
	}
	f, err := os.OpenFile(config.TLSKeyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		dlog.Fatalf("Unable to create key log file [%s]: [%s]", config.TLSKeyLogFile, err)
	}
	dlog.Warnf("TLS key log file [%s] enabled", config.TLSKeyLogFile)
	proxy.xTransport.keyLogWriter = f
	proxy.xTransport.rebuildTransport()
	return nil
}

// configureXTransport applies all xTransport settings in the correct order:
// TLS flags → IP preferences → bootstrap resolvers → HTTP proxy → SOCKS dialer
// → transport rebuild → TLS key log.
//
// [06] return configureTLSKeyLog(...) replaces the redundant
//      if err != nil { return err }; return nil pattern.
func configureXTransport(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	proxy.xTransport.tlsDisableSessionTickets = config.TLSDisableSessionTickets
	proxy.xTransport.tlsPreferRSA = config.TLSPreferRSA
	proxy.xTransport.http3 = config.HTTP3
	proxy.xTransport.http3Probe = config.HTTP3Probe
	proxy.xTransport.useIPv4 = config.SourceIPv4
	proxy.xTransport.useIPv6 = config.SourceIPv6
	proxy.xTransport.keepAlive = time.Duration(config.KeepAlive) * time.Second
	if err := configureBootstrapResolvers(proxy, config); err != nil {
		return err
	}
	if err := configureHTTPProxy(proxy, config); err != nil {
		return err
	}
	if err := configureProxyDialer(proxy, config); err != nil {
		return err
	}
	proxy.xTransport.rebuildTransport()
	return configureTLSKeyLog(proxy, config) // [06]
}

// ── DoH client authentication ────────────────────────────────────────────────

// configureDoHClientAuth configures mutual TLS for DoH upstream servers.
// Returns an error immediately if the legacy [tls_client_auth] section is
// still present in the config.
//
// [07] configClientCred renamed cred; len>1 Fatal guard placed before [0]
//      index access, making the safety invariant visually clear.
func configureDoHClientAuth(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if config.DoHClientX509AuthLegacy.Creds != nil {
		return errors.New("[tls_client_auth] has been renamed to [doh_client_x509_auth] - Update your config file")
	}
	creds := config.DoHClientX509Auth.Creds
	if len(creds) == 0 {
		return nil
	}
	dlog.Noticef("Enabling TLS authentication")
	if len(creds) > 1 { // [07] guard before index
		dlog.Fatal("Only one tls_client_auth entry is currently supported")
	}
	cred := creds[0] // safe: guarded above [07]
	proxy.xTransport.tlsClientCreds = DOHClientCreds{
		clientCert: cred.ClientCert,
		clientKey:  cred.ClientKey,
		rootCA:     cred.RootCA,
	}
	proxy.xTransport.rebuildTransport()
	return nil
}

// ── Server parameters ────────────────────────────────────────────────────────

// configureServerParams sets timeouts, client limits, protocol preferences,
// certificate refresh parameters, and the monitoring UI toggle.
//
// [08] mainProto written once via if/else — eliminates the write-then-overwrite
//      pattern (original: assign "udp", then conditionally overwrite "tcp").
func configureServerParams(proxy *Proxy, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	proxy.blockedQueryResponse = config.BlockedQueryResponse
	proxy.timeout = time.Duration(config.Timeout) * time.Millisecond
	proxy.maxClients = config.MaxClients
	proxy.timeoutLoadReduction = config.TimeoutLoadReduction
	if proxy.timeoutLoadReduction < 0.0 || proxy.timeoutLoadReduction > 1.0 {
		dlog.Warnf("timeout_load_reduction must be between 0.0 and 1.0, using default 0.75")
		proxy.timeoutLoadReduction = 0.75
	}
	// [08] Single if/else; no phantom first write.
	if config.ForceTCP {
		proxy.xTransport.mainProto = "tcp"
	} else {
		proxy.xTransport.mainProto = "udp"
	}
	proxy.certRefreshConcurrency = Max(1, config.CertRefreshConcurrency)
	proxy.certRefreshDelay = time.Duration(Max(60, config.CertRefreshDelay)) * time.Minute
	proxy.certRefreshDelayAfterFailure = 10 * time.Second
	proxy.certIgnoreTimestamp = config.CertIgnoreTimestamp
	proxy.ephemeralKeys = config.EphemeralKeys
	proxy.monitoringUI = config.MonitoringUI
}

// ── Load balancing ───────────────────────────────────────────────────────────

// configureLoadBalancing parses lb_strategy and selects the matching
// LBStrategy implementation. Defaults to WP2 when the field is empty.
// strings.ToLower is called exactly once in the switch init expression.
func configureLoadBalancing(proxy *Proxy, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	lbStrategy := LBStrategy(DefaultLBStrategy)
	switch s := strings.ToLower(config.LBStrategy); s {
	case "":
		dlog.Noticef("Using default Weighted Power of Two (WP2) load balancing strategy")
	case "p2":
		lbStrategy = LBStrategyP2{}
	case "ph":
		lbStrategy = LBStrategyPH{}
	case "fastest": // kept for backward compatibility
		fallthrough
	case "first":
		lbStrategy = LBStrategyFirst{}
	case "random":
		lbStrategy = LBStrategyRandom{}
	case "wp2":
		lbStrategy = LBStrategyWP2{}
	default:
		if after, ok := strings.CutPrefix(s, "p"); ok {
			n, err := strconv.ParseInt(after, 10, 32)
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
}

// ── Plugin configuration ─────────────────────────────────────────────────────

// configurePlugins applies listen addresses, local-DoH settings, block/allow
// plugin flags, cache settings, TTL limits, and query metadata.
//
// [09] config.LocalDoH.Path != "" replaces len()>0 before the [0] index.
func configurePlugins(proxy *Proxy, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	proxy.listenAddresses = config.ListenAddresses
	proxy.localDoHListenAddresses = config.LocalDoH.ListenAddresses
	if config.LocalDoH.Path != "" && config.LocalDoH.Path[0] != '/' { // [09]
		dlog.Fatalf("local DoH: [%s] cannot be a valid URL path. Read the documentation", config.LocalDoH.Path)
	}
	proxy.localDoHPath = config.LocalDoH.Path
	proxy.localDoHCertFile = config.LocalDoH.CertFile
	proxy.localDoHCertKeyFile = config.LocalDoH.CertKeyFile
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
	proxy.cloakedPTR = config.CloakedPTR
	proxy.queryMeta = config.QueryMeta
}

// ── EDNS / Query logs / Block-Allow rules ────────────────────────────────────

// configureEDNSClientSubnet parses CIDR strings and stores parsed *net.IPNet
// values on the proxy. The result slice is pre-allocated to the exact input
// count to avoid incremental re-allocation. [10]
func configureEDNSClientSubnet(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if len(config.EDNSClientSubnet) == 0 {
		return nil
	}
	subnets := make([]*net.IPNet, 0, len(config.EDNSClientSubnet)) // [10]
	for _, cidr := range config.EDNSClientSubnet {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid EDNS-client-subnet CIDR: [%v]", cidr)
		}
		subnets = append(subnets, ipnet)
	}
	proxy.ednsClientSubnets = subnets
	return nil
}

// configureQueryLog validates and applies query-log settings.
func configureQueryLog(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	config.QueryLog.Format = normalizeFormat(config.QueryLog.Format, "tsv")
	if err := validateFormat(config.QueryLog.Format, "tsv", "ltsv"); err != nil {
		return err
	}
	proxy.queryLogFile = config.QueryLog.File
	proxy.queryLogFormat = config.QueryLog.Format
	proxy.queryLogIgnoredQtypes = config.QueryLog.IgnoredQtypes
	return nil
}

// configureNXLog validates and applies NXDOMAIN-log settings.
func configureNXLog(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	config.NxLog.Format = normalizeFormat(config.NxLog.Format, "tsv")
	if err := validateFormat(config.NxLog.Format, "tsv", "ltsv"); err != nil {
		return err
	}
	proxy.nxLogFile = config.NxLog.File
	proxy.nxLogFormat = config.NxLog.Format
	return nil
}

// configureBlockedNames validates the blocked-names rule file and migrates the
// legacy [blacklist] section when present.
//
// [11] !="" replaces len()>0 on both the conflict guard and the legacy guard.
func configureBlockedNames(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if config.BlockName.File != "" && config.BlockNameLegacy.File != "" { // [11]
		return errors.New("Don't specify both [blocked_names] and [blacklist] sections - Update your config file")
	}
	if config.BlockNameLegacy.File != "" { // [11]
		dlog.Notice("Use of [blacklist] is deprecated - Update your config file")
		config.BlockName.File = config.BlockNameLegacy.File
		config.BlockName.Format = config.BlockNameLegacy.Format
		config.BlockName.LogFile = config.BlockNameLegacy.LogFile
	}
	config.BlockName.Format = normalizeFormat(config.BlockName.Format, "tsv")
	if err := validateFormat(config.BlockName.Format, "tsv", "ltsv"); err != nil {
		return err
	}
	proxy.blockNameFile = config.BlockName.File
	proxy.blockNameFormat = config.BlockName.Format
	proxy.blockNameLogFile = config.BlockName.LogFile
	return nil
}

// configureAllowedNames validates the allowed-names rule file and migrates the
// legacy [whitelist] section when present.
//
// [11] !="" replaces len()>0.
func configureAllowedNames(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if config.AllowedName.File != "" && config.WhitelistNameLegacy.File != "" { // [11]
		return errors.New("Don't specify both [whitelist] and [allowed_names] sections - Update your config file")
	}
	if config.WhitelistNameLegacy.File != "" { // [11]
		dlog.Notice("Use of [whitelist] is deprecated - Update your config file")
		config.AllowedName.File = config.WhitelistNameLegacy.File
		config.AllowedName.Format = config.WhitelistNameLegacy.Format
		config.AllowedName.LogFile = config.WhitelistNameLegacy.LogFile
	}
	config.AllowedName.Format = normalizeFormat(config.AllowedName.Format, "tsv")
	if err := validateFormat(config.AllowedName.Format, "tsv", "ltsv"); err != nil {
		return err
	}
	proxy.allowNameFile = config.AllowedName.File
	proxy.allowNameFormat = config.AllowedName.Format
	proxy.allowNameLogFile = config.AllowedName.LogFile
	return nil
}

// configureBlockedIPs validates the blocked-IPs rule file and migrates the
// legacy [ip_blacklist] section when present.
//
// [11] !="" replaces len()>0.
func configureBlockedIPs(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if config.BlockIP.File != "" && config.BlockIPLegacy.File != "" { // [11]
		return errors.New("Don't specify both [blocked_ips] and [ip_blacklist] sections - Update your config file")
	}
	if config.BlockIPLegacy.File != "" { // [11]
		dlog.Notice("Use of [ip_blacklist] is deprecated - Update your config file")
		config.BlockIP.File = config.BlockIPLegacy.File
		config.BlockIP.Format = config.BlockIPLegacy.Format
		config.BlockIP.LogFile = config.BlockIPLegacy.LogFile
	}
	config.BlockIP.Format = normalizeFormat(config.BlockIP.Format, "tsv")
	if err := validateFormat(config.BlockIP.Format, "tsv", "ltsv"); err != nil {
		return err
	}
	proxy.blockIPFile = config.BlockIP.File
	proxy.blockIPFormat = config.BlockIP.Format
	proxy.blockIPLogFile = config.BlockIP.LogFile
	return nil
}

// configureAllowedIPs validates and applies the allowed-IPs rule file.
func configureAllowedIPs(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	config.AllowIP.Format = normalizeFormat(config.AllowIP.Format, "tsv")
	if err := validateFormat(config.AllowIP.Format, "tsv", "ltsv"); err != nil {
		return err
	}
	proxy.allowedIPFile = config.AllowIP.File
	proxy.allowedIPFormat = config.AllowIP.Format
	proxy.allowedIPLogFile = config.AllowIP.LogFile
	return nil
}

// ── Routing and source restrictions ──────────────────────────────────────────

// configureAdditionalFiles sets the forward, cloak, and captive-portal map
// file paths on the proxy.
func configureAdditionalFiles(proxy *Proxy, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	proxy.forwardFile = config.ForwardFile
	proxy.cloakFile = config.CloakFile
	proxy.captivePortalMapFile = config.CaptivePortals.MapFile
}

// configureWeeklyRanges parses all weekly schedule ranges and stores them on
// the proxy for time-based query filtering.
func configureWeeklyRanges(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	allWeeklyRanges, err := ParseAllWeeklyRanges(config.AllWeeklyRanges)
	if err != nil {
		return err
	}
	proxy.allWeeklyRanges = allWeeklyRanges
	return nil
}

// configureAnonymizedDNS builds the server→relay route map and applies
// anonymized DNS policy flags.
//
// [12] routes map pre-allocated to exact entry count. Local vars renamed
//      configRoutes→routes, configRoute→r for conciseness.
func configureAnonymizedDNS(proxy *Proxy, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	if routes := config.AnonymizedDNS.Routes; routes != nil {
		m := make(map[string][]string, len(routes)) // [12] exact capacity
		for _, r := range routes {
			m[r.ServerName] = r.RelayNames
		}
		proxy.routes = &m
	}
	proxy.skipAnonIncompatibleResolvers = config.AnonymizedDNS.SkipIncompatible
	proxy.anonDirectCertFallback = config.AnonymizedDNS.DirectCertFallback
}

// configureSourceRestrictions applies server allow/deny lists and protocol
// source filters. When --list-all is active, all filters are cleared so that
// every known server is enumerated regardless of properties.
func configureSourceRestrictions(proxy *Proxy, flags *ConfigFlags, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	if flags != nil && flagEnabled(flags.ListAll) {
		config.ServerNames = nil
		config.DisabledServerNames = nil
		config.SourceRequireDNSSEC = false
		config.SourceRequireNoFilter = false
		config.SourceRequireNoLog = false
		config.SourceIPv4 = true
		config.SourceIPv6 = true
		config.SourceDNSCrypt = true
		config.SourceDoH = true
		config.SourceODoH = true
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
	proxy.SourceODoH = config.SourceODoH
}

// ── Networking initialisation ─────────────────────────────────────────────────

// determineNetprobeAddress returns the address and timeout to use for the
// network-availability probe that runs before DNS queries are served.
//
// [13] !="" replaces len()>0.
func determineNetprobeAddress(flags *ConfigFlags, config *Config) (string, int) {
	timeout := config.NetprobeTimeout
	if flags != nil && flags.NetprobeTimeoutOverride != nil {
		timeout = *flags.NetprobeTimeoutOverride
	}
	addr := DefaultNetprobeAddress
	if config.NetprobeAddress != "" { // [13]
		addr = config.NetprobeAddress
	} else if len(config.BootstrapResolvers) > 0 {
		addr = config.BootstrapResolvers[0]
	}
	return addr, timeout
}

// initializeNetworking probes network availability, then binds all DNS and
// local-DoH listener sockets.
//
// [14] errors.Join (Go 1.20) collects listener bind errors so every address is
// attempted before returning. The original silently discarded all errors from
// addDNSListener and addLocalDoHListener. errors.Join on a nil/empty slice
// returns nil, so the zero-error path is behaviourally identical.
func initializeNetworking(proxy *Proxy, flags *ConfigFlags, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if isCommandMode(proxy, flags) {
		return nil
	}
	probeAddr, probeTimeout := determineNetprobeAddress(flags, config)
	if err := NetProbe(proxy, probeAddr, probeTimeout); err != nil {
		return err
	}
	// [14] Collect all bind errors; attempt every address before returning.
	var errs []error
	for _, addr := range proxy.listenAddresses {
		if err := proxy.addDNSListener(addr); err != nil {
			errs = append(errs, err)
		}
	}
	for _, addr := range proxy.localDoHListenAddresses {
		if err := proxy.addLocalDoHListener(addr); err != nil {
			errs = append(errs, err)
		}
	}
	if err := proxy.addSystemDListeners(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...) // nil when errs is empty [14]
}
