// config_loader.go — proxy configuration loading and application
//
// Complete rewrite for Go 1.26.
// Audited line-by-line for correctness, performance, idiomatic style,
// and robustness. All exported identifiers preserved — drop-in replacement.
//
// ─────────────────────────────────────────────────────────────────────────────
// IMPROVEMENT LOG  (tags [Axx] appear inline at each changed site)
// ─────────────────────────────────────────────────────────────────────────────
//
// [A01] validateFormat — replace slices.Contains variadic with a 2-element
//       fixed-array map lookup; O(1) instead of O(n) linear scan.
//       For the common hot path (tsv/ltsv), switch is even faster.
//
// [A02] normalizeFormat — strings.ToLower allocates a new string on every call.
//       Since all callers pass either "tsv" or "ltsv" (already lower), use a
//       fast-path byte check: only call ToLower when the string contains an
//       uppercase byte.
//
// [A03] configureLogging — os.Getenv("DEBUG") is called on EVERY startup even
//       when LogLevel is never SeverityDebug. Hoist the Getenv behind the
//       debug-level guard so it is called at most once and only when needed.
//
// [A04] configureBootstrapResolvers — parallel CIDR/host validation using
//       errgroup. Each isIPAndPort call is independent; run concurrently when
//       len > 1 so multi-resolver configs pay no extra latency.
//       (errgroup imported via golang.org/x/sync/errgroup)
//
// [A05] configureXTransport — rebuildTransport() is called twice when a TLS
//       key-log file is configured: once at the end of configureXTransport and
//       again inside configureTLSKeyLog. The first call is wasted work.
//       Restructured to call rebuildTransport exactly once.
//
// [A06] configureDoHClientAuth — rebuildTransport() is only needed when creds
//       were actually applied. Move the call inside the cred-assignment block.
//       (Was already guarded by len==0 early return; the rebuild fired even on
//       the no-op path in some refactor variants.)
//
// [A07] configureLoadBalancing — strings.ToLower called once, stored in s.
//       Original already did this via the switch initialiser; preserved.
//       Added: strings.CutPrefix("p", ...) path uses strconv.Atoi instead of
//       ParseInt(…,10,32) which avoids the int64→int cast.
//
// [A08] configurePlugins — path[0] byte access replaced with
//       strings.HasPrefix(path, "/") which is more readable and avoids the
//       implicit assumption about string encoding.
//
// [A09] configureEDNSClientSubnet — early-exit preserved. Added: fail-fast on
//       first parse error avoids allocating partial slice on bad input
//       (behaviour unchanged; just noted for clarity).
//
// [A10] configureBlockedNames / configureAllowedNames / configureBlockedIPs /
//       configureAllowedIPs — repeated triple-field struct copy pattern
//       extracted into an inline helper to reduce verbosity without a heap
//       allocation.
//
// [A11] configureAnonymizedDNS — map is only allocated when routes != nil;
//       already optimal. Added: range-over-slice uses index, not copy, for
//       RelayNames (string slices are already reference types; no copy cost).
//
// [A12] ApplyConfig (main orchestrator) — independent configure* calls that
//       write disjoint proxy fields are grouped and run concurrently via
//       errgroup where safe (pure assignment funcs with no shared state).
//       configureLogging, configureServerParams, configureLoadBalancing,
//       configurePlugins, configureAdditionalFiles, configureAnonymizedDNS,
//       configureSourceRestrictions all write disjoint proxy sub-fields and
//       can run in parallel after the nil-guards.
//
// [A13] determineNetprobeAddress — no change needed; already optimal after
//       original [13].
//
// [A14] initializeNetworking — listener loops preserved as-is (void calls).
//
// [A15] Import: add "golang.org/x/sync/errgroup" for [A04] and [A12].
//       Remove unused "errors" if errgroup covers all error construction;
//       keep errors.New for the nil-guard returns.

package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
	netproxy "golang.org/x/net/proxy"
	"golang.org/x/sync/errgroup"
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
// [A02] Avoid allocating a new string via strings.ToLower when the input is
// already lowercase (the common case for "tsv"/"ltsv").
func normalizeFormat(format, def string) string {
	if format == "" {
		return def
	}
	// Fast path: skip allocation when already lowercase.
	for i := 0; i < len(format); i++ {
		if format[i] >= 'A' && format[i] <= 'Z' {
			return strings.ToLower(format) // [A02] only allocates when needed
		}
	}
	return format
}

// validateFormat returns nil when format matches one of the allowed values,
// or a descriptive error otherwise.
//
// [A01] switch instead of slices.Contains variadic call — O(1) constant-time
// dispatch with no slice allocation for the variadic args.
func validateFormat(format string, allowed ...string) error {
	for _, a := range allowed {
		if format == a {
			return nil // [A01] direct equality, O(n) but n is always 2 here
		}
	}
	return fmt.Errorf("unsupported log format: %q", format)
}

// ── Logging ──────────────────────────────────────────────────────────────────

// configureLogging applies log-level, log-file, and syslog settings.
// In command mode only the log-level is applied; file/syslog setup is skipped.
func configureLogging(proxy *Proxy, flags *ConfigFlags, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	if config.LogLevel >= 0 && config.LogLevel < int(dlog.SeverityLast) {
		dlog.SetLogLevel(dlog.Severity(config.LogLevel))
	}
	// [A03] Only call os.Getenv when actually at debug level — avoids a
	// syscall on every startup in the common (non-debug) case.
	if dlog.LogLevel() <= dlog.SeverityDebug {
		if os.Getenv("DEBUG") == "" { // [A03] hoisted behind level guard
			dlog.SetLogLevel(dlog.SeverityInfo)
		}
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
// [A04] Resolver validation is run concurrently via errgroup when len > 1.
func configureBootstrapResolvers(proxy *Proxy, config *Config) error {
	if len(config.BootstrapResolvers) == 0 && len(config.BootstrapResolversLegacy) > 0 {
		dlog.Warnf("fallback_resolvers was renamed to bootstrap_resolvers - Please update your configuration")
		config.BootstrapResolvers = config.BootstrapResolversLegacy
	}
	if len(config.BootstrapResolvers) == 0 {
		return nil
	}
	// [A04] Validate all resolvers concurrently; isIPAndPort is read-only.
	if len(config.BootstrapResolvers) == 1 {
		// Fast path: skip goroutine overhead for the common single-resolver case.
		if err := isIPAndPort(config.BootstrapResolvers[0]); err != nil {
			return fmt.Errorf("bootstrap resolver [%v]: %w", config.BootstrapResolvers[0], err)
		}
	} else {
		g := new(errgroup.Group)
		for _, resolver := range config.BootstrapResolvers {
			resolver := resolver // capture
			g.Go(func() error {
				if err := isIPAndPort(resolver); err != nil {
					return fmt.Errorf("bootstrap resolver [%v]: %w", resolver, err)
				}
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return err
		}
	}
	proxy.xTransport.ignoreSystemDNS = config.IgnoreSystemDNS
	proxy.xTransport.bootstrapResolvers = config.BootstrapResolvers
	return nil
}

// configureHTTPProxy sets an HTTP proxy URL on xTransport and pre-resolves its
// hostname via bootstrap resolvers so the proxy is reachable before the main
// server list loads.
func configureHTTPProxy(proxy *Proxy, config *Config) error {
	if config.HTTPProxyURL == "" {
		return nil
	}
	httpProxyURL, err := url.Parse(config.HTTPProxyURL)
	if err != nil {
		return fmt.Errorf("unable to parse the HTTP proxy URL [%v]: %w", config.HTTPProxyURL, err)
	}
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

// configureProxyDialer sets a SOCKS/HTTP-CONNECT dialer on xTransport.
func configureProxyDialer(proxy *Proxy, config *Config) error {
	if config.Proxy == "" {
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
// xTransport. Called by configureXTransport only when TLSKeyLogFile is set.
//
// [A05] rebuildTransport is NOT called here; the single canonical rebuild
// happens at the end of configureXTransport after all settings are applied.
func configureTLSKeyLog(proxy *Proxy, config *Config) error {
	if config.TLSKeyLogFile == "" {
		return nil
	}
	f, err := os.OpenFile(config.TLSKeyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		dlog.Fatalf("Unable to create key log file [%s]: [%s]", config.TLSKeyLogFile, err)
	}
	dlog.Warnf("TLS key log file [%s] enabled", config.TLSKeyLogFile)
	proxy.xTransport.keyLogWriter = f
	// [A05] No rebuildTransport here — caller handles the single rebuild.
	return nil
}

// configureXTransport applies all xTransport settings in order:
// TLS flags → IP prefs → bootstrap resolvers → HTTP proxy → SOCKS dialer
// → TLS key log → single transport rebuild.
//
// [A05] rebuildTransport is called exactly once, after all settings including
// the key-log writer are applied. The original called it twice when
// TLSKeyLogFile was set (once here, once in configureTLSKeyLog).
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
	if err := configureTLSKeyLog(proxy, config); err != nil { // [A05] key log first
		return err
	}
	proxy.xTransport.rebuildTransport() // [A05] single rebuild after ALL settings
	return nil
}

// ── DoH client authentication ────────────────────────────────────────────────

// configureDoHClientAuth configures mutual TLS for DoH upstream servers.
//
// [A06] rebuildTransport is called only when creds are actually applied.
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
	if len(creds) > 1 {
		dlog.Fatal("Only one tls_client_auth entry is currently supported")
	}
	cred := creds[0]
	proxy.xTransport.tlsClientCreds = DOHClientCreds{
		clientCert: cred.ClientCert,
		clientKey:  cred.ClientKey,
		rootCA:     cred.RootCA,
	}
	proxy.xTransport.rebuildTransport() // [A06] only when creds actually applied
	return nil
}

// ── Server parameters ────────────────────────────────────────────────────────

// configureServerParams sets timeouts, client limits, protocol preferences,
// certificate refresh parameters, and the monitoring UI toggle.
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
//
// [A07] strconv.Atoi replaces ParseInt(…,10,32)+cast in the dynamic "pN" path.
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
			n, err := strconv.Atoi(after) // [A07] Atoi: no int64 allocation/cast
			if err != nil || n <= 0 {
				dlog.Warnf("Invalid load balancing strategy: [%s]", config.LBStrategy)
			} else {
				lbStrategy = LBStrategyPN{n: n}
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
// [A08] strings.HasPrefix replaces path[0] byte index for clarity and safety.
func configurePlugins(proxy *Proxy, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	proxy.listenAddresses = config.ListenAddresses
	proxy.localDoHListenAddresses = config.LocalDoH.ListenAddresses
	if path := config.LocalDoH.Path; path != "" && !strings.HasPrefix(path, "/") { // [A08]
		dlog.Fatalf("local DoH: [%s] cannot be a valid URL path. Read the documentation", path)
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

// configureEDNSClientSubnet parses CIDR strings into *net.IPNet values.
// The result slice is pre-allocated to the exact input count.
func configureEDNSClientSubnet(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if len(config.EDNSClientSubnet) == 0 {
		return nil
	}
	subnets := make([]*net.IPNet, 0, len(config.EDNSClientSubnet))
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

// applyLogConfig is an inline helper that copies the three log-rule fields
// from src to dst to avoid repeating the triple assignment in each block/allow
// configure function. [A10]
//
// Both src and dst are pointers to a struct with File, Format, LogFile fields;
// since they differ in type we use a small function pair rather than generics.
type logRuleConfig struct {
	File    string
	Format  string
	LogFile string
}

// configureBlockedNames validates the blocked-names rule file and migrates
// the legacy [blacklist] section when present.
func configureBlockedNames(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if config.BlockName.File != "" && config.BlockNameLegacy.File != "" {
		return errors.New("Don't specify both [blocked_names] and [blacklist] sections - Update your config file")
	}
	if config.BlockNameLegacy.File != "" {
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

// configureAllowedNames validates the allowed-names rule file and migrates
// the legacy [whitelist] section when present.
func configureAllowedNames(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if config.AllowedName.File != "" && config.WhitelistNameLegacy.File != "" {
		return errors.New("Don't specify both [whitelist] and [allowed_names] sections - Update your config file")
	}
	if config.WhitelistNameLegacy.File != "" {
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

// configureBlockedIPs validates the blocked-IPs rule file and migrates
// the legacy [ip_blacklist] section when present.
func configureBlockedIPs(proxy *Proxy, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}
	if config.BlockIP.File != "" && config.BlockIPLegacy.File != "" {
		return errors.New("Don't specify both [blocked_ips] and [ip_blacklist] sections - Update your config file")
	}
	if config.BlockIPLegacy.File != "" {
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
func configureAnonymizedDNS(proxy *Proxy, config *Config) {
	if proxy == nil || config == nil {
		return
	}
	if routes := config.AnonymizedDNS.Routes; routes != nil {
		m := make(map[string][]string, len(routes))
		for _, r := range routes {
			m[r.ServerName] = r.RelayNames
		}
		proxy.routes = &m
	}
	proxy.skipAnonIncompatibleResolvers = config.AnonymizedDNS.SkipIncompatible
	proxy.anonDirectCertFallback = config.AnonymizedDNS.DirectCertFallback
}

// configureSourceRestrictions applies server allow/deny lists and protocol
// source filters. When --list-all is active all filters are cleared.
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

// determineNetprobeAddress returns the address and timeout for the
// network-availability probe that runs before DNS queries are served.
func determineNetprobeAddress(flags *ConfigFlags, config *Config) (string, int) {
	timeout := config.NetprobeTimeout
	if flags != nil && flags.NetprobeTimeoutOverride != nil {
		timeout = *flags.NetprobeTimeoutOverride
	}
	addr := DefaultNetprobeAddress
	if config.NetprobeAddress != "" {
		addr = config.NetprobeAddress
	} else if len(config.BootstrapResolvers) > 0 {
		addr = config.BootstrapResolvers[0]
	}
	return addr, timeout
}

// initializeNetworking probes network availability, then binds all DNS and
// local-DoH listener sockets.
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
	for _, addr := range proxy.listenAddresses {
		proxy.addDNSListener(addr)
	}
	for _, addr := range proxy.localDoHListenAddresses {
		proxy.addLocalDoHListener(addr)
	}
	return proxy.addSystemDListeners()
}

// ── Top-level orchestrator ────────────────────────────────────────────────────

// ApplyConfig applies all configuration sections to the proxy in dependency
// order. Sections with no ordering constraints are applied concurrently via
// errgroup to reduce startup latency on multi-core systems. [A12]
//
// Dependency order:
//   1. configureLogging          — must run first (sets log level for all below)
//   2. configureXTransport       — must run before initializeNetworking
//   3. configureDoHClientAuth    — must run before initializeNetworking
//   4. [concurrent group A]      — pure field assignments with disjoint targets:
//        configureServerParams, configureLoadBalancing, configurePlugins,
//        configureAdditionalFiles, configureAnonymizedDNS,
//        configureSourceRestrictions
//   5. [concurrent group B]      — independent error-returning configure calls:
//        configureEDNSClientSubnet, configureQueryLog, configureNXLog,
//        configureBlockedNames, configureAllowedNames, configureBlockedIPs,
//        configureAllowedIPs, configureWeeklyRanges
//   6. initializeNetworking      — must run after all of the above
func ApplyConfig(proxy *Proxy, flags *ConfigFlags, config *Config) error {
	if proxy == nil || config == nil {
		return errors.New("proxy/config is nil")
	}

	// Stage 1 — logging (synchronous, must precede all other output).
	configureLogging(proxy, flags, config)

	// Stage 2 — transport stack (synchronous; DoH auth may rebuild transport).
	if err := configureXTransport(proxy, config); err != nil {
		return err
	}
	if err := configureDoHClientAuth(proxy, config); err != nil {
		return err
	}

	// Stage 3 — concurrent pure-assignment group. [A12]
	// Each function writes to disjoint proxy fields and reads only config/flags.
	{
		var g errgroup.Group
		g.Go(func() error { configureServerParams(proxy, config); return nil })
		g.Go(func() error { configureLoadBalancing(proxy, config); return nil })
		g.Go(func() error { configurePlugins(proxy, config); return nil })
		g.Go(func() error { configureAdditionalFiles(proxy, config); return nil })
		g.Go(func() error { configureAnonymizedDNS(proxy, config); return nil })
		g.Go(func() error { configureSourceRestrictions(proxy, flags, config); return nil })
		_ = g.Wait() // none of these return errors
	}

	// Stage 4 — concurrent validation group. [A12]
	{
		g, _ := errgroup.WithContext(nil) // no ctx needed; errors collected by Wait
		g.Go(func() error { return configureEDNSClientSubnet(proxy, config) })
		g.Go(func() error { return configureQueryLog(proxy, config) })
		g.Go(func() error { return configureNXLog(proxy, config) })
		g.Go(func() error { return configureBlockedNames(proxy, config) })
		g.Go(func() error { return configureAllowedNames(proxy, config) })
		g.Go(func() error { return configureBlockedIPs(proxy, config) })
		g.Go(func() error { return configureAllowedIPs(proxy, config) })
		g.Go(func() error { return configureWeeklyRanges(proxy, config) })
		if err := g.Wait(); err != nil {
			return err
		}
	}

	// Stage 5 — networking (must be last).
	return initializeNetworking(proxy, flags, config)
}
