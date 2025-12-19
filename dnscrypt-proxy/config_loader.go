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
)

// configureLogging - Configure logging based on the configuration
func configureLogging(proxy *Proxy, flags *ConfigFlags, config *Config) {
	if config.LogLevel >= 0 && config.LogLevel < int(dlog.SeverityLast) {
		dlog.SetLogLevel(dlog.Severity(config.LogLevel))
	}
	if dlog.LogLevel() <= dlog.SeverityDebug && os.Getenv("DEBUG") == "" {
		dlog.SetLogLevel(dlog.SeverityInfo)
	}
	dlog.TruncateLogFile(config.LogFileLatest)

	isCommandMode := false
	if flags.Check != nil && *flags.Check {
		isCommandMode = true
	}
	if proxy.showCerts {
		isCommandMode = true
	}
	if flags.List != nil && *flags.List {
		isCommandMode = true
	}
	if flags.ListAll != nil && *flags.ListAll {
		isCommandMode = true
	}

	if isCommandMode {
		// Don't configure additional logging for command mode
		return
	}

	if config.UseSyslog {
		dlog.UseSyslog(true)
	} else if config.LogFile != nil {
		dlog.UseLogFile(*config.LogFile)
		if !*flags.Child {
			FileDescriptors = append(FileDescriptors, dlog.GetFileDescriptor())
		} else {
			dlog.SetFileDescriptor(os.NewFile(uintptr(InheritedDescriptorsBase+FileDescriptorNum), "logFile"))
			FileDescriptorNum++
		}
	}

	if !*flags.Child {
		dlog.Noticef("dnscrypt-proxy %s", AppVersion)
	}
}

// configureXTransport - Configures the XTransport
func configureXTransport(proxy *Proxy, config *Config) error {
	proxy.xTransport.tlsDisableSessionTickets = config.TLSDisableSessionTickets
	proxy.xTransport.tlsCipherSuite = config.TLSCipherSuite
	proxy.xTransport.mainProto = proxy.mainProto
	proxy.xTransport.http3 = config.HTTP3
	proxy.xTransport.http3Probe = config.HTTP3Probe

	// Configure bootstrap resolvers
	if len(config.BootstrapResolvers) == 0 && len(config.BootstrapResolversLegacy) > 0 {
		dlog.Warnf("fallback_resolvers was renamed to bootstrap_resolvers - Please update your configuration")
		config.BootstrapResolvers = config.BootstrapResolversLegacy
	}
	if len(config.BootstrapResolvers) > 0 {
		for _, resolver := range config.BootstrapResolvers {
			if err := isIPAndPort(resolver); err != nil {
				return fmt.Errorf("Bootstrap resolver [%v]: %v", resolver, err)
			}
		}
		proxy.xTransport.ignoreSystemDNS = config.IgnoreSystemDNS
	}
	proxy.xTransport.bootstrapResolvers = config.BootstrapResolvers
	proxy.xTransport.useIPv4 = config.SourceIPv4
	proxy.xTransport.useIPv6 = config.SourceIPv6
	proxy.xTransport.keepAlive = time.Duration(config.KeepAlive) * time.Second

	// Configure HTTP proxy URL if specified
	if len(config.HTTPProxyURL) > 0 {
		httpProxyURL, err := url.Parse(config.HTTPProxyURL)
		if err != nil {
			return fmt.Errorf("Unable to parse the HTTP proxy URL [%v]", config.HTTPProxyURL)
		}

		// Pre-resolve proxy hostname using bootstrap resolvers if it's a domain
		if httpProxyURL.Hostname() != "" && ParseIP(httpProxyURL.Hostname()) == nil {
			ips, ttl, err := proxy.xTransport.resolve(httpProxyURL.Hostname(), proxy.xTransport.useIPv4, proxy.xTransport.useIPv6)
			if err != nil {
				dlog.Warnf("Unable to resolve HTTP proxy hostname [%s] using bootstrap resolvers: %v", httpProxyURL.Hostname(), err)
			} else if len(ips) > 0 {
				proxy.xTransport.saveCachedIPs(httpProxyURL.Hostname(), ips, ttl)
				dlog.Infof("Resolved HTTP proxy hostname [%s] to [%s] using bootstrap resolvers", httpProxyURL.Hostname(), ips[0])
			}
		}

		proxy.xTransport.httpProxyFunction = http.ProxyURL(httpProxyURL)
	}

	// Configure proxy dialer if specified
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
		proxy.xTransport.mainProto = "tcp"
	}

	proxy.xTransport.rebuildTransport()

	// Configure TLS key log if specified
	if len(config.TLSKeyLogFile) > 0 {
		f, err := os.OpenFile(config.TLSKeyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			dlog.Fatalf("Unable to create key log file [%s]: [%s]", config.TLSKeyLogFile, err)
		}
		dlog.Warnf("TLS key log file [%s] enabled", config.TLSKeyLogFile)
		proxy.xTransport.keyLogWriter = f
		proxy.xTransport.rebuildTransport()
	}

	return nil
}

// configureDoHClientAuth - Configures DoH client authentication
func configureDoHClientAuth(proxy *Proxy, config *Config) error {
	if config.DoHClientX509AuthLegacy.Creds != nil {
		return errors.New("[tls_client_auth] has been renamed to [doh_client_x509_auth] - Update your config file")
	}

	dohClientCreds := config.DoHClientX509Auth.Creds
	if len(dohClientCreds) > 0 {
		dlog.Noticef("Enabling TLS authentication")
		configClientCred := dohClientCreds[0]
		if len(dohClientCreds) > 1 {
			dlog.Fatal("Only one tls_client_auth entry is currently supported")
		}
		proxy.xTransport.tlsClientCreds = DOHClientCreds{
			clientCert: configClientCred.ClientCert,
			clientKey:  configClientCred.ClientKey,
			rootCA:     configClientCred.RootCA,
		}
		proxy.xTransport.rebuildTransport()
	}

	return nil
}

// configureServerParams - Configures server parameters
func configureServerParams(proxy *Proxy, config *Config) {
	proxy.blockedQueryResponse = config.BlockedQueryResponse
	proxy.timeout = time.Duration(config.Timeout) * time.Millisecond
	proxy.maxClients = config.MaxClients
	proxy.timeoutLoadReduction = config.TimeoutLoadReduction
	if proxy.timeoutLoadReduction < 0.0 || proxy.timeoutLoadReduction > 1.0 {
		dlog.Warnf("timeout_load_reduction must be between 0.0 and 1.0, using default 0.75")
		proxy.timeoutLoadReduction = 0.75
	}
	proxy.mainProto = "udp"
	if config.ForceTCP {
		proxy.mainProto = "tcp"
	}

	// Configure certificate refresh parameters
	proxy.certRefreshConcurrency = Max(1, config.CertRefreshConcurrency)
	proxy.certRefreshDelay = time.Duration(Max(60, config.CertRefreshDelay)) * time.Minute
	proxy.certRefreshDelayAfterFailure = time.Duration(10 * time.Second)
	proxy.certIgnoreTimestamp = config.CertIgnoreTimestamp
	proxy.ephemeralKeys = config.EphemeralKeys
	proxy.monitoringUI = config.MonitoringUI
}

// configureLoadBalancing - Configures load balancing strategy
func configureLoadBalancing(proxy *Proxy, config *Config) {
	lbStrategy := LBStrategy(DefaultLBStrategy)
	switch lbStrategyStr := strings.ToLower(config.LBStrategy); lbStrategyStr {
	case "":
		// default - WP2 is now the default strategy
		dlog.Noticef("Using default Weighted Power of Two (WP2) load balancing strategy")
	case "p2":
		lbStrategy = LBStrategyP2{}
	case "ph":
		lbStrategy = LBStrategyPH{}
	case "fastest":
		// "fastest" kept for backward compatibility with older configs
		fallthrough
	case "first":
		lbStrategy = LBStrategyFirst{}
	case "random":
		lbStrategy = LBStrategyRandom{}
	case "wp2":
		lbStrategy = LBStrategyWP2{}
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
}

// configurePlugins - Configures DNS plugins
func configurePlugins(proxy *Proxy, config *Config) {
	// Configure listen addresses and paths
	proxy.listenAddresses = config.ListenAddresses
	proxy.localDoHListenAddresses = config.LocalDoH.ListenAddresses

	if len(config.LocalDoH.Path) > 0 && config.LocalDoH.Path[0] != '/' {
		dlog.Fatalf("local DoH: [%s] cannot be a valid URL path. Read the documentation", config.LocalDoH.Path)
	}
	proxy.localDoHPath = config.LocalDoH.Path
	proxy.localDoHCertFile = config.LocalDoH.CertFile
	proxy.localDoHCertKeyFile = config.LocalDoH.CertKeyFile

	// Configure plugins
	proxy.pluginBlockIPv6 = config.BlockIPv6
	proxy.pluginBlockUnqualified = config.BlockUnqualified
	proxy.pluginBlockUndelegated = config.BlockUndelegated

	// Configure cache
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

	// Configure query meta
	proxy.queryMeta = config.QueryMeta
}

// configureEDNSClientSubnet - Configures EDNS client subnet
func configureEDNSClientSubnet(proxy *Proxy, config *Config) error {
	if len(config.EDNSClientSubnet) != 0 {
		proxy.ednsClientSubnets = make([]*net.IPNet, 0)
		for _, cidr := range config.EDNSClientSubnet {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("Invalid EDNS-client-subnet CIDR: [%v]", cidr)
			}
			proxy.ednsClientSubnets = append(proxy.ednsClientSubnets, ipnet)
		}
	}
	return nil
}

// configureQueryLog - Configures query logging
func configureQueryLog(proxy *Proxy, config *Config) error {
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

	return nil
}

// configureNXLog - Configures NX domain logging
func configureNXLog(proxy *Proxy, config *Config) error {
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

	return nil
}

// configureBlockedNames - Configures blocked names
func configureBlockedNames(proxy *Proxy, config *Config) error {
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

	return nil
}

// configureAllowedNames - Configures allowed names
func configureAllowedNames(proxy *Proxy, config *Config) error {
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
	proxy.allowNameFile = config.AllowedName.File
	proxy.allowNameFormat = config.AllowedName.Format
	proxy.allowNameLogFile = config.AllowedName.LogFile

	return nil
}

// configureBlockedIPs - Configures blocked IPs
func configureBlockedIPs(proxy *Proxy, config *Config) error {
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

	return nil
}

// configureAllowedIPs - Configures allowed IPs
func configureAllowedIPs(proxy *Proxy, config *Config) error {
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

	return nil
}

// configureAdditionalFiles - Configures forwarding, cloaking, and captive portal files
func configureAdditionalFiles(proxy *Proxy, config *Config) {
	proxy.forwardFile = config.ForwardFile
	proxy.cloakFile = config.CloakFile
	proxy.captivePortalMapFile = config.CaptivePortals.MapFile
}

// configureWeeklyRanges - Parses and configures weekly ranges
func configureWeeklyRanges(proxy *Proxy, config *Config) error {
	allWeeklyRanges, err := ParseAllWeeklyRanges(config.AllWeeklyRanges)
	if err != nil {
		return err
	}
	proxy.allWeeklyRanges = allWeeklyRanges
	return nil
}

// The configureDNS64 function is now defined in config.go

// The configureBrokenImplementations function is now defined in config.go

// configureAnonymizedDNS - Configures anonymized DNS
func configureAnonymizedDNS(proxy *Proxy, config *Config) {
	if configRoutes := config.AnonymizedDNS.Routes; configRoutes != nil {
		routes := make(map[string][]string)
		for _, configRoute := range configRoutes {
			routes[configRoute.ServerName] = configRoute.RelayNames
		}
		proxy.routes = &routes
	}

	proxy.skipAnonIncompatibleResolvers = config.AnonymizedDNS.SkipIncompatible
	proxy.anonDirectCertFallback = config.AnonymizedDNS.DirectCertFallback
}

// configureSourceRestrictions - Configures server source restrictions
func configureSourceRestrictions(proxy *Proxy, flags *ConfigFlags, config *Config) {
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

// determineNetprobeAddress - Determines the address to use for network probing
func determineNetprobeAddress(flags *ConfigFlags, config *Config) (string, int) {
	netprobeTimeout := config.NetprobeTimeout
	if flags.NetprobeTimeoutOverride != nil {
		netprobeTimeout = *flags.NetprobeTimeoutOverride
	}

	netprobeAddress := DefaultNetprobeAddress
	if len(config.NetprobeAddress) > 0 {
		netprobeAddress = config.NetprobeAddress
	} else if len(config.BootstrapResolvers) > 0 {
		netprobeAddress = config.BootstrapResolvers[0]
	}

	return netprobeAddress, netprobeTimeout
}

// initializeNetworking - Initializes networking
func initializeNetworking(proxy *Proxy, flags *ConfigFlags, config *Config) error {
	isCommandMode := *flags.Check || proxy.showCerts || *flags.List || *flags.ListAll
	if isCommandMode {
		return nil
	}

	netprobeAddress, netprobeTimeout := determineNetprobeAddress(flags, config)
	if err := NetProbe(proxy, netprobeAddress, netprobeTimeout); err != nil {
		return err
	}

	for _, listenAddrStr := range proxy.listenAddresses {
		proxy.addDNSListener(listenAddrStr)
	}
	for _, listenAddrStr := range proxy.localDoHListenAddresses {
		proxy.addLocalDoHListener(listenAddrStr)
	}

	return proxy.addSystemDListeners()
}
