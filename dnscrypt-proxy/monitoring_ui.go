package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

// sanitizeString - Sanitizes user input to prevent XSS attacks
func sanitizeString(input string) string {
	// HTML escape to prevent XSS
	escaped := html.EscapeString(input)
	// Additional validation for domain names - only allow valid domain characters
	if strings.Contains(input, ".") { // Likely a domain name
		// Remove any non-domain characters
		var result strings.Builder
		for _, r := range escaped {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
				result.WriteRune(r)
			}
		}
		return result.String()
	}
	return escaped
}

// MonitoringUIConfig - Configuration for the monitoring UI
type MonitoringUIConfig struct {
	Enabled            bool   `toml:"enabled"`
	ListenAddress      string `toml:"listen_address"`
	Username           string `toml:"username"`
	Password           string `toml:"password"`
	TLSCertificate     string `toml:"tls_certificate"`
	TLSKey             string `toml:"tls_key"`
	EnableQueryLog     bool   `toml:"enable_query_log"`
	PrivacyLevel       int    `toml:"privacy_level"`         // 0: show all details, 1: anonymize client IPs, 2: aggregate only (no individual queries or domains)
	MaxQueryLogEntries int    `toml:"max_query_log_entries"` // Maximum number of recent queries to keep in memory (default: 100)
	MaxMemoryMB        int    `toml:"max_memory_mb"`         // Maximum memory usage in MB for recent queries (default: 1MB)
	PrometheusEnabled  bool   `toml:"prometheus_enabled"`    // Enable Prometheus metrics endpoint
	PrometheusPath     string `toml:"prometheus_path"`       // Path for Prometheus metrics endpoint (default: /metrics)
}

// MetricsCollector - Collects and stores metrics for the monitoring UI
type MetricsCollector struct {
	// Split locks for better concurrency
	countersMutex   sync.RWMutex // For totalQueries, cacheHits, cacheMisses, blockCount, QPS
	serverMutex     sync.RWMutex // For serverResponseTime, serverQueryCount
	domainMutex     sync.RWMutex // For topDomains
	queryLogMutex   sync.RWMutex // For recentQueries
	queryTypesMutex sync.RWMutex // For queryTypes

	startTime          time.Time
	totalQueries       uint64
	queriesPerSecond   float64
	lastQueriesCount   uint64
	lastQueriesTime    time.Time
	cacheHits          uint64
	cacheMisses        uint64
	blockCount         uint64
	queryTypes         map[string]uint64
	responseTimeSum    uint64
	responseTimeCount  uint64
	serverResponseTime map[string]uint64
	serverQueryCount   map[string]uint64
	topDomains         map[string]uint64
	recentQueries      []QueryLogEntry
	maxRecentQueries   int
	maxMemoryBytes     int64
	currentMemoryBytes int64
	privacyLevel       int

	// Caching for expensive calculations
	cacheMutex      sync.RWMutex
	cachedMetrics   map[string]interface{}
	cacheLastUpdate time.Time
	cacheTTL        time.Duration

	// Prometheus metrics (optional)
	prometheusEnabled bool
}

// QueryLogEntry - Entry for the query log
type QueryLogEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	ClientIP     string    `json:"client_ip"`
	Domain       string    `json:"domain"`
	Type         string    `json:"type"`
	ResponseCode string    `json:"response_code"`
	ResponseTime int64     `json:"response_time"`
	Server       string    `json:"server"`
	CacheHit     bool      `json:"cache_hit"`
}

// EstimateMemoryUsage estimates the memory usage of a QueryLogEntry in bytes
func (q *QueryLogEntry) EstimateMemoryUsage() int64 {
	// Base struct size + string content lengths
	return int64(88 + // approximate struct overhead
		len(q.ClientIP) +
		len(q.Domain) +
		len(q.Type) +
		len(q.ResponseCode) +
		len(q.Server))
}

// MonitoringUI - Handles the monitoring UI
type MonitoringUI struct {
	config           MonitoringUIConfig
	metricsCollector *MetricsCollector
	httpServer       *http.Server
	upgrader         websocket.Upgrader
	clients          map[*websocket.Conn]bool
	clientsMutex     sync.Mutex
	proxy            *Proxy

	// WebSocket broadcast rate limiting
	broadcastMutex    sync.Mutex
	lastBroadcast     time.Time
	broadcastMinDelay time.Duration
	pendingBroadcast  bool

	// Prometheus metrics
	prometheusPath string
}

// NewMonitoringUI - Creates a new monitoring UI
func NewMonitoringUI(proxy *Proxy) *MonitoringUI {
	dlog.Debugf("Creating new monitoring UI instance")

	if proxy == nil {
		dlog.Errorf("Proxy is nil in NewMonitoringUI")
		return nil
	}

	// Set defaults for memory limits if not configured
	maxEntries := proxy.monitoringUI.MaxQueryLogEntries
	if maxEntries <= 0 {
		maxEntries = 100
	}
	maxMemoryMB := proxy.monitoringUI.MaxMemoryMB
	if maxMemoryMB <= 0 {
		maxMemoryMB = 1
	}

	// Initialize metrics collector
	metricsCollector := &MetricsCollector{
		startTime:          time.Now(),
		queryTypes:         make(map[string]uint64),
		serverResponseTime: make(map[string]uint64),
		serverQueryCount:   make(map[string]uint64),
		topDomains:         make(map[string]uint64),
		recentQueries:      make([]QueryLogEntry, 0, maxEntries),
		maxRecentQueries:   maxEntries,
		maxMemoryBytes:     int64(maxMemoryMB * 1024 * 1024),
		currentMemoryBytes: 0,
		privacyLevel:       proxy.monitoringUI.PrivacyLevel,
		// Initialize caching with 1 second TTL
		cacheTTL:      time.Second,
		cachedMetrics: make(map[string]interface{}),
		// Initialize Prometheus
		prometheusEnabled: proxy.monitoringUI.PrometheusEnabled,
	}

	dlog.Debugf("Metrics collector initialized with privacy level: %d", metricsCollector.privacyLevel)

	// Create and return the monitoring UI instance
	return &MonitoringUI{
		config:           proxy.monitoringUI,
		metricsCollector: metricsCollector,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					return true // Allow requests without Origin header (direct connections)
				}
				host := r.Host
				if host == "" {
					return false
				}
				// Allow same-origin requests and localhost variations
				return origin == "http://"+host || origin == "https://"+host ||
					origin == "http://localhost:8080" || origin == "https://localhost:8080" ||
					origin == "http://127.0.0.1:8080" || origin == "https://127.0.0.1:8080"
			},
		},
		clients: make(map[*websocket.Conn]bool),
		proxy:   proxy,
		// Initialize broadcast rate limiting with 100ms minimum delay
		broadcastMinDelay: 100 * time.Millisecond,
		// Initialize Prometheus path
		prometheusPath: func() string {
			if proxy.monitoringUI.PrometheusPath != "" {
				return proxy.monitoringUI.PrometheusPath
			}
			return "/metrics"
		}(),
	}
}

// Start - Starts the monitoring UI
func (ui *MonitoringUI) Start() error {
	if !ui.config.Enabled {
		return nil
	}

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", ui.handleRoot)
	mux.HandleFunc("/api/metrics", ui.handleMetrics)
	mux.HandleFunc("/api/ws", ui.handleWebSocket)
	mux.HandleFunc("/static/monitoring.js", ui.handleStaticJS)
	mux.HandleFunc("/static/", ui.handleStatic)

	// Add Prometheus endpoint if enabled
	if ui.metricsCollector.prometheusEnabled {
		mux.HandleFunc(ui.prometheusPath, ui.handlePrometheus)
		dlog.Debugf("Prometheus metrics endpoint enabled at %s", ui.prometheusPath)
	}

	ui.httpServer = &http.Server{
		Addr:         ui.config.ListenAddress,
		Handler:      ui.basicAuthMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start HTTP server
	go func() {
		var err error
		if ui.config.TLSCertificate != "" && ui.config.TLSKey != "" {
			dlog.Noticef("Starting monitoring UI on https://%s", ui.config.ListenAddress)
			err = ui.httpServer.ListenAndServeTLS(ui.config.TLSCertificate, ui.config.TLSKey)
		} else {
			dlog.Noticef("Starting monitoring UI on http://%s", ui.config.ListenAddress)
			err = ui.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			dlog.Errorf("Monitoring UI server error: %v", err)
		}
	}()

	return nil
}

// Stop - Stops the monitoring UI
func (ui *MonitoringUI) Stop() error {
	if ui.httpServer != nil {
		return ui.httpServer.Close()
	}
	return nil
}

// UpdateMetrics - Updates metrics with a new query
func (ui *MonitoringUI) UpdateMetrics(pluginsState PluginsState, msg *dns.Msg, start time.Time) {
	if !ui.config.Enabled {
		return
	}

	dlog.Debugf("Updating metrics for query: %s", pluginsState.qName)

	mc := ui.metricsCollector
	now := time.Now()

	// Update counters (total queries, cache, QPS) - separate lock
	mc.countersMutex.Lock()
	mc.totalQueries++
	dlog.Debugf("Total queries now: %d", mc.totalQueries)

	// Update queries per second
	elapsed := now.Sub(mc.lastQueriesTime).Seconds()
	if elapsed >= 1.0 || mc.lastQueriesTime.IsZero() {
		if mc.lastQueriesTime.IsZero() {
			// First query, initialize
			mc.lastQueriesTime = now
			mc.lastQueriesCount = 0
			mc.queriesPerSecond = 0
		} else {
			mc.queriesPerSecond = float64(mc.totalQueries-mc.lastQueriesCount) / elapsed
			mc.lastQueriesCount = mc.totalQueries
			mc.lastQueriesTime = now
		}
		dlog.Debugf("Updated QPS: %.2f", mc.queriesPerSecond)
	}

	// Update cache hits/misses
	if pluginsState.cacheHit {
		mc.cacheHits++
		dlog.Debugf("Cache hit, total hits: %d", mc.cacheHits)
	} else {
		mc.cacheMisses++
		dlog.Debugf("Cache miss, total misses: %d", mc.cacheMisses)
	}
	mc.countersMutex.Unlock()

	// Invalidate cache since counters changed
	mc.invalidateCache()

	// Update query types - separate lock
	if msg != nil && len(msg.Question) > 0 {
		question := msg.Question[0]
		qType, ok := dns.TypeToString[question.Qtype]
		if !ok {
			qType = fmt.Sprintf("%d", question.Qtype)
		}
		mc.queryTypesMutex.Lock()
		mc.queryTypes[qType]++
		dlog.Debugf("Query type %s, count: %d", qType, mc.queryTypes[qType])
		mc.queryTypesMutex.Unlock()
	} else {
		dlog.Debugf("No question in message or message is nil")
	}

	// Update response time - back to counters lock
	responseTime := time.Since(start).Milliseconds()
	mc.countersMutex.Lock()
	mc.responseTimeSum += uint64(responseTime)
	mc.responseTimeCount++
	dlog.Debugf("Response time: %dms, avg: %.2fms", responseTime, float64(mc.responseTimeSum)/float64(mc.responseTimeCount))
	mc.countersMutex.Unlock()

	// Update server stats - separate lock
	if pluginsState.serverName != "" && pluginsState.serverName != "-" {
		mc.serverMutex.Lock()
		mc.serverQueryCount[pluginsState.serverName]++
		mc.serverResponseTime[pluginsState.serverName] += uint64(responseTime)
		dlog.Debugf("Server %s, queries: %d, avg response: %.2fms",
			pluginsState.serverName,
			mc.serverQueryCount[pluginsState.serverName],
			float64(mc.serverResponseTime[pluginsState.serverName])/float64(mc.serverQueryCount[pluginsState.serverName]))
		mc.serverMutex.Unlock()
	} else {
		dlog.Debugf("No server name or server is '-'")
	}

	// Update top domains - separate lock
	if mc.privacyLevel < 2 {
		sanitizedDomain := sanitizeString(pluginsState.qName)
		mc.domainMutex.Lock()
		mc.topDomains[sanitizedDomain]++
		dlog.Debugf("Domain %s, count: %d", sanitizedDomain, mc.topDomains[sanitizedDomain])
		mc.domainMutex.Unlock()
	}

	// Update recent queries if enabled, but only if privacy level < 2
	if ui.config.EnableQueryLog && mc.privacyLevel < 2 {
		var clientIP string
		if mc.privacyLevel >= 1 {
			clientIP = "anonymized"
		} else if pluginsState.clientAddr != nil {
			switch pluginsState.clientProto {
			case "udp":
				if udpAddr, ok := (*pluginsState.clientAddr).(*net.UDPAddr); ok && udpAddr != nil {
					clientIP = udpAddr.IP.String()
				} else {
					clientIP = "unknown-udp"
				}
			case "tcp", "local_doh":
				if tcpAddr, ok := (*pluginsState.clientAddr).(*net.TCPAddr); ok && tcpAddr != nil {
					clientIP = tcpAddr.IP.String()
				} else {
					clientIP = "unknown-tcp"
				}
			default:
				clientIP = "internal"
			}
		} else {
			clientIP = "no-client-addr"
		}

		returnCode, ok := PluginsReturnCodeToString[pluginsState.returnCode]
		if !ok {
			returnCode = fmt.Sprintf("%d", pluginsState.returnCode)
		}

		var qType string
		if msg != nil && len(msg.Question) > 0 {
			var ok bool
			qType, ok = dns.TypeToString[msg.Question[0].Qtype]
			if !ok {
				qType = fmt.Sprintf("%d", msg.Question[0].Qtype)
			}
		} else {
			qType = "unknown"
		}

		entry := QueryLogEntry{
			Timestamp:    now,
			ClientIP:     clientIP,
			Domain:       sanitizeString(pluginsState.qName),
			Type:         sanitizeString(qType),
			ResponseCode: sanitizeString(returnCode),
			ResponseTime: responseTime,
			Server:       sanitizeString(pluginsState.serverName),
			CacheHit:     pluginsState.cacheHit,
		}

		mc.queryLogMutex.Lock()
		entrySize := entry.EstimateMemoryUsage()

		// Check if adding this entry would exceed memory limit
		if mc.currentMemoryBytes+entrySize > mc.maxMemoryBytes {
			// Remove oldest entries until we have enough space
			for len(mc.recentQueries) > 0 && mc.currentMemoryBytes+entrySize > mc.maxMemoryBytes {
				oldEntry := mc.recentQueries[0]
				mc.recentQueries = mc.recentQueries[1:]
				mc.currentMemoryBytes -= oldEntry.EstimateMemoryUsage()
			}
		}

		mc.recentQueries = append(mc.recentQueries, entry)
		mc.currentMemoryBytes += entrySize

		// Also enforce the max entries limit
		if len(mc.recentQueries) > mc.maxRecentQueries {
			oldEntry := mc.recentQueries[0]
			mc.recentQueries = mc.recentQueries[1:]
			mc.currentMemoryBytes -= oldEntry.EstimateMemoryUsage()
		}

		dlog.Debugf("Added query log entry, total entries: %d, memory usage: %d bytes",
			len(mc.recentQueries), mc.currentMemoryBytes)
		mc.queryLogMutex.Unlock()
	}

	// Broadcast updates to WebSocket clients (rate limited)
	ui.scheduleBroadcast()
}

// generatePrometheusMetrics - Generates Prometheus-formatted metrics
func (mc *MetricsCollector) generatePrometheusMetrics() string {
	if !mc.prometheusEnabled {
		return ""
	}

	mc.countersMutex.RLock()
	totalQueries := mc.totalQueries
	queriesPerSecond := mc.queriesPerSecond
	cacheHits := mc.cacheHits
	cacheMisses := mc.cacheMisses
	blockCount := mc.blockCount
	responseTimeSum := mc.responseTimeSum
	responseTimeCount := mc.responseTimeCount
	startTime := mc.startTime
	mc.countersMutex.RUnlock()

	// Calculate derived metrics
	var avgResponseTime float64
	if responseTimeCount > 0 {
		avgResponseTime = float64(responseTimeSum) / float64(responseTimeCount)
	}

	var cacheHitRatio float64
	totalCacheQueries := cacheHits + cacheMisses
	if totalCacheQueries > 0 {
		cacheHitRatio = float64(cacheHits) / float64(totalCacheQueries)
	}

	uptime := time.Since(startTime).Seconds()

	var result strings.Builder

	// Write help and type information for each metric
	result.WriteString("# HELP dnscrypt_proxy_build_info A metric with a constant '1' value labeled by version, goversion from which dnscrypt_proxy was built, and the goos and goarch for the build.\n")
	result.WriteString("# TYPE dnscrypt_proxy_build_info gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_build_info{goarch=\"%s\" goos=\"%s\" goversion=\"%s\" version=\"%s\"} 1\n", runtime.GOARCH, runtime.GOOS, runtime.Version(), AppVersion))

	result.WriteString("# HELP dnscrypt_proxy_queries_total Total number of DNS queries processed\n")
	result.WriteString("# TYPE dnscrypt_proxy_queries_total counter\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_queries_total %d\n", totalQueries))

	result.WriteString("# HELP dnscrypt_proxy_queries_per_second Current queries per second rate\n")
	result.WriteString("# TYPE dnscrypt_proxy_queries_per_second gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_queries_per_second %.2f\n", queriesPerSecond))

	result.WriteString("# HELP dnscrypt_proxy_uptime_seconds Uptime in seconds\n")
	result.WriteString("# TYPE dnscrypt_proxy_uptime_seconds counter\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_uptime_seconds %.0f\n", uptime))

	result.WriteString("# HELP dnscrypt_proxy_cache_hits_total Total number of cache hits\n")
	result.WriteString("# TYPE dnscrypt_proxy_cache_hits_total counter\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_cache_hits_total %d\n", cacheHits))

	result.WriteString("# HELP dnscrypt_proxy_cache_misses_total Total number of cache misses\n")
	result.WriteString("# TYPE dnscrypt_proxy_cache_misses_total counter\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_cache_misses_total %d\n", cacheMisses))

	result.WriteString("# HELP dnscrypt_proxy_cache_hit_ratio Current cache hit ratio\n")
	result.WriteString("# TYPE dnscrypt_proxy_cache_hit_ratio gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_cache_hit_ratio %.4f\n", cacheHitRatio))

	result.WriteString("# HELP dnscrypt_proxy_blocked_queries_total Total number of blocked queries\n")
	result.WriteString("# TYPE dnscrypt_proxy_blocked_queries_total counter\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_blocked_queries_total %d\n", blockCount))

	result.WriteString("# HELP dnscrypt_proxy_response_time_average_ms Average response time in milliseconds\n")
	result.WriteString("# TYPE dnscrypt_proxy_response_time_average_ms gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_response_time_average_ms %.2f\n", avgResponseTime))

	// Add server-specific metrics
	mc.serverMutex.RLock()
	result.WriteString("# HELP dnscrypt_proxy_server_queries_total Total queries per server\n")
	result.WriteString("# TYPE dnscrypt_proxy_server_queries_total counter\n")
	for server, count := range mc.serverQueryCount {
		sanitizedServer := sanitizeString(server)
		result.WriteString(fmt.Sprintf("dnscrypt_proxy_server_queries_total{server=\"%s\"} %d\n", sanitizedServer, count))
	}

	result.WriteString("# HELP dnscrypt_proxy_server_response_time_average_ms Average response time per server in milliseconds\n")
	result.WriteString("# TYPE dnscrypt_proxy_server_response_time_average_ms gauge\n")
	for server, count := range mc.serverQueryCount {
		if count > 0 {
			avgTime := float64(mc.serverResponseTime[server]) / float64(count)
			sanitizedServer := sanitizeString(server)
			result.WriteString(fmt.Sprintf("dnscrypt_proxy_server_response_time_average_ms{server=\"%s\"} %.2f\n", sanitizedServer, avgTime))
		}
	}
	mc.serverMutex.RUnlock()

	// Add query type metrics
	mc.queryTypesMutex.RLock()
	result.WriteString("# HELP dnscrypt_proxy_query_type_total Total queries per DNS record type\n")
	result.WriteString("# TYPE dnscrypt_proxy_query_type_total counter\n")
	for qtype, count := range mc.queryTypes {
		sanitizedQtype := sanitizeString(qtype)
		result.WriteString(fmt.Sprintf("dnscrypt_proxy_query_type_total{type=\"%s\"} %d\n", sanitizedQtype, count))
	}
	mc.queryTypesMutex.RUnlock()

	// Add memory usage metrics if available
	mc.queryLogMutex.RLock()
	queryLogEntries := len(mc.recentQueries)
	memoryUsage := mc.currentMemoryBytes
	mc.queryLogMutex.RUnlock()

	result.WriteString("# HELP dnscrypt_proxy_query_log_entries Current number of query log entries in memory\n")
	result.WriteString("# TYPE dnscrypt_proxy_query_log_entries gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_query_log_entries %d\n", queryLogEntries))

	result.WriteString("# HELP dnscrypt_proxy_memory_usage_bytes Current memory usage in bytes for query logs\n")
	result.WriteString("# TYPE dnscrypt_proxy_memory_usage_bytes gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_memory_usage_bytes %d\n", memoryUsage))

	return result.String()
}

// invalidateCache - Marks the cache as stale (call when data changes)
func (mc *MetricsCollector) invalidateCache() {
	mc.cacheMutex.Lock()
	mc.cacheLastUpdate = time.Time{} // Zero time to force refresh
	mc.cacheMutex.Unlock()
}

// GetMetrics - Returns the current metrics
func (mc *MetricsCollector) GetMetrics() map[string]interface{} {
	dlog.Debugf("GetMetrics called")

	// Check cache first
	mc.cacheMutex.RLock()
	if time.Since(mc.cacheLastUpdate) < mc.cacheTTL && mc.cachedMetrics != nil {
		cached := mc.cachedMetrics
		mc.cacheMutex.RUnlock()
		dlog.Debugf("Returning cached metrics")
		return cached
	}
	mc.cacheMutex.RUnlock()

	// Read basic counters first
	mc.countersMutex.RLock()
	totalQueries := mc.totalQueries
	queriesPerSecond := mc.queriesPerSecond
	cacheHits := mc.cacheHits
	cacheMisses := mc.cacheMisses
	blockCount := mc.blockCount
	responseTimeSum := mc.responseTimeSum
	responseTimeCount := mc.responseTimeCount
	startTime := mc.startTime
	mc.countersMutex.RUnlock()

	dlog.Debugf("GetMetrics - total queries: %d", totalQueries)

	// Calculate average response time
	var avgResponseTime float64
	if responseTimeCount > 0 {
		avgResponseTime = float64(responseTimeSum) / float64(responseTimeCount)
	}

	// Calculate cache hit ratio (as decimal 0-1, not percentage)
	var cacheHitRatio float64
	totalCacheQueries := cacheHits + cacheMisses
	if totalCacheQueries > 0 {
		cacheHitRatio = float64(cacheHits) / float64(totalCacheQueries)
	}

	// Calculate per-server metrics sorted by increasing average response time
	serverMetrics := make([]map[string]interface{}, 0)

	// Create a slice of server performance data
	type serverPerf struct {
		name    string
		queries uint64
		avgTime float64
	}

	// Read server data with its own lock
	mc.serverMutex.RLock()
	serverPerfs := make([]serverPerf, 0, len(mc.serverQueryCount))
	for server, count := range mc.serverQueryCount {
		avgTime := float64(0)
		if count > 0 {
			avgTime = float64(mc.serverResponseTime[server]) / float64(count)
		}
		serverPerfs = append(serverPerfs, serverPerf{
			name:    server,
			queries: count,
			avgTime: avgTime,
		})
	}
	mc.serverMutex.RUnlock()

	// Sort by increasing average response time (faster servers first)
	sort.Slice(serverPerfs, func(i, j int) bool {
		if serverPerfs[i].avgTime != serverPerfs[j].avgTime {
			return serverPerfs[i].avgTime < serverPerfs[j].avgTime
		}
		return serverPerfs[i].name < serverPerfs[j].name
	})

	// Convert to map for JSON output
	for _, sp := range serverPerfs {
		serverMetrics = append(serverMetrics, map[string]interface{}{
			"name":            sp.name,
			"queries":         sp.queries,
			"avg_response_ms": sp.avgTime,
		})
	}

	// Get top domains (limited to 20) sorted by decreasing count
	topDomainsList := make([]map[string]interface{}, 0)
	if mc.privacyLevel < 2 {
		// Create a slice of domain-count pairs
		type domainCount struct {
			domain string
			count  uint64
		}
		// Read domain data with its own lock
		mc.domainMutex.RLock()
		domainCounts := make([]domainCount, 0, len(mc.topDomains))
		for domain, hits := range mc.topDomains {
			domainCounts = append(domainCounts, domainCount{domain, hits})
		}
		mc.domainMutex.RUnlock()

		// Sort by decreasing count
		sort.Slice(domainCounts, func(i, j int) bool {
			if domainCounts[i].count != domainCounts[j].count {
				return domainCounts[i].count > domainCounts[j].count
			}
			return domainCounts[i].domain < domainCounts[j].domain
		})

		// Take top 20
		count := 0
		for _, dc := range domainCounts {
			topDomainsList = append(topDomainsList, map[string]interface{}{
				"domain": sanitizeString(dc.domain),
				"count":  dc.count,
			})
			count++
			if count >= 20 {
				break
			}
		}
	}

	// Get query type distribution sorted by decreasing count and limited to 10
	queryTypesList := make([]map[string]interface{}, 0)

	// Create a slice of query type-count pairs
	type queryTypeCount struct {
		qtype string
		count uint64
	}
	// Read query types with its own lock
	mc.queryTypesMutex.RLock()
	queryTypeCounts := make([]queryTypeCount, 0, len(mc.queryTypes))
	for qtype, count := range mc.queryTypes {
		queryTypeCounts = append(queryTypeCounts, queryTypeCount{qtype, count})
	}
	mc.queryTypesMutex.RUnlock()

	// Sort by decreasing count
	sort.Slice(queryTypeCounts, func(i, j int) bool {
		if queryTypeCounts[i].count != queryTypeCounts[j].count {
			return queryTypeCounts[i].count > queryTypeCounts[j].count
		}
		return queryTypeCounts[i].qtype < queryTypeCounts[j].qtype
	})

	// Take top 10
	count := 0
	for _, qtc := range queryTypeCounts {
		queryTypesList = append(queryTypesList, map[string]interface{}{
			"type":  qtc.qtype,
			"count": qtc.count,
		})
		count++
		if count >= 10 {
			break
		}
	}

	// Read recent queries with its own lock
	mc.queryLogMutex.RLock()
	recentQueries := make([]QueryLogEntry, len(mc.recentQueries))
	copy(recentQueries, mc.recentQueries)
	mc.queryLogMutex.RUnlock()

	// Return all metrics and cache the result
	metrics := map[string]interface{}{
		"total_queries":      totalQueries,
		"queries_per_second": queriesPerSecond,
		"uptime_seconds":     time.Since(startTime).Seconds(),
		"cache_hit_ratio":    cacheHitRatio,
		"cache_hits":         cacheHits,
		"cache_misses":       cacheMisses,
		"avg_response_time":  avgResponseTime,
		"blocked_queries":    blockCount,
		"servers":            serverMetrics,
		"top_domains":        topDomainsList,
		"query_types":        queryTypesList,
		"recent_queries":     recentQueries,
	}

	// Cache the computed metrics
	mc.cacheMutex.Lock()
	mc.cachedMetrics = metrics
	mc.cacheLastUpdate = time.Now()
	mc.cacheMutex.Unlock()

	dlog.Debugf("Computed and cached new metrics")
	return metrics
}

// setCORSHeaders - Sets standard CORS headers for all responses
func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

// setDynamicCacheHeaders - Sets cache headers for dynamic content (metrics, API)
func setDynamicCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

// setStaticCacheHeaders - Sets cache headers for static content
func setStaticCacheHeaders(w http.ResponseWriter, maxAge int) {
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	w.Header().Set("Expires", time.Now().Add(time.Duration(maxAge)*time.Second).Format(http.TimeFormat))
}

// handleTestQuery - Handles test query requests for debugging
func (ui *MonitoringUI) handleTestQuery(w http.ResponseWriter, r *http.Request) {
	dlog.Debugf("Adding test query")

	// Test queries modify state - no cache
	setDynamicCacheHeaders(w)

	// Create a fake DNS message
	msg := &dns.Msg{}
	msg.SetQuestion("test.example.com.", dns.TypeA)

	// Create a fake plugin state
	pluginsState := PluginsState{
		qName:       "test.example.com",
		serverName:  "cloudflare",
		clientProto: "udp",
		questionMsg: msg,
		cacheHit:    false,
	}

	// Update metrics
	ui.UpdateMetrics(pluginsState, msg, time.Now().Add(-10*time.Millisecond))

	// Return success
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Test query added"))
}

// handleRoot - Handles the root path
func (ui *MonitoringUI) handleRoot(w http.ResponseWriter, r *http.Request) {
	dlog.Debugf("Received root request from %s", r.RemoteAddr)

	// Set CORS headers
	setCORSHeaders(w)

	// Handle preflight OPTIONS request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Test function to add a fake query for debugging
	if r.URL.Query().Get("test") == "1" {
		ui.handleTestQuery(w, r)
		return
	}

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Serve the main dashboard page - cache for 5 minutes since template is static
	setStaticCacheHeaders(w, 300)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(MainHTMLTemplate))
}

// handleMetrics - Handles the metrics API endpoint
func (ui *MonitoringUI) handleMetrics(w http.ResponseWriter, r *http.Request) {
	dlog.Debugf("Received metrics request from %s", r.RemoteAddr)

	// Set CORS headers and dynamic cache headers for API
	setCORSHeaders(w)
	setDynamicCacheHeaders(w)

	// Handle preflight OPTIONS request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	metrics := ui.metricsCollector.GetMetrics()

	w.Header().Set("Content-Type", "application/json")

	// Check if this is a JSONP request
	callback := r.URL.Query().Get("callback")

	// Marshal the data to JSON
	jsonData, err := json.Marshal(metrics)
	if err != nil {
		dlog.Errorf("Error marshaling metrics: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	dlog.Debugf("Sending metrics response (%d bytes)", len(jsonData))

	// If it's a JSONP request, wrap the JSON in the callback function
	if callback != "" {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(callback + "("))
		w.Write(jsonData)
		w.Write([]byte(");"))
		dlog.Debugf("Sent JSONP response with callback: %s", callback)
	} else {
		// Regular JSON response
		w.Write(jsonData)
	}
}

// handleWebSocket - Handles WebSocket connections
func (ui *MonitoringUI) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers for WebSocket
	setCORSHeaders(w)

	// Handle preflight OPTIONS request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Configure upgrader with more permissive settings
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		dlog.Warnf("WebSocket upgrade error: %v", err)
		return
	}

	// Set read/write deadlines
	conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))

	ui.clientsMutex.Lock()
	ui.clients[conn] = true
	ui.clientsMutex.Unlock()

	// Send initial metrics
	metrics := ui.metricsCollector.GetMetrics()
	if err := conn.WriteJSON(metrics); err != nil {
		dlog.Warnf("WebSocket initial write error: %v", err)
		conn.Close()
		ui.clientsMutex.Lock()
		delete(ui.clients, conn)
		ui.clientsMutex.Unlock()
		return
	}

	// Handle client messages and disconnection
	go func() {
		defer func() {
			ui.clientsMutex.Lock()
			delete(ui.clients, conn)
			ui.clientsMutex.Unlock()
			conn.Close()
			dlog.Debugf("WebSocket connection closed and cleaned up")
		}()

		// Create a ping handler to keep the connection alive
		conn.SetPingHandler(func(data string) error {
			dlog.Debugf("Received ping from client")
			return conn.WriteControl(websocket.PongMessage, []byte{}, time.Now().Add(5*time.Second))
		})

		// Create a pong handler to respond to server pings
		conn.SetPongHandler(func(data string) error {
			dlog.Debugf("Received pong from client")
			conn.SetReadDeadline(time.Now().Add(120 * time.Second))
			return nil
		})

		for {
			// Reset read deadline for each message
			conn.SetReadDeadline(time.Now().Add(120 * time.Second))

			// Read message
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					dlog.Warnf("WebSocket unexpected close error: %v", err)
				} else {
					dlog.Debugf("WebSocket read error (normal): %v", err)
				}
				break
			}

			// Handle ping message from client
			if messageType == websocket.TextMessage {
				var msg map[string]interface{}
				if err := json.Unmarshal(message, &msg); err == nil {
					if msgType, ok := msg["type"].(string); ok && msgType == "ping" {
						dlog.Debugf("Received ping message from client")
						// Send a pong response
						conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
						if err := conn.WriteJSON(map[string]string{"type": "pong"}); err != nil {
							dlog.Warnf("Error sending pong: %v", err)
						}

						// Also send updated metrics
						conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
						if err := conn.WriteJSON(ui.metricsCollector.GetMetrics()); err != nil {
							dlog.Warnf("Error sending metrics after ping: %v", err)
						}
					}
				}
			}
		}
	}()

	// Send periodic pings to keep the connection alive
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ui.clientsMutex.Lock()
				if _, exists := ui.clients[conn]; !exists {
					ui.clientsMutex.Unlock()
					return // Connection is closed, stop the goroutine
				}
				ui.clientsMutex.Unlock()

				// Send ping
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(5*time.Second)); err != nil {
					dlog.Debugf("Error sending ping: %v", err)
					return
				}
			}
		}
	}()
}

// handleStatic - Handles static files
func (ui *MonitoringUI) handleStatic(w http.ResponseWriter, r *http.Request) {
	// This is a placeholder for serving static files
	// In this implementation, we're embedding everything in the HTML
	http.NotFound(w, r)
}

// handleStaticJS - Serves the JavaScript for the monitoring UI
func (ui *MonitoringUI) handleStaticJS(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	// JavaScript is static - cache for 1 hour
	setStaticCacheHeaders(w, 3600)
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte(MonitoringJSContent))
}

// handlePrometheus - Serves Prometheus metrics
func (ui *MonitoringUI) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	dlog.Debugf("Received Prometheus metrics request from %s", r.RemoteAddr)

	if !ui.metricsCollector.prometheusEnabled {
		http.NotFound(w, r)
		return
	}

	// Generate Prometheus metrics
	metrics := ui.metricsCollector.generatePrometheusMetrics()

	// Set appropriate headers for Prometheus
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	setDynamicCacheHeaders(w) // Always fresh for metrics

	// Write metrics
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(metrics))

	dlog.Debugf("Served Prometheus metrics (%d bytes)", len(metrics))
}

// basicAuthMiddleware - Adds basic authentication to the HTTP server
func (ui *MonitoringUI) basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if username is empty
		if ui.config.Username == "" {
			next.ServeHTTP(w, r)
			return
		}

		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(ui.config.Username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(ui.config.Password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="DNSCrypt Proxy Monitoring"`)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// scheduleBroadcast - Rate-limited scheduling of WebSocket broadcasts
func (ui *MonitoringUI) scheduleBroadcast() {
	ui.broadcastMutex.Lock()
	defer ui.broadcastMutex.Unlock()

	now := time.Now()
	timeSinceLastBroadcast := now.Sub(ui.lastBroadcast)

	if timeSinceLastBroadcast >= ui.broadcastMinDelay {
		// Enough time has passed, broadcast immediately
		ui.lastBroadcast = now
		ui.pendingBroadcast = false
		go ui.broadcastMetrics()
	} else {
		// Too soon, schedule a delayed broadcast if not already pending
		if !ui.pendingBroadcast {
			ui.pendingBroadcast = true
			delay := ui.broadcastMinDelay - timeSinceLastBroadcast
			go func() {
				time.Sleep(delay)
				ui.broadcastMutex.Lock()
				if ui.pendingBroadcast {
					ui.lastBroadcast = time.Now()
					ui.pendingBroadcast = false
					ui.broadcastMutex.Unlock()
					ui.broadcastMetrics()
				} else {
					ui.broadcastMutex.Unlock()
				}
			}()
		}
	}
}

// broadcastMetrics - Broadcasts metrics to all connected WebSocket clients
func (ui *MonitoringUI) broadcastMetrics() {
	metrics := ui.metricsCollector.GetMetrics()

	ui.clientsMutex.Lock()
	defer ui.clientsMutex.Unlock()

	for client := range ui.clients {
		client.SetWriteDeadline(time.Now().Add(5 * time.Second))
		err := client.WriteJSON(metrics)
		if err != nil {
			dlog.Debugf("WebSocket write error: %v", err)
			client.Close()
			delete(ui.clients, client)
		}
	}
}
