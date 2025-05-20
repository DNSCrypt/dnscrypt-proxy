package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

// MonitoringUIConfig - Configuration for the monitoring UI
type MonitoringUIConfig struct {
	Enabled        bool   `toml:"enabled"`
	ListenAddress  string `toml:"listen_address"`
	Username       string `toml:"username"`
	Password       string `toml:"password"`
	TLSCertificate string `toml:"tls_certificate"`
	TLSKey         string `toml:"tls_key"`
	EnableQueryLog bool   `toml:"enable_query_log"`
	PrivacyLevel   int    `toml:"privacy_level"` // 0: show all, 1: anonymize clients, 2: aggregate only
}

// MetricsCollector - Collects and stores metrics for the monitoring UI
type MetricsCollector struct {
	sync.RWMutex
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
	privacyLevel       int
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

// MonitoringUI - Handles the monitoring UI
type MonitoringUI struct {
	config           MonitoringUIConfig
	metricsCollector *MetricsCollector
	httpServer       *http.Server
	upgrader         websocket.Upgrader
	clients          map[*websocket.Conn]bool
	clientsMutex     sync.Mutex
	proxy            *Proxy
}

// NewMonitoringUI - Creates a new monitoring UI
func NewMonitoringUI(proxy *Proxy) *MonitoringUI {
	dlog.Debugf("Creating new monitoring UI instance")

	if proxy == nil {
		dlog.Errorf("Proxy is nil in NewMonitoringUI")
		return nil
	}

	// Initialize metrics collector
	metricsCollector := &MetricsCollector{
		startTime:          time.Now(),
		queryTypes:         make(map[string]uint64),
		serverResponseTime: make(map[string]uint64),
		serverQueryCount:   make(map[string]uint64),
		topDomains:         make(map[string]uint64),
		recentQueries:      make([]QueryLogEntry, 0, 100),
		maxRecentQueries:   100,
		privacyLevel:       proxy.monitoringUI.PrivacyLevel,
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
				return true
			},
		},
		clients: make(map[*websocket.Conn]bool),
		proxy:   proxy,
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
	mux.HandleFunc("/static/", ui.handleStatic)

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
	mc.Lock()
	defer mc.Unlock()

	// Update total queries
	mc.totalQueries++
	dlog.Debugf("Total queries now: %d", mc.totalQueries)

	// Update queries per second
	now := time.Now()
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

	// Update query types
	if msg != nil && len(msg.Question) > 0 {
		question := msg.Question[0]
		qType, ok := dns.TypeToString[question.Qtype]
		if !ok {
			qType = fmt.Sprintf("%d", question.Qtype)
		}
		mc.queryTypes[qType]++
		dlog.Debugf("Query type %s, count: %d", qType, mc.queryTypes[qType])
	} else {
		dlog.Debugf("No question in message or message is nil")
	}

	// Update response time
	responseTime := time.Since(start).Milliseconds()
	mc.responseTimeSum += uint64(responseTime)
	mc.responseTimeCount++
	dlog.Debugf("Response time: %dms, avg: %.2fms", responseTime, float64(mc.responseTimeSum)/float64(mc.responseTimeCount))

	// Update server stats
	if pluginsState.serverName != "" && pluginsState.serverName != "-" {
		mc.serverQueryCount[pluginsState.serverName]++
		mc.serverResponseTime[pluginsState.serverName] += uint64(responseTime)
		dlog.Debugf("Server %s, queries: %d, avg response: %.2fms",
			pluginsState.serverName,
			mc.serverQueryCount[pluginsState.serverName],
			float64(mc.serverResponseTime[pluginsState.serverName])/float64(mc.serverQueryCount[pluginsState.serverName]))
	} else {
		dlog.Debugf("No server name or server is '-'")
	}

	// Update top domains
	if mc.privacyLevel < 2 {
		mc.topDomains[pluginsState.qName]++
		dlog.Debugf("Domain %s, count: %d", pluginsState.qName, mc.topDomains[pluginsState.qName])
	}

	// Update recent queries if enabled
	if ui.config.EnableQueryLog {
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
			Domain:       pluginsState.qName,
			Type:         qType,
			ResponseCode: returnCode,
			ResponseTime: responseTime,
			Server:       pluginsState.serverName,
			CacheHit:     pluginsState.cacheHit,
		}

		mc.recentQueries = append(mc.recentQueries, entry)
		if len(mc.recentQueries) > mc.maxRecentQueries {
			mc.recentQueries = mc.recentQueries[1:]
		}
		dlog.Debugf("Added query log entry, total entries: %d", len(mc.recentQueries))
	}

	// Broadcast updates to WebSocket clients
	go ui.broadcastMetrics()
}

// GetMetrics - Returns the current metrics
func (mc *MetricsCollector) GetMetrics() map[string]interface{} {
	mc.RLock()
	defer mc.RUnlock()

	dlog.Debugf("GetMetrics called - total queries: %d", mc.totalQueries)

	// Calculate average response time
	var avgResponseTime float64
	if mc.responseTimeCount > 0 {
		avgResponseTime = float64(mc.responseTimeSum) / float64(mc.responseTimeCount)
	}

	// Calculate cache hit ratio
	var cacheHitRatio float64
	totalCacheQueries := mc.cacheHits + mc.cacheMisses
	if totalCacheQueries > 0 {
		cacheHitRatio = float64(mc.cacheHits) / float64(totalCacheQueries)
	}

	// Calculate per-server metrics sorted by increasing average response time
	serverMetrics := make([]map[string]interface{}, 0)

	// Create a slice of server performance data
	type serverPerf struct {
		name    string
		queries uint64
		avgTime float64
	}
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

	// Sort by increasing average response time (faster servers first)
	sort.Slice(serverPerfs, func(i, j int) bool {
		return serverPerfs[i].avgTime < serverPerfs[j].avgTime
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
		domainCounts := make([]domainCount, 0, len(mc.topDomains))
		for domain, hits := range mc.topDomains {
			domainCounts = append(domainCounts, domainCount{domain, hits})
		}

		// Sort by decreasing count
		sort.Slice(domainCounts, func(i, j int) bool {
			return domainCounts[i].count > domainCounts[j].count
		})

		// Take top 20
		count := 0
		for _, dc := range domainCounts {
			topDomainsList = append(topDomainsList, map[string]interface{}{
				"domain": dc.domain,
				"count":  dc.count,
			})
			count++
			if count >= 20 {
				break
			}
		}
	}

	// Get query type distribution
	queryTypesList := make([]map[string]interface{}, 0)
	for qtype, count := range mc.queryTypes {
		queryTypesList = append(queryTypesList, map[string]interface{}{
			"type":  qtype,
			"count": count,
		})
	}

	// Return all metrics
	return map[string]interface{}{
		"total_queries":      mc.totalQueries,
		"queries_per_second": mc.queriesPerSecond,
		"uptime_seconds":     time.Since(mc.startTime).Seconds(),
		"cache_hit_ratio":    cacheHitRatio,
		"cache_hits":         mc.cacheHits,
		"cache_misses":       mc.cacheMisses,
		"avg_response_time":  avgResponseTime,
		"blocked_queries":    mc.blockCount,
		"servers":            serverMetrics,
		"top_domains":        topDomainsList,
		"query_types":        queryTypesList,
		"recent_queries":     mc.recentQueries,
	}
}

// handleRoot - Handles the root path
func (ui *MonitoringUI) handleRoot(w http.ResponseWriter, r *http.Request) {
	dlog.Debugf("Received root request from %s", r.RemoteAddr)

	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// Handle preflight OPTIONS request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Test function to add a fake query for debugging
	if r.URL.Query().Get("test") == "1" {
		dlog.Debugf("Adding test query")

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
		return
	}

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// If this is a simple version request, return a simple page
	if r.URL.Query().Get("simple") == "1" {
		metrics := ui.metricsCollector.GetMetrics()

		// Create a simple HTML page with the metrics
		simpleHTML := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>DNSCrypt Proxy Monitoring (Simple)</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body { font-family: sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        table { border-collapse: collapse; width: 100%%; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>DNSCrypt Proxy Monitoring (Simple View)</h1>
    <p>Auto-refreshes every 5 seconds. <a href="/">Switch to full dashboard</a></p>

    <h2>Overview</h2>
    <table>
        <tr><th>Total Queries</th><td>%d</td></tr>
        <tr><th>Queries Per Second</th><td>%.2f</td></tr>
        <tr><th>Uptime</th><td>%.0f seconds</td></tr>
        <tr><th>Cache Hit Ratio</th><td>%.2f%%</td></tr>
        <tr><th>Cache Hits</th><td>%d</td></tr>
        <tr><th>Cache Misses</th><td>%d</td></tr>
    </table>

    <p><small>Generated at %s</small></p>
</body>
</html>`,
			metrics["total_queries"],
			metrics["queries_per_second"],
			metrics["uptime_seconds"],
			metrics["cache_hit_ratio"].(float64)*100,
			metrics["cache_hits"],
			metrics["cache_misses"],
			time.Now().Format(time.RFC1123))

		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(simpleHTML))
		dlog.Debugf("Sent simple HTML page")
		return
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNSCrypt Proxy Monitoring</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 0;
            color: #333;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background-color: #2c3e50;
            color: white;
            padding: 1rem;
            margin-bottom: 20px;
        }
        h1 {
            margin: 0;
            font-size: 1.5rem;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 20px;
        }
        .card h2 {
            margin-top: 0;
            font-size: 1.2rem;
            color: #2c3e50;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .stat {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        .stat-label {
            font-weight: bold;
        }
        .chart-container {
            height: 200px;
            margin-top: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        table th, table td {
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid #eee;
        }
        table th {
            background-color: #f9f9f9;
        }
    </style>
</head>
<body>
    <header>
        <h1>DNSCrypt Proxy Monitoring Dashboard</h1>
        <div style="position: absolute; top: 10px; right: 10px;">
            <a href="/?simple=1" style="color: white; text-decoration: underline; margin-right: 15px;">Simple View</a>
            <a href="/api/metrics" target="_blank" style="color: white; text-decoration: underline;">Raw Data</a>
        </div>
    </header>
    <div class="container">
        <!-- Loading indicator -->
        <div id="loading-indicator" style="text-align: center; padding: 40px; margin: 20px 0; background-color: #f8f9fa; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
            <h2>Loading DNSCrypt Proxy Monitoring...</h2>
            <p>Please wait while we connect to the monitoring service.</p>
            <p>If this message persists, please check that the DNSCrypt Proxy is running with monitoring enabled.</p>
            <div style="margin: 20px 0; height: 4px; background-color: #eee; border-radius: 2px; overflow: hidden;">
                <div id="loading-bar" style="height: 100%; width: 0%; background-color: #2c3e50; animation: loading 2s infinite linear;"></div>
            </div>
            <style>
                @keyframes loading {
                    0% { width: 0%; }
                    50% { width: 100%; }
                    100% { width: 0%; }
                }
            </style>
        </div>

        <div class="dashboard">
            <div class="card">
                <h2>Overview</h2>
                <div class="stat">
                    <span class="stat-label">Total Queries:</span>
                    <span id="total-queries">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Queries Per Second:</span>
                    <span id="qps">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Uptime:</span>
                    <span id="uptime">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Avg Response Time:</span>
                    <span id="avg-response-time">-</span>
                </div>
            </div>
            <div class="card">
                <h2>Cache Performance</h2>
                <div class="stat">
                    <span class="stat-label">Cache Hit Ratio:</span>
                    <span id="cache-hit-ratio">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Cache Hits:</span>
                    <span id="cache-hits">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Cache Misses:</span>
                    <span id="cache-misses">-</span>
                </div>
                <div class="chart-container" id="cache-chart"></div>
            </div>
            <div class="card">
                <h2>Query Types</h2>
                <div id="query-types-container">
                    <table id="query-types-table">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Count</th>
                            </tr>
                        </thead>
                        <tbody>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Server Performance</h2>
            <table id="server-table">
                <thead>
                    <tr>
                        <th>Server</th>
                        <th>Queries</th>
                        <th>Avg Response Time</th>
                    </tr>
                </thead>
                <tbody>
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Top Domains</h2>
            <table id="domains-table">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Recent Queries</h2>
            <table id="queries-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Domain</th>
                        <th>Type</th>
                        <th>Client</th>
                        <th>Server</th>
                        <th>Response</th>
                        <th>Time (ms)</th>
                    </tr>
                </thead>
                <tbody>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // Error handling function with fallback to static content
        function handleError(error) {
            console.error('Error:', error);
            try {
                // Show error message
                document.getElementById('total-queries').textContent = 'Error loading data';

                // Update the loading indicator with error information
                var loadingIndicator = document.getElementById('loading-indicator');
                if (loadingIndicator) {
                    loadingIndicator.style.backgroundColor = '#f8d7da';
                    loadingIndicator.style.color = '#721c24';
                    loadingIndicator.style.display = 'block';

                    loadingIndicator.innerHTML = '<h2>Connection Error</h2>' +
                        '<p>Unable to connect to the monitoring server. This could be due to:</p>' +
                        '<ul style="text-align: left; display: inline-block;">' +
                        '<li>The server is still starting up</li>' +
                        '<li>Network connectivity issues</li>' +
                        '<li>Server is under heavy load</li>' +
                        '</ul>' +
                        '<p>The page will automatically retry connecting in 10 seconds.</p>' +
                        '<p>You can also try:</p>' +
                        '<ul style="text-align: left; display: inline-block;">' +
                        '<li>Refreshing the page</li>' +
                        '<li>Checking if the DNSCrypt Proxy is running</li>' +
                        '<li>Verifying the monitoring UI is enabled in the configuration</li>' +
                        '</ul>' +
                        '<div style="margin: 20px 0; height: 4px; background-color: #eee; border-radius: 2px; overflow: hidden;">' +
                        '<div style="height: 100%; width: 100%; background-color: #dc3545; animation: none;"></div>' +
                        '</div>' +
                        '<button onclick="window.location.reload()" style="padding: 10px 20px; background-color: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer;">Retry Now</button>';
                } else {
                    // Fallback if loading indicator doesn't exist
                    var fallbackDiv = document.createElement('div');
                    fallbackDiv.className = 'card';
                    fallbackDiv.style.marginTop = '20px';
                    fallbackDiv.style.padding = '20px';
                    fallbackDiv.style.backgroundColor = '#f8d7da';
                    fallbackDiv.style.color = '#721c24';
                    fallbackDiv.style.borderRadius = '5px';

                    fallbackDiv.innerHTML = '<h3>Connection Error</h3>' +
                        '<p>Unable to connect to the monitoring server.</p>' +
                        '<p>The page will automatically retry connecting.</p>' +
                        '<button onclick="window.location.reload()" style="padding: 10px 20px; background-color: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer;">Retry Now</button>';

                    // Add the fallback message to the page if it doesn't already exist
                    if (!document.getElementById('fallback-message')) {
                        fallbackDiv.id = 'fallback-message';
                        document.querySelector('.container').appendChild(fallbackDiv);
                    }
                }

                // Schedule a page reload after 10 seconds
                setTimeout(function() {
                    if (!document.hidden) { // Only reload if the page is visible
                        console.log('Auto-reloading page after error...');
                        window.location.reload();
                    }
                }, 10000);
            } catch (e) {
                console.error('Failed to update error message:', e);
            }
        }

        // Safe update function that handles missing data
        function safeUpdateDashboard(data) {
            try {
                if (!data) {
                    console.error('No data provided to safeUpdateDashboard');
                    return;
                }

                console.log('Updating dashboard with data');

                // Hide loading indicator when data is loaded
                var loadingIndicator = document.getElementById('loading-indicator');
                if (loadingIndicator) {
                    loadingIndicator.style.display = 'none';
                }

                // Update overview stats with null checks
                const totalQueries = data.total_queries !== undefined ? data.total_queries : 0;
                const qps = data.queries_per_second !== undefined ? data.queries_per_second : 0;
                const uptime = data.uptime_seconds !== undefined ? data.uptime_seconds : 0;
                const avgResponseTime = data.avg_response_time !== undefined ? data.avg_response_time : 0;

                document.getElementById('total-queries').textContent = totalQueries.toLocaleString();
                document.getElementById('qps').textContent = qps.toFixed(2);
                document.getElementById('uptime').textContent = formatUptime(uptime);
                document.getElementById('avg-response-time').textContent = avgResponseTime.toFixed(2) + ' ms';

                // Update cache stats with null checks
                const cacheHitRatio = data.cache_hit_ratio !== undefined ? data.cache_hit_ratio : 0;
                const cacheHits = data.cache_hits !== undefined ? data.cache_hits : 0;
                const cacheMisses = data.cache_misses !== undefined ? data.cache_misses : 0;

                document.getElementById('cache-hit-ratio').textContent = (cacheHitRatio * 100).toFixed(2) + '%';
                document.getElementById('cache-hits').textContent = cacheHits.toLocaleString();
                document.getElementById('cache-misses').textContent = cacheMisses.toLocaleString();

                // Update server table
                const serverTable = document.getElementById('server-table').getElementsByTagName('tbody')[0];
                serverTable.innerHTML = '';
                if (data.servers && Array.isArray(data.servers)) {
                    data.servers.forEach(server => {
                        const row = serverTable.insertRow();
                        row.insertCell(0).textContent = server.name || 'Unknown';
                        row.insertCell(1).textContent = (server.queries || 0).toLocaleString();
                        row.insertCell(2).textContent = (server.avg_response_ms || 0).toFixed(2) + ' ms';
                    });
                }

                // Update query types table
                const queryTypesTable = document.getElementById('query-types-table').getElementsByTagName('tbody')[0];
                queryTypesTable.innerHTML = '';
                if (data.query_types && Array.isArray(data.query_types)) {
                    data.query_types.forEach(type => {
                        const row = queryTypesTable.insertRow();
                        row.insertCell(0).textContent = type.type || 'Unknown';
                        row.insertCell(1).textContent = (type.count || 0).toLocaleString();
                    });
                }

                // Update top domains table
                const domainsTable = document.getElementById('domains-table').getElementsByTagName('tbody')[0];
                domainsTable.innerHTML = '';
                if (data.top_domains && Array.isArray(data.top_domains)) {
                    data.top_domains.forEach(domain => {
                        const row = domainsTable.insertRow();
                        row.insertCell(0).textContent = domain.domain || 'Unknown';
                        row.insertCell(1).textContent = (domain.count || 0).toLocaleString();
                    });
                }

                // Update recent queries table
                const queriesTable = document.getElementById('queries-table').getElementsByTagName('tbody')[0];
                queriesTable.innerHTML = '';
                if (data.recent_queries && Array.isArray(data.recent_queries)) {
                    data.recent_queries.slice().reverse().forEach(query => {
                        const row = queriesTable.insertRow();
                        row.insertCell(0).textContent = query.timestamp ? new Date(query.timestamp).toLocaleTimeString() : '-';
                        row.insertCell(1).textContent = query.domain || '-';
                        row.insertCell(2).textContent = query.type || '-';
                        row.insertCell(3).textContent = query.client_ip || '-';
                        row.insertCell(4).textContent = query.server || '-';
                        row.insertCell(5).textContent = query.response_code || '-';
                        row.insertCell(6).textContent = (query.response_time || 0) + ' ms';
                    });
                }
            } catch (error) {
                console.error('Error updating dashboard:', error);
            }
        }

        function formatUptime(seconds) {
            try {
                const days = Math.floor(seconds / 86400);
                const hours = Math.floor((seconds % 86400) / 3600);
                const minutes = Math.floor((seconds % 3600) / 60);
                const secs = Math.floor(seconds % 60);

                let result = '';
                if (days > 0) result += days + 'd ';
                if (hours > 0 || days > 0) result += hours + 'h ';
                if (minutes > 0 || hours > 0 || days > 0) result += minutes + 'm ';
                result += secs + 's';

                return result;
            } catch (error) {
                return 'Error';
            }
        }

        // Simple direct data loading approach
        function loadData() {
            console.log('Loading data using simple approach');

            // Create a script element to load the data
            var script = document.createElement('script');
            script.src = '/api/metrics?callback=handleMetricsData&_=' + new Date().getTime();
            script.onerror = function(e) {
                console.error('Script load error:', e);
                handleError(new Error('Failed to load metrics data'));

                // Try again after 5 seconds
                setTimeout(loadData, 5000);
            };

            // Add the script to the document
            document.body.appendChild(script);

            // Remove the script after a timeout (whether it loaded or not)
            setTimeout(function() {
                if (script.parentNode) {
                    script.parentNode.removeChild(script);
                }
            }, 10000);
        }

        // Callback function for the JSONP-style request
        window.handleMetricsData = function(data) {
            console.log('Data received via JSONP');
            if (data) {
                safeUpdateDashboard(data);
            } else {
                console.error('Empty data received');
                handleError(new Error('Empty data received'));
            }
        };

        // Start loading data
        loadData();

        // Fallback: If data doesn't load within 10 seconds, try direct XHR
        setTimeout(function() {
            var loadingIndicator = document.getElementById('loading-indicator');
            if (loadingIndicator && loadingIndicator.style.display !== 'none') {
                console.log('Loading indicator still visible after 10s, trying direct XHR');

                var xhr = new XMLHttpRequest();
                xhr.open('GET', '/api/metrics', true);
                xhr.timeout = 10000;

                xhr.onload = function() {
                    if (xhr.status >= 200 && xhr.status < 300) {
                        try {
                            var data = JSON.parse(xhr.responseText);
                            if (data) {
                                console.log('XHR fallback succeeded');
                                safeUpdateDashboard(data);
                            }
                        } catch (e) {
                            console.error('XHR fallback parse error:', e);
                        }
                    }
                };

                xhr.send();
            }
        }, 10000);

        // WebSocket connection with error handling and reconnection
        let wsReconnectAttempts = 0;
        const maxReconnectAttempts = 5;
        const reconnectDelay = 3000; // 3 seconds

        // WebSocket connection with fallback
        function connectWebSocket() {
            console.log('Attempting to connect WebSocket...');

            // Check if WebSocket is supported
            if (typeof WebSocket === 'undefined') {
                console.error('WebSocket is not supported in this browser');
                return null;
            }

            try {
                // Construct WebSocket URL
                var protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
                var host = window.location.host;
                var wsUrl = protocol + host + '/api/ws';
                console.log('WebSocket URL:', wsUrl);

                // Create WebSocket connection
                var ws = new WebSocket(wsUrl);

                // Connection opened
                ws.onopen = function() {
                    console.log('WebSocket connected successfully');
                    wsReconnectAttempts = 0; // Reset reconnect attempts on successful connection

                    // Send a ping to verify connection
                    try {
                        ws.send(JSON.stringify({type: 'ping'}));
                    } catch (e) {
                        console.error('Error sending ping:', e);
                    }
                };

                // Listen for messages
                ws.onmessage = function(event) {
                    try {
                        if (!event) {
                            console.warn('Received invalid WebSocket event');
                            return;
                        }

                        if (!event.data) {
                            console.warn('Received empty WebSocket message');
                            return;
                        }

                        console.log('Received WebSocket data');
                        var data = JSON.parse(event.data);
                        safeUpdateDashboard(data);
                    } catch (error) {
                        console.error('Error processing WebSocket data:', error);
                    }
                };

                // Handle errors
                ws.onerror = function(error) {
                    console.error('WebSocket error occurred:', error);
                };

                // Connection closed
                ws.onclose = function(event) {
                    console.log('WebSocket disconnected, code:', event.code, 'reason:', event.reason || 'No reason provided');

                    // Try to reconnect with exponential backoff
                    if (wsReconnectAttempts < maxReconnectAttempts) {
                        wsReconnectAttempts++;
                        var delay = reconnectDelay * Math.pow(2, wsReconnectAttempts - 1);
                        console.log('Attempting to reconnect in ' + delay + 'ms (attempt ' + wsReconnectAttempts + '/' + maxReconnectAttempts + ')');

                        setTimeout(function() {
                            var newWs = connectWebSocket();
                            if (newWs) {
                                // We can't update the global ws variable from here
                                // Instead, we'll rely on the polling fallback
                                console.log('New WebSocket connection established');
                            }
                        }, delay);
                    } else {
                        console.log('Max reconnect attempts reached, falling back to polling');
                    }
                };

                return ws;
            } catch (error) {
                console.error('Failed to create WebSocket connection:', error);
                return null;
            }
        }

        // Start WebSocket connection
        let ws = connectWebSocket();

        // Polling function with error handling - using script tag approach
        function pollMetrics() {
            console.log('Polling metrics...');

            if (!ws || ws.readyState !== WebSocket.OPEN) {
                // Use script tag approach for better compatibility
                var pollScript = document.createElement('script');
                pollScript.src = '/api/metrics?callback=handlePollData&_=' + new Date().getTime();

                // Handle errors
                pollScript.onerror = function(e) {
                    console.error('Polling script load error:', e);
                };

                // Add the script to the document
                document.body.appendChild(pollScript);

                // Remove the script after a timeout
                setTimeout(function() {
                    if (pollScript.parentNode) {
                        pollScript.parentNode.removeChild(pollScript);
                    }
                }, 5000);
            }
        }

        // Callback function for polling
        window.handlePollData = function(data) {
            if (data) {
                console.log('Polling data received successfully');
                safeUpdateDashboard(data);
            } else {
                console.warn('Received empty data from polling');
            }
        };

        // Initialize dashboard with default values
        function initializeDashboard() {
            document.getElementById('total-queries').textContent = '0';
            document.getElementById('qps').textContent = '0.00';
            document.getElementById('uptime').textContent = '0s';
            document.getElementById('avg-response-time').textContent = '0.00 ms';
            document.getElementById('cache-hit-ratio').textContent = '0.00%';
            document.getElementById('cache-hits').textContent = '0';
            document.getElementById('cache-misses').textContent = '0';
        }

        // Initialize with default values
        initializeDashboard();

        // Refresh data every 5 seconds as a fallback if WebSocket fails
        setInterval(pollMetrics, 5000);

        // Ultimate fallback: If nothing works after 20 seconds, create an iframe
        setTimeout(function() {
            var loadingIndicator = document.getElementById('loading-indicator');
            if (loadingIndicator && loadingIndicator.style.display !== 'none') {
                console.log('Still no data after 20s, trying iframe approach');

                // Create a message for the user
                loadingIndicator.innerHTML = '<h2>Loading Data...</h2>' +
                    '<p>We\'re having trouble loading data directly. Trying alternative method...</p>' +
                    '<div id="iframe-container" style="display: none;"></div>';

                // Create an iframe to load the metrics directly
                var iframe = document.createElement('iframe');
                iframe.style.display = 'none';
                iframe.src = '/api/metrics';

                // When the iframe loads, try to extract the data
                iframe.onload = function() {
                    try {
                        console.log('Iframe loaded, attempting to extract data');

                        // Try to get the content
                        var iframeContent = iframe.contentDocument || iframe.contentWindow.document;
                        var jsonText = iframeContent.body.innerText || iframeContent.body.textContent;

                        if (jsonText) {
                            var data = JSON.parse(jsonText);
                            console.log('Successfully extracted data from iframe');
                            safeUpdateDashboard(data);
                        }
                    } catch (e) {
                        console.error('Error extracting data from iframe:', e);

                        // Last resort: just hide the loading indicator and show whatever we have
                        loadingIndicator.style.display = 'none';
                    }
                };

                // Add the iframe to the page
                document.getElementById('iframe-container').appendChild(iframe);

                // Set a timeout to hide the loading indicator regardless
                setTimeout(function() {
                    loadingIndicator.style.display = 'none';
                }, 5000);
            }
        }, 20000);
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// handleMetrics - Handles the metrics API endpoint
func (ui *MonitoringUI) handleMetrics(w http.ResponseWriter, r *http.Request) {
	dlog.Debugf("Received metrics request from %s", r.RemoteAddr)

	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

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

// broadcastMetrics - Broadcasts metrics to all connected WebSocket clients
func (ui *MonitoringUI) broadcastMetrics() {
	metrics := ui.metricsCollector.GetMetrics()

	ui.clientsMutex.Lock()
	defer ui.clientsMutex.Unlock()

	for client := range ui.clients {
		err := client.WriteJSON(metrics)
		if err != nil {
			dlog.Debugf("WebSocket write error: %v", err)
			client.Close()
			delete(ui.clients, client)
		}
	}
}
