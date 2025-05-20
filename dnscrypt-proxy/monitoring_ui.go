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
	PrivacyLevel   int    `toml:"privacy_level"` // 0: show all details, 1: anonymize client IPs, 2: aggregate only (no individual queries or domains)
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
	mux.HandleFunc("/static/monitoring.js", ui.handleStaticJS)
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

// setCORSHeaders - Sets standard CORS headers for all responses
func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

// handleTestQuery - Handles test query requests for debugging
func (ui *MonitoringUI) handleTestQuery(w http.ResponseWriter, r *http.Request) {
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

	// If this is a simple version request, return a simple page
	if r.URL.Query().Get("simple") == "1" {
		metrics := ui.metricsCollector.GetMetrics()

		// Create a simple HTML page with the metrics
		simpleHTML := fmt.Sprintf(SimpleHTMLTemplate,
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

	// Serve the main dashboard page
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(MainHTMLTemplate))
}

// handleMetrics - Handles the metrics API endpoint
func (ui *MonitoringUI) handleMetrics(w http.ResponseWriter, r *http.Request) {
	dlog.Debugf("Received metrics request from %s", r.RemoteAddr)

	// Set CORS headers
	setCORSHeaders(w)

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
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte(MonitoringJSContent))
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
