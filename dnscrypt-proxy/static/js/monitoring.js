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

// Cache for the last non-empty recent queries
let lastRecentQueries = [];

// Safe update function that handles missing data
function safeUpdateDashboard(data) {
    try {
        if (!data) {
            console.error('No data provided to safeUpdateDashboard');
            return;
        }

        if (data.type === 'pong') {
            console.log('Received pong message');
            return;
        }

        console.log('Updating dashboard with data');

        // Store the current scroll position before updates
        const scrollPos = {
            x: window.scrollX || window.pageXOffset,
            y: window.scrollY || window.pageYOffset
        };

        // Hide loading indicator when data is loaded
        var loadingIndicator = document.getElementById('loading-indicator');
        if (loadingIndicator) {
            loadingIndicator.style.display = 'none';
        }

        // Update overview stats with null checks
        const totalQueries = data.total_queries !== undefined ? data.total_queries : 0;
        const blockedQueries = data.blocked_queries !== undefined ? data.blocked_queries : 0;
        const qps = data.queries_per_second !== undefined ? data.queries_per_second : 0;
        const uptime = data.uptime_seconds !== undefined ? data.uptime_seconds : 0;
        const avgResponseTime = data.avg_response_time !== undefined ? data.avg_response_time : 0;

        updateElementText('total-queries', formatNumber(totalQueries));
        updateElementText('blocked-queries', formatNumber(blockedQueries));
        updateElementText('qps', qps.toFixed(2));
        updateElementText('uptime', formatUptime(uptime));
        updateElementText('avg-response-time', formatMilliseconds(avgResponseTime));

        const generatedAt = data.generated_at ? new Date(data.generated_at) : null;
        const lastUpdatedEl = document.getElementById('last-updated');
        if (lastUpdatedEl) {
            if (generatedAt && !isNaN(generatedAt.getTime())) {
                lastUpdatedEl.textContent = generatedAt.toLocaleString();
            } else {
                lastUpdatedEl.textContent = '-';
            }
        }

        // Update cache stats with null checks
        const cacheHitRatio = data.cache_hit_ratio !== undefined ? data.cache_hit_ratio : 0;
        const cacheHits = data.cache_hits !== undefined ? data.cache_hits : 0;
        const cacheMisses = data.cache_misses !== undefined ? data.cache_misses : 0;
        const cacheStats = data.cache_stats || {};

        updateElementText('cache-hit-ratio', formatPercent(cacheHitRatio));
        updateElementText('cache-hits', formatNumber(cacheHits));
        updateElementText('cache-misses', formatNumber(cacheMisses));
        updateElementText('cache-enabled', formatBoolean(cacheStats.enabled));
        updateElementText('cache-configured-size', formatNumber(cacheStats.configured_size));
        updateElementText('cache-entries', formatNumber(cacheStats.entries));
        updateElementText('cache-capacity', formatNumber(cacheStats.capacity));
        updateElementText('cache-ttl-range', formatTTLRange(cacheStats));

        // Update resolver health table
        const resolverTable = document.getElementById('resolver-table').getElementsByTagName('tbody')[0];
        resolverTable.innerHTML = '';
        const resolverRows = Array.isArray(data.resolver_health) ? data.resolver_health : [];

        if (resolverRows.length > 0) {
            // Sort by total queries (desc), then avg response, name, and last seen.
            const sortedResolvers = resolverRows.slice().sort((a, b) => {
                const totalQueries = resolver => {
                    if (typeof resolver.total_queries === 'number') {
                        return resolver.total_queries;
                    }
                    if (typeof resolver.queries === 'number') {
                        return resolver.queries;
                    }
                    return -1;
                };
                const avgResponse = resolver => {
                    return typeof resolver.avg_response_ms === 'number' ? resolver.avg_response_ms : Number.POSITIVE_INFINITY;
                };
                const name = resolver => (resolver.name || '').toLowerCase();
                const lastSeen = resolver => {
                    const value = resolver.last_update;
                    if (!value) {
                        return 0;
                    }
                    const parsed = Date.parse(value);
                    return Number.isNaN(parsed) ? 0 : parsed;
                };

                return (
                    (totalQueries(b) - totalQueries(a)) ||
                    (avgResponse(a) - avgResponse(b)) ||
                    (name(a) > name(b) ? 1 : name(a) < name(b) ? -1 : 0) ||
                    (lastSeen(b) - lastSeen(a))
                );
            });

            sortedResolvers.forEach(resolver => {
                const row = resolverTable.insertRow();
                row.insertCell(0).textContent = resolver.name || 'Unknown';
                row.insertCell(1).textContent = formatStatus(resolver.status);
                row.insertCell(2).textContent = formatPercent(resolver.success_rate);
                row.insertCell(3).textContent = formatNumber(resolver.total_queries !== undefined ? resolver.total_queries : resolver.queries);
                row.insertCell(4).textContent = formatNumber(resolver.failed_queries);
                row.insertCell(5).textContent = formatMilliseconds(resolver.avg_response_ms);
                row.insertCell(6).textContent = formatTimestamp(resolver.last_update);
            });
        } else {
            const row = resolverTable.insertRow();
            const cell = row.insertCell(0);
            cell.colSpan = 7;
            cell.textContent = 'No resolver data yet';
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

        // Update sources table
        const sourcesTable = document.getElementById('sources-table').getElementsByTagName('tbody')[0];
        sourcesTable.innerHTML = '';
        if (data.sources && Array.isArray(data.sources) && data.sources.length > 0) {
            data.sources.forEach(source => {
                const row = sourcesTable.insertRow();
                row.insertCell(0).textContent = source.name || '-';
                row.insertCell(1).textContent = formatTimestamp(source.last_refresh);
                row.insertCell(2).textContent = formatTimestamp(source.next_refresh);
                row.insertCell(3).textContent = formatSourceStatus(source.status, source.error);
                row.insertCell(4).textContent = formatAge(source.age_seconds);
            });
        } else {
            const row = sourcesTable.insertRow();
            const cell = row.insertCell(0);
            cell.colSpan = 5;
            cell.textContent = 'No source activity recorded yet';
        }

        // Update recent queries table
        const queriesTable = document.getElementById('queries-table').getElementsByTagName('tbody')[0];
        let queriesToShow = lastRecentQueries;
        if (data.recent_queries && Array.isArray(data.recent_queries) && data.recent_queries.length > 0) {
            lastRecentQueries = data.recent_queries;
            queriesToShow = lastRecentQueries;
        }
        queriesTable.innerHTML = '';
        if (queriesToShow && Array.isArray(queriesToShow)) {
            queriesToShow.slice().reverse().forEach(query => {
                const row = queriesTable.insertRow();
                row.insertCell(0).textContent = query.timestamp ? new Date(query.timestamp).toLocaleTimeString() : '-';
                row.insertCell(1).textContent = query.domain || '-';
                row.insertCell(2).textContent = query.type || '-';
                row.insertCell(3).textContent = query.client_ip || '-';
                row.insertCell(4).textContent = query.server || '-';
                row.insertCell(5).textContent = query.response_code || '-';
                row.insertCell(6).textContent = formatMilliseconds(query.response_time);
            });
        }

        // Restore scroll position after DOM updates
        window.scrollTo(scrollPos.x, scrollPos.y);
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

function updateElementText(id, value) {
    const el = document.getElementById(id);
    if (!el) {
        return;
    }
    el.textContent = value !== undefined && value !== null && value !== '' ? value : '-';
}

function formatNumber(value) {
    if (value === undefined || value === null) {
        return '-';
    }
    const num = Number(value);
    if (Number.isNaN(num)) {
        return '-';
    }
    return num.toLocaleString();
}

function formatPercent(value) {
    if (value === undefined || value === null) {
        return '-';
    }
    const num = Number(value);
    if (Number.isNaN(num)) {
        return '-';
    }
    return (num * 100).toFixed(1) + '%';
}

function formatMilliseconds(value) {
    if (value === undefined || value === null) {
        return '-';
    }
    const num = Number(value);
    if (Number.isNaN(num)) {
        return '-';
    }
    return Math.round(num) + ' ms';
}

function formatBoolean(value) {
    if (value === undefined || value === null) {
        return '-';
    }
    return value ? 'Yes' : 'No';
}

function formatStatus(status) {
    if (!status || typeof status !== 'string') {
        return 'Unknown';
    }
    const normalized = status.replace(/_/g, ' ').toLowerCase();
    return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function formatTimestamp(value) {
    if (!value) {
        return '-';
    }
    try {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return '-';
        }
        return date.toLocaleString();
    } catch (error) {
        return '-';
    }
}

function formatAge(seconds) {
    if (seconds === undefined || seconds === null) {
        return '-';
    }
    const num = Number(seconds);
    if (Number.isNaN(num) || num < 0) {
        return '-';
    }
    const totalSeconds = Math.round(num);
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const secs = totalSeconds % 60;
    const parts = [];
    if (days > 0) parts.push(days + 'd');
    if (hours > 0) parts.push(hours + 'h');
    if (minutes > 0) parts.push(minutes + 'm');
    parts.push(secs + 's');
    return parts.join(' ');
}

function formatTTLRange(cacheStats) {
    if (!cacheStats || typeof cacheStats !== 'object') {
        return '-';
    }
    const parts = [];
    if (cacheStats.min_ttl !== undefined && cacheStats.max_ttl !== undefined) {
        parts.push('pos ' + cacheStats.min_ttl + 's-' + cacheStats.max_ttl + 's');
    }
    if (cacheStats.neg_min_ttl !== undefined && cacheStats.neg_max_ttl !== undefined) {
        parts.push('neg ' + cacheStats.neg_min_ttl + 's-' + cacheStats.neg_max_ttl + 's');
    }
    return parts.length ? parts.join(' / ') : '-';
}

function formatSourceStatus(status, error) {
    let label = formatStatus(status);
    if (error) {
        label += ' (' + error + ')';
    }
    return label;
}

function fetchMetrics() {
    return fetch(window.location.origin + '/api/metrics', {
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { 'Accept': 'application/json' },
    }).then(function(response) {
        if (!response.ok) {
            throw new Error('HTTP ' + response.status);
        }
        return response.json();
    });
}

function loadData() {
    fetchMetrics().then(function(data) {
        if (data) {
            safeUpdateDashboard(data);
        } else {
            handleError(new Error('Empty data received'));
        }
    }).catch(function(err) {
        console.error('Initial metrics load failed:', err);
        handleError(err);
        setTimeout(loadData, 5000);
    });
}

loadData();

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
        var newWs = new WebSocket(wsUrl);

        // Connection opened
        newWs.onopen = function() {
            console.log('WebSocket connected successfully');
            wsReconnectAttempts = 0; // Reset reconnect attempts on successful connection

            // Send a ping to verify connection
            try {
                newWs.send(JSON.stringify({type: 'ping'}));
            } catch (e) {
                console.error('Error sending ping:', e);
            }
        };

        // Listen for messages
        newWs.onmessage = function(event) {
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
        newWs.onerror = function(error) {
            console.error('WebSocket error occurred:', error);
        };

        // Connection closed
        newWs.onclose = function(event) {
            console.log('WebSocket disconnected, code:', event.code, 'reason:', event.reason || 'No reason provided');

            // Try to reconnect with exponential backoff
            if (wsReconnectAttempts < maxReconnectAttempts) {
                wsReconnectAttempts++;
                var delay = reconnectDelay * Math.pow(2, wsReconnectAttempts - 1);
                console.log('Attempting to reconnect in ' + delay + 'ms (attempt ' + wsReconnectAttempts + '/' + maxReconnectAttempts + ')');

                setTimeout(function() {
                    ws = connectWebSocket();
                    if (ws) {
                        console.log('New WebSocket connection established');
                    }
                }, delay);
            } else {
                console.log('Max reconnect attempts reached, falling back to polling');
            }
        };

        return newWs;
    } catch (error) {
        console.error('Failed to create WebSocket connection:', error);
        return null;
    }
}

// Start WebSocket connection
let ws = connectWebSocket();

function pollMetrics() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        return;
    }
    fetchMetrics().then(function(data) {
        if (data) {
            safeUpdateDashboard(data);
        }
    }).catch(function(err) {
        console.error('Polling metrics failed:', err);
    });
}

// Initialize dashboard with default values
function initializeDashboard() {
    updateElementText('total-queries', '0');
    updateElementText('blocked-queries', '0');
    updateElementText('qps', '0.00');
    updateElementText('uptime', '0s');
    updateElementText('avg-response-time', '0.00 ms');
    updateElementText('cache-hit-ratio', '0.0%');
    updateElementText('cache-hits', '0');
    updateElementText('cache-misses', '0');
    updateElementText('cache-enabled', '-');
    updateElementText('cache-configured-size', '-');
    updateElementText('cache-entries', '-');
    updateElementText('cache-capacity', '-');
    updateElementText('cache-ttl-range', '-');
    updateElementText('last-updated', '-');
}

// Initialize with default values
initializeDashboard();

setInterval(pollMetrics, 5000);
