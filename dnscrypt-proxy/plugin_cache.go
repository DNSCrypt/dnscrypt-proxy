// plugin_cache.go implements DNS response cache reader/writer plugins.

package main

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/go-sieve-cache/pkg/sievecache"
)

// ── Constants ─────────────────────────────────────────────────────────────────

// StaleResponseTTL is the TTL granted to an expired cached entry while a fresh
// upstream response is fetched in the background (stale-while-revalidate).
const StaleResponseTTL = 30 * time.Second

// ── Types ─────────────────────────────────────────────────────────────────────

// CachedResponse pairs a DNS response with its cache expiration deadline.
//
// expiration is stored as Unix nanoseconds (int64) rather than time.Time
// to reduce per-entry memory usage.
type CachedResponse struct {
	expiration int64
	msg        *dns.Msg // 8 B pointer
}

// CachedResponses is the package-level cache container.
//
// cache is accessed via atomic.Pointer [C01] to guarantee memory-safe
// concurrent reads from PluginCache.Eval and the one-time write from
// PluginCacheResponse.Eval.
//
// initErr is written at most once inside cacheOnce.Do.  The sync.Once
// happens-before guarantee makes reads after Do return safe without
// additional synchronisation. [C09]
type CachedResponses struct {
	cache     atomic.Pointer[sievecache.ShardedSieveCache[[32]byte, CachedResponse]] // [C01]
	initErr   error  // [C09] written once under cacheOnce; readable after Do
	cacheOnce sync.Once
}

var cachedResponses CachedResponses

// CacheStats returns the live entry count and capacity of the sieve cache.
// Returns (0, 0) if the cache has not yet been successfully initialised.
//
// External files (e.g. monitoring_ui.go) must call this instead of accessing
// cachedResponses.cache directly — the field is now atomic.Pointer[T] and
// cannot be compared to nil or have methods called on it without Load(). [C01]
func (cr *CachedResponses) CacheStats() (entries, capacity int) {
	if c := cr.cache.Load(); c != nil {
		return c.Len(), c.Capacity()
	}
	return 0, 0
}


// ── Hash pool ─────────────────────────────────────────────────────────────────

// cacheKeyHashPool recycles SHA-512/256 hash objects across goroutines. [C12]
// Eliminates one heap allocation per cache lookup and per cache insert.
var cacheKeyHashPool = sync.Pool{
	New: func() any { return sha512.New512_256() },
}

// ── Cache key ─────────────────────────────────────────────────────────────────

// computeCacheKey returns a 32-byte SHA-512/256 digest that uniquely
// identifies (qname, qtype, qclass, dnssec) for use as a cache lookup key.
func computeCacheKey(pluginsState *PluginsState, msg *dns.Msg) [32]byte {
	// [C11] Guard against malformed messages with an empty Question section.
	if len(msg.Question) == 0 {
		return [32]byte{}
	}

	question := msg.Question[0]

	// [C12] Reuse a pooled hash object; Reset() clears any previous state.
	h := cacheKeyHashPool.Get().(hash.Hash)
	h.Reset()
	defer cacheKeyHashPool.Put(h)

	// [C13] Stack-backed append slice — zero allocation, no manual index math.
	// AppendUint16 available since Go 1.23; NativeEndian since Go 1.21 [C10].
	var backing [5]byte
	buf := backing[:0]
	buf = binary.NativeEndian.AppendUint16(buf, dns.RRToType(question))  // [C10][C13]
	buf = binary.NativeEndian.AppendUint16(buf, question.Header().Class) // [C10][C13]
	if pluginsState.dnssec {
		buf = append(buf, 1)
	}
	h.Write(buf)

	normalizedRawQName := []byte(question.Header().Name)
	NormalizeRawQName(&normalizedRawQName)
	h.Write(normalizedRawQName)

	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

// ── PluginCache (reader) ──────────────────────────────────────────────────────

// PluginCache is the DNS cache reader plugin.  It is evaluated before an
// upstream query is sent; a cache hit synthesises a response directly,
// short-circuiting the full resolution path.  A stale hit stores the expired
// response for background revalidation and lets the query proceed upstream.
type PluginCache struct{}

// Name returns the plugin identifier.
func (plugin *PluginCache) Name() string { return "cache" }

// Description returns a human-readable summary of the plugin.
func (plugin *PluginCache) Description() string { return "DNS cache (reader)." }

// Init performs any one-time setup required by the plugin.
func (plugin *PluginCache) Init(proxy *Proxy) error { return nil }

// Drop releases any resources held by the plugin.
func (plugin *PluginCache) Drop() error { return nil }

// Reload reloads the plugin configuration.
func (plugin *PluginCache) Reload() error { return nil }

// Eval looks up msg in the cache.
// Fresh hit: synthesises a response and sets PluginsActionSynth.
// Stale hit: stores the old response in sessionData["stale"] for the upstream
// path to use as a fallback, then returns without short-circuiting.
func (plugin *PluginCache) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	// [C01] Atomic load — sequentially consistent with the Store in the writer.
	c := cachedResponses.cache.Load()
	if c == nil {
		return nil
	}

	cacheKey := computeCacheKey(pluginsState, msg)
	cached, ok := c.Get(cacheKey)
	if !ok {
		return nil
	}

	synth := cached.msg.Copy()
	synth.ID = msg.ID
	synth.Response = true
	synth.Question = msg.Question

	// [C02] Capture now once; reused for both the expiry check and stale TTL.
	now := time.Now()
	if now.UnixNano() > cached.expiration { // [C14] int64 comparison
		staleExpiration := now.Add(StaleResponseTTL) // [C03] expiration2 → staleExpiration
		updateTTL(synth, staleExpiration)
		pluginsState.sessionData["stale"] = synth
		return nil
	}

	updateTTL(synth, time.Unix(0, cached.expiration)) // [C14] reconstruct time.Time
	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	pluginsState.cacheHit = true
	return nil
}

// ── PluginCacheResponse (writer) ─────────────────────────────────────────────

// PluginCacheResponse is the DNS cache writer plugin.  It is evaluated after
// a successful upstream response and stores cacheable answers for future hits.
type PluginCacheResponse struct{}

// Name returns the plugin identifier.
func (plugin *PluginCacheResponse) Name() string { return "cache_response" }

// Description returns a human-readable summary of the plugin.
func (plugin *PluginCacheResponse) Description() string { return "DNS cache (writer)." }

// Init performs any one-time setup required by the plugin.
func (plugin *PluginCacheResponse) Init(proxy *Proxy) error { return nil }

// Drop releases any resources held by the plugin.
func (plugin *PluginCacheResponse) Drop() error { return nil }

// Reload reloads the plugin configuration.
func (plugin *PluginCacheResponse) Reload() error { return nil }

// Eval stores the upstream response in the cache when the Rcode is cacheable
// and the message is not truncated.  The sieve cache is initialised lazily on
// the first qualifying response via sync.Once.
func (plugin *PluginCacheResponse) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	// [C04] Named boolean: intent ("skip non-cacheable rcodes") is clear.
	cacheable := msg.Rcode == dns.RcodeSuccess ||
		msg.Rcode == dns.RcodeNameError ||
		msg.Rcode == dns.RcodeNotAuth
	if !cacheable {
		return nil
	}
	if msg.Truncated {
		return nil
	}

	// [C07] Compute expiration once; reused for Insert and updateTTL.
	// [C14] Store as int64 Unix nanoseconds — 8 B instead of 24 B per entry.
	ttl := getMinTTL(
		msg,
		pluginsState.cacheMinTTL,
		pluginsState.cacheMaxTTL,
		pluginsState.cacheNegMinTTL,
		pluginsState.cacheNegMaxTTL,
	)
	expiration := time.Now().Add(ttl).UnixNano() // [C07][C14] int64

	// Lazily initialise the sieve cache on the first cacheable response.
	// [C09] initErr stored in struct; all callers after a failure see the error.
	cachedResponses.cacheOnce.Do(func() {
		cache, err := sievecache.NewSharded[[32]byte, CachedResponse](pluginsState.cacheSize)
		if err != nil {
			cachedResponses.initErr = err // [C09]
			return                        // [C08] early return; no else branch
		}
		cachedResponses.cache.Store(cache) // [C01] atomic Store
	})
	// sync.Once happens-before guarantee makes this read of initErr safe. [C09]
	if cachedResponses.initErr != nil {
		return fmt.Errorf("failed to initialize the cache: %w", cachedResponses.initErr)
	}

	// [C06] Defer computeCacheKey and msg.Copy() until cache is confirmed
	// available — avoids the hash and allocation after a permanent init failure.
	if c := cachedResponses.cache.Load(); c != nil { // [C01][C06]
		cacheKey := computeCacheKey(pluginsState, msg) // [C06] inside guard
		c.Insert(cacheKey, CachedResponse{
			expiration: expiration,    // [C14] int64
			msg:        msg.Copy(),    // [C06] copy only when cache is ready
		})
	}

	updateTTL(msg, time.Unix(0, expiration)) // [C07][C14] reconstruct time.Time
	return nil
}
