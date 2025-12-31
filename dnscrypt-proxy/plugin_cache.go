package main

import (
    "crypto/sha512"
    "encoding/binary"
    "fmt"
    "hash"
    "sync"
    "time"

    "codeberg.org/miekg/dns"
    "github.com/jedisct1/go-sieve-cache/pkg/sievecache"
)

const StaleResponseTTL = 30 * time.Second

type CachedResponse struct {
    expiration time.Time
    msg        *dns.Msg
}

type CachedResponses struct {
    cache     *sievecache.ShardedSieveCache[[32]byte, CachedResponse]
    cacheOnce sync.Once
}

var cachedResponses CachedResponses

// Use a pool to reuse hashers and avoid allocations on every request
var hasherPool = sync.Pool{
    New: func() interface{} {
        return sha512.New512_256()
    },
}

func computeCacheKey(pluginsState *PluginsState, msg *dns.Msg) [32]byte {
    question := msg.Question[0]
    
    // Get a hasher from the pool
    h := hasherPool.Get().(hash.Hash)
    
    var tmp [5]byte
    // Use Qtype and Qclass directly to avoid overhead
    binary.LittleEndian.PutUint16(tmp[0:2], question.Qtype)
    binary.LittleEndian.PutUint16(tmp[2:4], question.Qclass)
    if pluginsState.dnssec {
        tmp[4] = 1
    }
    h.Write(tmp[:])
    
    // Note: question.Name is used directly instead of Header()
    normalizedRawQName := []byte(question.Name)
    NormalizeRawQName(&normalizedRawQName)
    h.Write(normalizedRawQName)
    
    var sum [32]byte
    h.Sum(sum[:0])
    
    // Reset and put back in pool
    h.Reset()
    hasherPool.Put(h)

    return sum
}

// ---

type PluginCache struct{}

func (plugin *PluginCache) Name() string {
    return "cache"
}

func (plugin *PluginCache) Description() string {
    return "DNS cache (reader)."
}

func (plugin *PluginCache) Init(proxy *Proxy) error {
    return nil
}

func (plugin *PluginCache) Drop() error {
    return nil
}

func (plugin *PluginCache) Reload() error {
    return nil
}

func (plugin *PluginCache) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
    if cachedResponses.cache == nil {
        return nil
    }
    
    cacheKey := computeCacheKey(pluginsState, msg)
    cached, ok := cachedResponses.cache.Get(cacheKey)
    if !ok {
        return nil
    }
    
    // Optimization: Call time.Now() once
    now := time.Now()
    
    synth := cached.msg.Copy()
    synth.ID = msg.ID
    synth.Response = true
    synth.Question = msg.Question

    if now.After(cached.expiration) {
        // Use the cached 'now' time
        expiration2 := now.Add(StaleResponseTTL)
        updateTTL(synth, expiration2)
        pluginsState.sessionData["stale"] = synth
        return nil
    }

    updateTTL(synth, cached.expiration)

    pluginsState.synthResponse = synth
    pluginsState.action = PluginsActionSynth
    pluginsState.cacheHit = true
    return nil
}

// ---

type PluginCacheResponse struct{}

func (plugin *PluginCacheResponse) Name() string {
    return "cache_response"
}

func (plugin *PluginCacheResponse) Description() string {
    return "DNS cache (writer)."
}

func (plugin *PluginCacheResponse) Init(proxy *Proxy) error {
    return nil
}

func (plugin *PluginCacheResponse) Drop() error {
    return nil
}

func (plugin *PluginCacheResponse) Reload() error {
    return nil
}

func (plugin *PluginCacheResponse) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
    if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError && msg.Rcode != dns.RcodeNotAuth {
        return nil
    }
    if msg.Truncated {
        return nil
    }
    
    // Optimization: Check if cache is nil before incurring sync.Once overhead
    if cachedResponses.cache == nil {
        var cacheInitError error
        cachedResponses.cacheOnce.Do(func() {
            cache, err := sievecache.NewSharded[[32]byte, CachedResponse](pluginsState.cacheSize)
            if err != nil {
                cacheInitError = err
            } else {
                cachedResponses.cache = cache
            }
        })
        if cacheInitError != nil {
            return fmt.Errorf("failed to initialize the cache: %w", cacheInitError)
        }
        // If it's still nil (initialization failed silently or other issue), return
        if cachedResponses.cache == nil {
            return nil
        }
    }
    
    cacheKey := computeCacheKey(pluginsState, msg)
    ttl := getMinTTL(
        msg,
        pluginsState.cacheMinTTL,
        pluginsState.cacheMaxTTL,
        pluginsState.cacheNegMinTTL,
        pluginsState.cacheNegMaxTTL,
    )
    
    // Optimization: Use calculated TTL directly
    expiration := time.Now().Add(ttl)
    cachedResponse := CachedResponse{
        expiration: expiration,
        msg:        msg.Copy(),
    }

    cachedResponses.cache.Insert(cacheKey, cachedResponse)
    updateTTL(msg, cachedResponse.expiration)

    return nil
}
