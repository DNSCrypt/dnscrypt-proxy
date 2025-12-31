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

// Optimized: Pool for hashers to reduce memory allocations on every request
var hasherPool = sync.Pool{
    New: func() interface{} {
        return sha512.New512_256()
    },
}

func computeCacheKey(pluginsState *PluginsState, msg *dns.Msg) [32]byte {
    question := msg.Question[0]
    
    // Optimized: Reuse hasher from pool
    h := hasherPool.Get().(hash.Hash)
    
    var tmp [5]byte
    // Corrected: Use Header() and RRToType as question is an RR interface
    binary.LittleEndian.PutUint16(tmp[0:2], dns.RRToType(question))
    binary.LittleEndian.PutUint16(tmp[2:4], question.Header().Class)
    if pluginsState.dnssec {
        tmp[4] = 1
    }
    h.Write(tmp[:])
    
    // Corrected: Use Header().Name
    normalizedRawQName := []byte(question.Header().Name)
    NormalizeRawQName(&normalizedRawQName)
    h.Write(normalizedRawQName)
    
    var sum [32]byte
    h.Sum(sum[:0])
    
    // Reset hasher and return to pool
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
    
    // Optimized: Call time.Now() only once
    now := time.Now()
    
    synth := cached.msg.Copy()
    synth.ID = msg.ID
    synth.Response = true
    synth.Question = msg.Question

    if now.After(cached.expiration) {
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
    
    // Optimized: Double-checked locking pattern implicitly handled by sync.Once,
    // but we check nil first to avoid function call overhead on happy path.
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
    
    // Optimized: Calculate expiration once
    expiration := time.Now().Add(ttl)
    cachedResponse := CachedResponse{
        expiration: expiration,
        msg:        msg.Copy(),
    }

    cachedResponses.cache.Insert(cacheKey, cachedResponse)
    updateTTL(msg, cachedResponse.expiration)

    return nil
}
