package main

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type CachedResponse struct {
	expiration time.Time
	msg        dns.Msg
}

type CachedResponses struct {
	sync.RWMutex
	cache *lru.ARCCache
}

type CacheStats struct {
	size        int32
	hits        uint64
	misses      uint64
	expirations uint64
}

var cachedResponses CachedResponses
var cacheStats CacheStats

type PluginCacheResponse struct {
	cachedResponses *CachedResponses
}

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
	plugin.cachedResponses = &cachedResponses
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError && msg.Rcode != dns.RcodeNotAuth {
		return nil
	}
	cacheKey, err := computeCacheKey(pluginsState, msg)
	if err != nil {
		return err
	}
	ttl := getMinTTL(msg, pluginsState.cacheMinTTL, pluginsState.cacheMaxTTL, pluginsState.cacheNegMinTTL, pluginsState.cacheNegMaxTTL)
	cachedResponse := CachedResponse{
		expiration: time.Now().Add(ttl),
		msg:        *msg,
	}
	plugin.cachedResponses.Lock()
	defer plugin.cachedResponses.Unlock()
	if plugin.cachedResponses.cache == nil {
		plugin.cachedResponses.cache, err = lru.NewARC(pluginsState.cacheSize)
		if err != nil {
			return err
		}
		atomic.StoreInt32(&cacheStats.size, int32(pluginsState.cacheSize))
	}
	plugin.cachedResponses.cache.Add(cacheKey, cachedResponse)
	updateTTL(msg, cachedResponse.expiration)

	return nil
}

type PluginCache struct {
	cachedResponses *CachedResponses
	cacheStats      *CacheStats
}

func (plugin *PluginCache) Name() string {
	return "cache"
}

func (plugin *PluginCache) Description() string {
	return "DNS cache (reader)."
}

func (plugin *PluginCache) Init(proxy *Proxy) error {
	atomic.StoreInt32(&cacheStats.size, 0)
	atomic.StoreUint64(&cacheStats.hits, 0)
	atomic.StoreUint64(&cacheStats.misses, 0)
	atomic.StoreUint64(&cacheStats.expirations, 0)
	plugin.cacheStats = &cacheStats

	// proxy.RegisterPluginHTTPHandler(plugin.Name(), "/config", plugin.httpConfigHandler)
	proxy.RegisterPluginHTTPHandler(plugin.Name(), "/status", plugin.httpStatusHandler)
	return nil
}

func (plugin *PluginCache) Drop() error {
	return nil
}

func (plugin *PluginCache) Reload() error {
	return nil
}

func (plugin *PluginCache) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	plugin.cachedResponses = &cachedResponses

	cacheKey, err := computeCacheKey(pluginsState, msg)
	if err != nil {
		return nil
	}
	plugin.cachedResponses.RLock()
	defer plugin.cachedResponses.RUnlock()

	if plugin.cachedResponses.cache == nil {
		atomic.AddUint64(&plugin.cacheStats.misses, 1)
		return nil
	}
	cachedAny, ok := plugin.cachedResponses.cache.Get(cacheKey)
	if !ok {
		atomic.AddUint64(&plugin.cacheStats.misses, 1)
		return nil
	}
	cached := cachedAny.(CachedResponse)
	if time.Now().After(cached.expiration) {
		atomic.AddUint64(&plugin.cacheStats.expirations, 1)
		return nil
	}

	atomic.AddUint64(&plugin.cacheStats.hits, 1)
	updateTTL(&cached.msg, cached.expiration)

	synth := cached.msg
	synth.Id = msg.Id
	synth.Response = true
	synth.Compress = true
	synth.Question = msg.Question
	pluginsState.synthResponse = &synth
	pluginsState.action = PluginsActionSynth
	return nil
}

func computeCacheKey(pluginsState *PluginsState, msg *dns.Msg) ([32]byte, error) {
	questions := msg.Question
	if len(questions) != 1 {
		return [32]byte{}, errors.New("No question present")
	}
	question := questions[0]
	h := sha512.New512_256()
	var tmp [5]byte
	binary.LittleEndian.PutUint16(tmp[0:2], question.Qtype)
	binary.LittleEndian.PutUint16(tmp[2:4], question.Qclass)
	if pluginsState.dnssec {
		tmp[4] = 1
	}
	h.Write(tmp[:])
	normalizedName := []byte(question.Name)
	NormalizeName(&normalizedName)
	h.Write(normalizedName)
	var sum [32]byte
	h.Sum(sum[:0])
	return sum, nil
}

// func (plugin *PluginCache) httpConfigHandler(w http.ResponseWriter, r *http.Request) {
// 	dlog.Noticef("Unhandled call to " + r.RequestURI)
// }

func (plugin *PluginCache) httpStatusHandler(responseWriter http.ResponseWriter, request *http.Request) {
	dlog.Debugf("Handling call to " + request.RequestURI)

	if request.Method != "GET" {
		responseWriter.WriteHeader(405)
		return
	}

	entries := 0
	if plugin.cachedResponses != nil {
		plugin.cachedResponses.RLock()
		entries = plugin.cachedResponses.cache.Len()
		plugin.cachedResponses.RUnlock()
	}

	jsonValues := map[string]interface{}{
		"plugin": plugin.Name(),
		"statistics": map[string]interface{}{
			"entries":     entries,
			"size":        atomic.LoadInt32(&cacheStats.size),
			"hits":        atomic.LoadUint64(&cacheStats.hits),
			"misses":      atomic.LoadUint64(&cacheStats.misses),
			"expirations": atomic.LoadUint64(&cacheStats.expirations),
		},
	}

	jsonEncoder := json.NewEncoder(responseWriter)
	jsonEncoder.Encode(jsonValues)
}
