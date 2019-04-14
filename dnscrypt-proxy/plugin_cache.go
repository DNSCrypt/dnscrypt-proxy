package main

import (
	"crypto/sha512"
	"encoding/binary"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
)

type CachedResponse struct {
	since      time.Time
	msg        dns.Msg
}

type CacheKey struct {
	ckName  string
	ckType  uint16
	ckClass uint16
}

type CachedResponses struct {
	sync.RWMutex
	cache *lru.ARCCache
}

var cachedResponses CachedResponses

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
	var err error
	var answers map[CacheKey]([]dns.RR)

	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError && msg.Rcode != dns.RcodeNotAuth {
		return nil
	}
	if msg.Truncated {
		return nil
	}

	updateMsgTTLs( msg, pluginsState.cacheMinTTL, pluginsState.cacheMaxTTL, pluginsState.cacheNegMinTTL, pluginsState.cacheNegMaxTTL )

	now := time.Now()

	// group answers by cache key
	for i := 0; i < len(msg.Answer); i++ {
		if answers == nil {
			answers = make(map[CacheKey]([]dns.RR))
		}
		cacheKey := rrToCacheKey( &msg.Answer[i] )
		answers[*cacheKey] = append( answers[*cacheKey], msg.Answer[i] )
	}


	plugin.cachedResponses = &cachedResponses
	if plugin.cachedResponses.cache == nil {
		plugin.cachedResponses.cache, err = lru.NewARC(pluginsState.cacheSize)
		if err != nil {
			return err
		}
	}

	plugin.cachedResponses.Lock()
	defer plugin.cachedResponses.Unlock()

	for _ck, rrset := range answers {
		var ck *CacheKey
		var cachedResponse CachedResponse

		if (msg.Question[0].Name == _ck.ckName &&
			_ck.ckType == dns.TypeCNAME) {

			// if this RR set is for same name as query
			// name and this query is of type CNAME then
			// cache the complete RR set

			ck = questionToCacheKey(&msg.Question[0])

			cachedResponse = CachedResponse{
				since: now,
				msg:   *msg,
			}
		} else {
			ck = &_ck

			msg1 := *msg
			msg1.Answer = rrset

			cachedResponse = CachedResponse{
				since: now,
				msg:   msg1,
			}
		}
		cacheKey, err := computeCacheKey(pluginsState, ck)
		if err != nil {
			return err
		}
		plugin.cachedResponses.cache.Add(cacheKey, cachedResponse)
	}

	if answers == nil && len( msg.Ns ) > 0 {
		ck := questionToCacheKey( &msg.Question[0] )
		cacheKey, err := computeCacheKey(pluginsState, ck)
		if err != nil {
			return err
		}
		cachedResponse := CachedResponse{
			since: now,
			msg: *msg,
		}
		plugin.cachedResponses.cache.Add(cacheKey, cachedResponse)
	}

	return nil
}

type PluginCache struct {
	cachedResponses *CachedResponses
}

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
	plugin.cachedResponses = &cachedResponses

	if len(msg.Question) != 1 {
		// no questions present
		return nil
	}
	cacheKey, err := computeCacheKey(pluginsState, questionToCacheKey(&msg.Question[0]))
	if err != nil {
		return nil
	}
	plugin.cachedResponses.RLock()
	defer plugin.cachedResponses.RUnlock()
	if plugin.cachedResponses.cache == nil {
		return nil
	}
	cachedAny, ok := plugin.cachedResponses.cache.Get(cacheKey)
	if !ok {
		return nil
	}
	cached := cachedAny.(CachedResponse)
	now := time.Now()
	for _, rr := range cached.msg.Answer {
		if (now.Sub( cached.since )) >= (time.Duration(rr.Header().Ttl) * time.Second) {
			return nil
		}
	}

	synth := cached.msg.Copy()
	(*synth).Question = msg.Question
	(*synth).Id = msg.Id
	(*synth).Response = true
	(*synth).Compress = true
	updateTTLs(synth, cached.since)
 	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	return nil
}

func computeCacheKey(pluginsState *PluginsState, key *CacheKey) ([32]byte, error) {
	h := sha512.New512_256()
	var tmp [5]byte
	binary.LittleEndian.PutUint16(tmp[0:2], key.ckType)
	binary.LittleEndian.PutUint16(tmp[2:4], key.ckClass)
	if pluginsState.dnssec {
		tmp[4] = 1
	}
	h.Write(tmp[:])
	normalizedName := []byte(key.ckName)
	NormalizeName(&normalizedName)
	h.Write(normalizedName)
	var sum [32]byte
	h.Sum(sum[:0])
	return sum, nil
}

func questionToCacheKey( q *dns.Question ) *CacheKey {
	return &CacheKey {
		ckName: q.Name,
		ckType: q.Qtype,
		ckClass: q.Qclass,
	}
}

func rrToCacheKey( rr *dns.RR ) *CacheKey {
	hdr := (*rr).Header()
	return &CacheKey {
		ckName: hdr.Name,
		ckType: hdr.Rrtype,
		ckClass: hdr.Class,
	}
}
