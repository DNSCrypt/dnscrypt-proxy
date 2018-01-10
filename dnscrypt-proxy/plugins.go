package main

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
)

type PluginsAction int

const (
	PluginsActionNone    = 0
	PluginsActionForward = 1
	PluginsActionDrop    = 2
	PluginsActionReject  = 3
	PluginsActionSynth   = 4
)

type PluginsState struct {
	sessionData            map[string]interface{}
	action                 PluginsAction
	originalMaxPayloadSize int
	maxPayloadSize         int
	proto                  string
	queryPlugins           *[]Plugin
	responsePlugins        *[]Plugin
	synthResponse          *dns.Msg
	dnssec                 bool
}

type Plugin interface {
	Name() string
	Description() string
	Eval(pluginsState *PluginsState, msg *dns.Msg) error
}

func NewPluginsState(proxy *Proxy, proto string) PluginsState {
	queryPlugins := &[]Plugin{}
	if proxy.pluginBlockIPv6 {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginBlockIPv6)))
	}
	*queryPlugins = append(*queryPlugins, Plugin(new(PluginGetSetPayloadSize)))
	if proxy.cache {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginCache)))
	}

	responsePlugins := &[]Plugin{}
	if proxy.cache {
		*responsePlugins = append(*responsePlugins, Plugin(new(PluginCacheResponse)))
	}

	return PluginsState{
		action:          PluginsActionForward,
		maxPayloadSize:  MaxDNSUDPPacketSize - ResponseOverhead,
		queryPlugins:    queryPlugins,
		responsePlugins: responsePlugins,
		proto:           proto,
	}
}

// ---------------- Query plugins ----------------

func (pluginsState *PluginsState) ApplyQueryPlugins(packet []byte) ([]byte, error) {
	if len(*pluginsState.queryPlugins) == 0 {
		return packet, nil
	}
	pluginsState.action = PluginsActionForward
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return packet, err
	}
	for _, plugin := range *pluginsState.queryPlugins {
		if ret := plugin.Eval(pluginsState, &msg); ret != nil {
			pluginsState.action = PluginsActionDrop
			return packet, ret
		}
		if pluginsState.action != PluginsActionForward {
			break
		}
	}
	packet2, err := msg.PackBuffer(packet)
	if err != nil {
		return packet, err
	}
	return packet2, nil
}

// -------- get_set_payload_size plugin --------

type PluginGetSetPayloadSize struct{}

func (plugin *PluginGetSetPayloadSize) Name() string {
	return "get_set_payload_size"
}

func (plugin *PluginGetSetPayloadSize) Description() string {
	return "Adjusts the maximum payload size advertised in queries sent to upstream servers."
}

func (plugin *PluginGetSetPayloadSize) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	pluginsState.originalMaxPayloadSize = 512 - ResponseOverhead
	opt := msg.IsEdns0()
	dnssec := false
	if opt != nil {
		pluginsState.originalMaxPayloadSize = Min(int(opt.UDPSize())-ResponseOverhead, pluginsState.originalMaxPayloadSize)
		dnssec = opt.Do()
	}
	pluginsState.dnssec = dnssec
	pluginsState.maxPayloadSize = Min(MaxDNSUDPPacketSize-ResponseOverhead, Max(pluginsState.originalMaxPayloadSize, pluginsState.maxPayloadSize))
	if pluginsState.maxPayloadSize > 512 {
		extra2 := []dns.RR{}
		for _, extra := range msg.Extra {
			if extra.Header().Rrtype != dns.TypeOPT {
				extra2 = append(extra2, extra)
			}
		}
		msg.Extra = extra2
		msg.SetEdns0(uint16(pluginsState.maxPayloadSize), dnssec)
	}
	return nil
}

// -------- block_ipv6 plugin --------

type PluginBlockIPv6 struct{}

func (plugin *PluginBlockIPv6) Name() string {
	return "block_ipv6"
}

func (plugin *PluginBlockIPv6) Description() string {
	return "Immediately return a synthetic response to AAAA queries"
}

func (plugin *PluginBlockIPv6) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	questions := msg.Question
	if len(questions) != 1 {
		return nil
	}
	question := questions[0]
	if question.Qclass != dns.ClassINET || question.Qtype != dns.TypeAAAA {
		return nil
	}
	synth, err := EmptyResponseFromMessage(msg)
	if err != nil {
		return err
	}
	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	return nil
}

// ---------------- Response plugins ----------------

func (pluginsState *PluginsState) ApplyResponsePlugins(packet []byte) ([]byte, error) {
	if len(*pluginsState.responsePlugins) == 0 {
		return packet, nil
	}
	pluginsState.action = PluginsActionForward
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return packet, err
	}
	for _, plugin := range *pluginsState.responsePlugins {
		if ret := plugin.Eval(pluginsState, &msg); ret != nil {
			pluginsState.action = PluginsActionDrop
			return packet, ret
		}
		if pluginsState.action != PluginsActionForward {
			break
		}
	}
	packet2, err := msg.PackBuffer(packet)
	if err != nil {
		return packet, err
	}
	return packet2, nil
}

// -------- cache plugin --------

type CachedResponse struct {
	expiration time.Time
	msg        dns.Msg
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

func (plugin *PluginCacheResponse) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	plugin.cachedResponses = &cachedResponses

	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNXRrset {
		return nil
	}
	cacheKey, err := computeCacheKey(pluginsState, msg)
	if err != nil {
		return nil
	}
	ttl := getMinTTL(msg, 60, 86400, 60)
	cachedResponse := CachedResponse{
		expiration: time.Now().Add(ttl),
		msg:        *msg,
	}
	plugin.cachedResponses.Lock()
	defer plugin.cachedResponses.Unlock()
	if plugin.cachedResponses.cache == nil {
		plugin.cachedResponses.cache, err = lru.NewARC(1000)
		if err != nil {
			return err
		}
	}
	plugin.cachedResponses.cache.Add(cacheKey, cachedResponse)
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

func (plugin *PluginCache) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	plugin.cachedResponses = &cachedResponses

	cacheKey, err := computeCacheKey(pluginsState, msg)
	if err != nil {
		return nil
	}
	plugin.cachedResponses.RLock()
	defer plugin.cachedResponses.RUnlock()
	if plugin.cachedResponses.cache == nil {
		return nil
	}
	cached_any, ok := plugin.cachedResponses.cache.Get(cacheKey)
	if !ok {
		return nil
	}
	cached := cached_any.(CachedResponse)
	if time.Now().After(cached.expiration) {
		return nil
	}
	synth := cached.msg
	synth.MsgHdr = msg.MsgHdr
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
