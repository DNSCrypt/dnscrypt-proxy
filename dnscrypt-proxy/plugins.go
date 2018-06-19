package main

import (
	"errors"
	"net"
	"sync"

	"github.com/jedisct1/dlog"
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

type PluginsGlobals struct {
	sync.RWMutex
	queryPlugins    *[]Plugin
	responsePlugins *[]Plugin
	loggingPlugins  *[]Plugin
}

type PluginsReturnCode int

const (
	PluginsReturnCodePass = iota
	PluginsReturnCodeForward
	PluginsReturnCodeDrop
	PluginsReturnCodeReject
	PluginsReturnCodeSynth
	PluginsReturnCodeParseError
	PluginsReturnCodeNXDomain
	PluginsReturnCodeResponseError
	PluginsReturnCodeServerError
)

var PluginsReturnCodeToString = map[PluginsReturnCode]string{
	PluginsReturnCodePass:          "PASS",
	PluginsReturnCodeForward:       "FORWARD",
	PluginsReturnCodeDrop:          "DROP",
	PluginsReturnCodeReject:        "REJECT",
	PluginsReturnCodeSynth:         "SYNTH",
	PluginsReturnCodeParseError:    "PARSE_ERROR",
	PluginsReturnCodeNXDomain:      "NXDOMAIN",
	PluginsReturnCodeResponseError: "RESPONSE_ERROR",
	PluginsReturnCodeServerError:   "SERVER_ERROR",
}

type PluginsState struct {
	sessionData            map[string]interface{}
	action                 PluginsAction
	originalMaxPayloadSize int
	maxPayloadSize         int
	clientProto            string
	clientAddr             *net.Addr
	synthResponse          *dns.Msg
	dnssec                 bool
	cacheSize              int
	cacheNegMinTTL         uint32
	cacheNegMaxTTL         uint32
	cacheMinTTL            uint32
	cacheMaxTTL            uint32
	questionMsg            *dns.Msg
	returnCode             PluginsReturnCode
}

func InitPluginsGlobals(pluginsGlobals *PluginsGlobals, proxy *Proxy) error {
	queryPlugins := &[]Plugin{}
	if len(proxy.whitelistNameFile) != 0 {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginWhitelistName)))
	}
	if len(proxy.blockNameFile) != 0 {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginBlockName)))
	}
	if proxy.pluginBlockIPv6 {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginBlockIPv6)))
	}
	if len(proxy.cloakFile) != 0 {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginCloak)))
	}
	*queryPlugins = append(*queryPlugins, Plugin(new(PluginGetSetPayloadSize)))
	if proxy.cache {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginCache)))
	}
	if len(proxy.forwardFile) != 0 {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginForward)))
	}

	responsePlugins := &[]Plugin{}
	if len(proxy.nxLogFile) != 0 {
		*responsePlugins = append(*responsePlugins, Plugin(new(PluginNxLog)))
	}
	if len(proxy.blockIPFile) != 0 {
		*responsePlugins = append(*responsePlugins, Plugin(new(PluginBlockIP)))
	}
	if proxy.cache {
		*responsePlugins = append(*responsePlugins, Plugin(new(PluginCacheResponse)))
	}

	loggingPlugins := &[]Plugin{}
	if len(proxy.queryLogFile) != 0 {
		*loggingPlugins = append(*loggingPlugins, Plugin(new(PluginQueryLog)))
	}

	for _, plugin := range *queryPlugins {
		if err := plugin.Init(proxy); err != nil {
			return err
		}
	}
	for _, plugin := range *responsePlugins {
		if err := plugin.Init(proxy); err != nil {
			return err
		}
	}
	for _, plugin := range *loggingPlugins {
		if err := plugin.Init(proxy); err != nil {
			return err
		}
	}

	(*pluginsGlobals).queryPlugins = queryPlugins
	(*pluginsGlobals).responsePlugins = responsePlugins
	(*pluginsGlobals).loggingPlugins = loggingPlugins
	return nil
}

type Plugin interface {
	Name() string
	Description() string
	Init(proxy *Proxy) error
	Drop() error
	Reload() error
	Eval(pluginsState *PluginsState, msg *dns.Msg) error
	Status() error
}

func NewPluginsState(proxy *Proxy, clientProto string, clientAddr *net.Addr) PluginsState {
	return PluginsState{
		action:         PluginsActionForward,
		maxPayloadSize: MaxDNSUDPPacketSize - ResponseOverhead,
		clientProto:    clientProto,
		clientAddr:     clientAddr,
		cacheSize:      proxy.cacheSize,
		cacheNegMinTTL: proxy.cacheNegMinTTL,
		cacheNegMaxTTL: proxy.cacheNegMaxTTL,
		cacheMinTTL:    proxy.cacheMinTTL,
		cacheMaxTTL:    proxy.cacheMaxTTL,
		questionMsg:    nil,
	}
}

func (pluginsState *PluginsState) ApplyQueryPlugins(pluginsGlobals *PluginsGlobals, packet []byte) ([]byte, error) {
	if len(*pluginsGlobals.queryPlugins) == 0 && len(*pluginsGlobals.loggingPlugins) == 0 {
		return packet, nil
	}
	pluginsState.action = PluginsActionForward
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return packet, err
	}
	if len(msg.Question) > 1 {
		return packet, errors.New("Unexpected number of questions")
	}
	pluginsState.questionMsg = &msg
	pluginsGlobals.RLock()
	for _, plugin := range *pluginsGlobals.queryPlugins {
		if ret := plugin.Eval(pluginsState, &msg); ret != nil {
			pluginsGlobals.RUnlock()
			pluginsState.action = PluginsActionDrop
			return packet, ret
		}
		if pluginsState.action == PluginsActionReject {
			synth, err := RefusedResponseFromMessage(&msg)
			if err != nil {
				return nil, err
			}
			pluginsState.synthResponse = synth
		}
		if pluginsState.action != PluginsActionForward {
			break
		}
	}
	pluginsGlobals.RUnlock()
	packet2, err := msg.PackBuffer(packet)
	if err != nil {
		return packet, err
	}
	return packet2, nil
}

func (pluginsState *PluginsState) ApplyResponsePlugins(pluginsGlobals *PluginsGlobals, packet []byte, ttl *uint32) ([]byte, error) {
	if len(*pluginsGlobals.responsePlugins) == 0 && len(*pluginsGlobals.loggingPlugins) == 0 {
		return packet, nil
	}
	pluginsState.action = PluginsActionForward
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		if len(packet) >= MinDNSPacketSize && HasTCFlag(packet) {
			err = nil
		}
		return packet, err
	}
	switch Rcode(packet) {
	case dns.RcodeSuccess:
		pluginsState.returnCode = PluginsReturnCodePass
	case dns.RcodeNameError:
		pluginsState.returnCode = PluginsReturnCodeNXDomain
	case dns.RcodeServerFailure:
		pluginsState.returnCode = PluginsReturnCodeServerError
	default:
		pluginsState.returnCode = PluginsReturnCodeResponseError
	}
	pluginsGlobals.RLock()
	for _, plugin := range *pluginsGlobals.responsePlugins {
		if ret := plugin.Eval(pluginsState, &msg); ret != nil {
			pluginsGlobals.RUnlock()
			pluginsState.action = PluginsActionDrop
			return packet, ret
		}
		if pluginsState.action == PluginsActionReject {
			synth, err := RefusedResponseFromMessage(&msg)
			if err != nil {
				return nil, err
			}
			dlog.Infof("Blocking [%s]", synth.Question[0].Name)
			pluginsState.synthResponse = synth
		}
		if pluginsState.action != PluginsActionForward {
			break
		}
	}
	pluginsGlobals.RUnlock()
	if ttl != nil {
		setMaxTTL(&msg, *ttl)
	}
	packet2, err := msg.PackBuffer(packet)
	if err != nil {
		return packet, err
	}
	return packet2, nil
}

func (pluginsState *PluginsState) ApplyLoggingPlugins(pluginsGlobals *PluginsGlobals) error {
	if len(*pluginsGlobals.loggingPlugins) == 0 {
		return nil
	}
	questionMsg := pluginsState.questionMsg
	if questionMsg == nil || len(questionMsg.Question) > 1 {
		return errors.New("Unexpected number of questions")
	}
	pluginsGlobals.RLock()
	for _, plugin := range *pluginsGlobals.loggingPlugins {
		if ret := plugin.Eval(pluginsState, questionMsg); ret != nil {
			pluginsGlobals.RUnlock()
			return ret
		}
	}
	pluginsGlobals.RUnlock()
	return nil
}

func (pluginsState *PluginsState) CollectStatistics(pluginsGlobals *PluginsGlobals) error {

	pluginsGlobals.RLock()
	defer pluginsGlobals.RUnlock()

	dlog.Debugf("Plugin count: %d query, %d response, %d logging", len(*pluginsGlobals.queryPlugins), len(*pluginsGlobals.responsePlugins), len(*pluginsGlobals.loggingPlugins))

	for _, plugin := range *pluginsGlobals.queryPlugins {
		if ret := plugin.Status(); ret != nil {
			return ret
		}
	}
	for _, plugin := range *pluginsGlobals.responsePlugins {
		if ret := plugin.Status(); ret != nil {
			return ret
		}
	}
	for _, plugin := range *pluginsGlobals.loggingPlugins {
		if ret := plugin.Status(); ret != nil {
			return ret
		}
	}
	return nil
}
