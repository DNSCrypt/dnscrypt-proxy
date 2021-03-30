package main

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginsAction int

const (
	PluginsActionNone     = 0
	PluginsActionContinue = 1
	PluginsActionDrop     = 2
	PluginsActionReject   = 3
	PluginsActionSynth    = 4
)

type PluginsGlobals struct {
	sync.RWMutex
	queryPlugins           *[]Plugin
	responsePlugins        *[]Plugin
	loggingPlugins         *[]Plugin
	refusedCodeInResponses bool
	respondWithIPv4        net.IP
	respondWithIPv6        net.IP
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
	PluginsReturnCodeServFail
	PluginsReturnCodeNetworkError
	PluginsReturnCodeCloak
	PluginsReturnCodeServerTimeout
	PluginsReturnCodeNotReady
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
	PluginsReturnCodeServFail:      "SERVFAIL",
	PluginsReturnCodeNetworkError:  "NETWORK_ERROR",
	PluginsReturnCodeCloak:         "CLOAK",
	PluginsReturnCodeServerTimeout: "SERVER_TIMEOUT",
	PluginsReturnCodeNotReady:      "NOT_READY",
}

type PluginsState struct {
	requestStart                     time.Time
	requestEnd                       time.Time
	clientProto                      string
	serverName                       string
	serverProto                      string
	qName                            string
	clientAddr                       *net.Addr
	synthResponse                    *dns.Msg
	questionMsg                      *dns.Msg
	sessionData                      map[string]interface{}
	action                           PluginsAction
	timeout                          time.Duration
	returnCode                       PluginsReturnCode
	maxPayloadSize                   int
	cacheSize                        int
	originalMaxPayloadSize           int
	maxUnencryptedUDPSafePayloadSize int
	rejectTTL                        uint32
	cacheMaxTTL                      uint32
	cacheNegMaxTTL                   uint32
	cacheNegMinTTL                   uint32
	cacheMinTTL                      uint32
	cacheHit                         bool
	dnssec                           bool
}

func (proxy *Proxy) InitPluginsGlobals() error {
	queryPlugins := &[]Plugin{}

	if proxy.captivePortalMap != nil {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginCaptivePortal)))
	}
	if len(proxy.queryMeta) != 0 {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginQueryMeta)))
	}
	if len(proxy.allowNameFile) != 0 {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginAllowName)))
	}

	*queryPlugins = append(*queryPlugins, Plugin(new(PluginFirefox)))

	if len(proxy.ednsClientSubnets) != 0 {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginECS)))
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
	if proxy.pluginBlockUnqualified {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginBlockUnqualified)))
	}
	if proxy.pluginBlockUndelegated {
		*queryPlugins = append(*queryPlugins, Plugin(new(PluginBlockUndelegated)))
	}

	responsePlugins := &[]Plugin{}
	if len(proxy.nxLogFile) != 0 {
		*responsePlugins = append(*responsePlugins, Plugin(new(PluginNxLog)))
	}
	if len(proxy.allowedIPFile) != 0 {
		*responsePlugins = append(*responsePlugins, Plugin(new(PluginAllowedIP)))
	}
	if len(proxy.blockNameFile) != 0 {
		*responsePlugins = append(*responsePlugins, Plugin(new(PluginBlockNameResponse)))
	}
	if len(proxy.blockIPFile) != 0 {
		*responsePlugins = append(*responsePlugins, Plugin(new(PluginBlockIP)))
	}
	if len(proxy.dns64Resolvers) != 0 || len(proxy.dns64Prefixes) != 0 {
		*responsePlugins = append(*responsePlugins, Plugin(new(PluginDNS64)))
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

	proxy.pluginsGlobals.queryPlugins = queryPlugins
	proxy.pluginsGlobals.responsePlugins = responsePlugins
	proxy.pluginsGlobals.loggingPlugins = loggingPlugins

	parseBlockedQueryResponse(proxy.blockedQueryResponse, &proxy.pluginsGlobals)

	return nil
}

// blockedQueryResponse can be 'refused', 'hinfo' or IP responses 'a:IPv4,aaaa:IPv6
func parseBlockedQueryResponse(blockedResponse string, pluginsGlobals *PluginsGlobals) {
	blockedResponse = StringStripSpaces(strings.ToLower(blockedResponse))

	if strings.HasPrefix(blockedResponse, "a:") {
		blockedIPStrings := strings.Split(blockedResponse, ",")
		(*pluginsGlobals).respondWithIPv4 = net.ParseIP(strings.TrimPrefix(blockedIPStrings[0], "a:"))

		if (*pluginsGlobals).respondWithIPv4 == nil {
			dlog.Notice("Error parsing IPv4 response given in blocked_query_response option, defaulting to `hinfo`")
			(*pluginsGlobals).refusedCodeInResponses = false
			return
		}

		if len(blockedIPStrings) > 1 {
			if strings.HasPrefix(blockedIPStrings[1], "aaaa:") {
				ipv6Response := strings.TrimPrefix(blockedIPStrings[1], "aaaa:")
				if strings.HasPrefix(ipv6Response, "[") {
					ipv6Response = strings.Trim(ipv6Response, "[]")
				}
				(*pluginsGlobals).respondWithIPv6 = net.ParseIP(ipv6Response)

				if (*pluginsGlobals).respondWithIPv6 == nil {
					dlog.Notice("Error parsing IPv6 response given in blocked_query_response option, defaulting to IPv4")
				}
			} else {
				dlog.Noticef("Invalid IPv6 response given in blocked_query_response option [%s], the option should take the form 'a:<IPv4>,aaaa:<IPv6>'", blockedIPStrings[1])
			}
		}

		if (*pluginsGlobals).respondWithIPv6 == nil {
			(*pluginsGlobals).respondWithIPv6 = (*pluginsGlobals).respondWithIPv4
		}
	} else {
		switch blockedResponse {
		case "refused":
			(*pluginsGlobals).refusedCodeInResponses = true
		case "hinfo":
			(*pluginsGlobals).refusedCodeInResponses = false
		default:
			dlog.Noticef("Invalid blocked_query_response option [%s], defaulting to `hinfo`", blockedResponse)
			(*pluginsGlobals).refusedCodeInResponses = false
		}
	}
}

type Plugin interface {
	Name() string
	Description() string
	Init(proxy *Proxy) error
	Drop() error
	Reload() error
	Eval(pluginsState *PluginsState, msg *dns.Msg) error
}

func NewPluginsState(proxy *Proxy, clientProto string, clientAddr *net.Addr, serverProto string, start time.Time) PluginsState {
	return PluginsState{
		action:                           PluginsActionContinue,
		returnCode:                       PluginsReturnCodePass,
		maxPayloadSize:                   MaxDNSUDPPacketSize - ResponseOverhead,
		clientProto:                      clientProto,
		clientAddr:                       clientAddr,
		cacheSize:                        proxy.cacheSize,
		cacheNegMinTTL:                   proxy.cacheNegMinTTL,
		cacheNegMaxTTL:                   proxy.cacheNegMaxTTL,
		cacheMinTTL:                      proxy.cacheMinTTL,
		cacheMaxTTL:                      proxy.cacheMaxTTL,
		rejectTTL:                        proxy.rejectTTL,
		questionMsg:                      nil,
		qName:                            "",
		serverName:                       "-",
		serverProto:                      serverProto,
		timeout:                          proxy.timeout,
		requestStart:                     start,
		maxUnencryptedUDPSafePayloadSize: MaxDNSUDPSafePacketSize,
		sessionData:                      make(map[string]interface{}),
	}
}

func (pluginsState *PluginsState) ApplyQueryPlugins(pluginsGlobals *PluginsGlobals, packet []byte, needsEDNS0Padding bool) ([]byte, error) {
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return packet, err
	}
	if len(msg.Question) != 1 {
		return packet, errors.New("Unexpected number of questions")
	}
	qName, err := NormalizeQName(msg.Question[0].Name)
	if err != nil {
		return packet, err
	}
	dlog.Debugf("Handling query for [%v]", qName)
	pluginsState.qName = qName
	pluginsState.questionMsg = &msg
	if len(*pluginsGlobals.queryPlugins) == 0 && len(*pluginsGlobals.loggingPlugins) == 0 {
		return packet, nil
	}
	pluginsGlobals.RLock()
	defer pluginsGlobals.RUnlock()
	for _, plugin := range *pluginsGlobals.queryPlugins {
		if err := plugin.Eval(pluginsState, &msg); err != nil {
			pluginsState.action = PluginsActionDrop
			return packet, err
		}
		if pluginsState.action == PluginsActionReject {
			synth := RefusedResponseFromMessage(&msg, pluginsGlobals.refusedCodeInResponses, pluginsGlobals.respondWithIPv4, pluginsGlobals.respondWithIPv6, pluginsState.rejectTTL)
			pluginsState.synthResponse = synth
		}
		if pluginsState.action != PluginsActionContinue {
			break
		}
	}

	packet2, err := msg.PackBuffer(packet)
	if err != nil {
		return packet, err
	}
	if needsEDNS0Padding && pluginsState.action == PluginsActionContinue {
		padLen := 63 - ((len(packet2) + 63) & 63)
		if paddedPacket2, _ := addEDNS0PaddingIfNoneFound(&msg, packet2, padLen); paddedPacket2 != nil {
			return paddedPacket2, nil
		}
	}
	return packet2, nil
}

func (pluginsState *PluginsState) ApplyResponsePlugins(pluginsGlobals *PluginsGlobals, packet []byte, ttl *uint32) ([]byte, error) {
	msg := dns.Msg{Compress: true}
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
		pluginsState.returnCode = PluginsReturnCodeServFail
	default:
		pluginsState.returnCode = PluginsReturnCodeResponseError
	}
	removeEDNS0Options(&msg)
	pluginsGlobals.RLock()
	defer pluginsGlobals.RUnlock()
	for _, plugin := range *pluginsGlobals.responsePlugins {
		if err := plugin.Eval(pluginsState, &msg); err != nil {
			pluginsState.action = PluginsActionDrop
			return packet, err
		}
		if pluginsState.action == PluginsActionReject {
			synth := RefusedResponseFromMessage(&msg, pluginsGlobals.refusedCodeInResponses, pluginsGlobals.respondWithIPv4, pluginsGlobals.respondWithIPv6, pluginsState.rejectTTL)
			pluginsState.synthResponse = synth
		}
		if pluginsState.action != PluginsActionContinue {
			break
		}
	}
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
	pluginsState.requestEnd = time.Now()
	questionMsg := pluginsState.questionMsg
	if questionMsg == nil {
		return errors.New("Question not found")
	}
	pluginsGlobals.RLock()
	defer pluginsGlobals.RUnlock()
	for _, plugin := range *pluginsGlobals.loggingPlugins {
		if err := plugin.Eval(pluginsState, questionMsg); err != nil {
			return err
		}
	}
	return nil
}
