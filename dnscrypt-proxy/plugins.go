package main

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"
	"github.com/fsnotify/fsnotify"
	"github.com/jedisct1/dlog"
	"github.com/jedisct1/go-clocksmith"
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
	queryPlugins           *[]Plugin
	responsePlugins        *[]Plugin
	loggingPlugins         *[]Plugin
	refusedCodeInResponses bool
	respondWithIPv4        net.IP
	respondWithIPv6        net.IP
	watcher                *fsnotify.Watcher
	reloadMap              map[string]*PluginReloadState
	reloadMutex            sync.RWMutex
	reloadRunning          bool
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
	PluginsReturnCodeCloak
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
	PluginsReturnCodeCloak:         "CLOAK",
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
	requestStart           time.Time
	requestEnd             time.Time
	cacheHit               bool
	returnCode             PluginsReturnCode
	serverName             string
}

type PluginReloadState struct {
	fileName      string
	pluginArray   *[]Plugin
	arrayIdx      int
	triggerReload bool
	newPlugin     func() Plugin
}

func (state *PluginReloadState) initNewPlugin(pluginsGlobals *PluginsGlobals, proxy *Proxy) (Plugin, error) {
	newPlugin := state.newPlugin()

	pluginsGlobals.RLock()
	defer pluginsGlobals.RUnlock()

	if err := newPlugin.Init(proxy, &(*state.pluginArray)[state.arrayIdx]); err != nil {
		return nil, err
	}
	return newPlugin, nil
}

func (state *PluginReloadState) updatePlugin(pluginsGlobals *PluginsGlobals, newPlugin Plugin) {
	pluginsGlobals.Lock()
	defer pluginsGlobals.Unlock()

	(*state.pluginArray)[state.arrayIdx] = newPlugin
}

func (state *PluginReloadState) ReloadPlugin(pluginsGlobals *PluginsGlobals, proxy *Proxy) error {
	if state.triggerReload {
		dlog.Debugf("Reloading plugin that watches file [%s]", state.fileName)

		newPlugin, err := state.initNewPlugin(pluginsGlobals, proxy)
		if err != nil {
			return err
		}

		state.updatePlugin(pluginsGlobals, newPlugin)

		state.triggerReload = false
		dlog.Noticef("Plugin [%s] reloaded", newPlugin.Name())
	}

	return nil
}

func watchPluginFile(pluginsGlobals *PluginsGlobals, fileName string, pluginArray *[]Plugin, newPlugin func() Plugin) error {
	pluginsGlobals.reloadMap[fileName] = &PluginReloadState{
		fileName:      fileName,
		pluginArray:   pluginArray,
		arrayIdx:      len(*pluginArray) - 1,
		triggerReload: false,
		newPlugin:     newPlugin,
	}

	if err := pluginsGlobals.watcher.Add(fileName); err != nil {
		return err
	}

	return nil
}

func initFileWatcher(pluginsGlobals *PluginsGlobals, proxy *Proxy) error {
	pluginsGlobals.reloadMap = make(map[string]*PluginReloadState)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	(*pluginsGlobals).watcher = watcher

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				if event.Op&fsnotify.Write == fsnotify.Write {
					dlog.Debugf("Plugin file [%s] has been modified", event.Name)

					if reloadState, ok := pluginsGlobals.reloadMap[event.Name]; ok {
						pluginsGlobals.reloadMutex.Lock()
						reloadState.triggerReload = true
						if !pluginsGlobals.reloadRunning {
							pluginsGlobals.reloadRunning = true
							go pluginReloader(pluginsGlobals, proxy)
						}
						pluginsGlobals.reloadMutex.Unlock()
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}

				dlog.Warnf("fsnotify.Watcher error:", err)
			}
		}
	}()

	dlog.Notice("Hot reload of plugins is enabled")

	return nil
}

func pluginReloader(pluginsGlobals *PluginsGlobals, proxy *Proxy) {
	// wait 2 seconds for debouncing...
	clocksmith.Sleep(2 * time.Second)

	pluginsGlobals.reloadMutex.RLock()
	defer pluginsGlobals.reloadMutex.RUnlock()

	// handle all updated plugins that were flagged during the debouncing period
	for _, state := range pluginsGlobals.reloadMap {
		if err := state.ReloadPlugin(pluginsGlobals, proxy); err != nil {
			dlog.Error(err)
		}
	}

	pluginsGlobals.reloadRunning = false
}

func InitPluginsGlobals(pluginsGlobals *PluginsGlobals, proxy *Proxy) error {
	if proxy.hotReloadPlugins {
		if err := initFileWatcher(pluginsGlobals, proxy); err != nil {
			return err
		}
	}

	type pluginInfo struct {
		pluginArray   *[]Plugin
		pluginEnabled bool
		watchFileName string
		newPlugin     func() Plugin
	}

	queryPlugins := &[]Plugin{}
	responsePlugins := &[]Plugin{}
	loggingPlugins := &[]Plugin{}

	plugins := []pluginInfo{
		{queryPlugins, PluginWhitelistNameEnabled(proxy), proxy.whitelistNameFile, NewPluginWhitelistName},
		{queryPlugins, PluginBlockNameEnabled(proxy), proxy.blockNameFile, NewPluginBlockName},
		{queryPlugins, PluginBlockIPv6Enabled(proxy), "", NewPluginBlockIPv6},
		{queryPlugins, PluginCloakEnabled(proxy), proxy.cloakFile, NewPluginCloak},
		{queryPlugins, PluginGetSetPayloadSizeEnabled(proxy), "", NewPluginGetSetPayloadSize},
		{queryPlugins, PluginCacheEnabled(proxy), "", NewPluginCache},
		{queryPlugins, PluginForwardEnabled(proxy), proxy.forwardFile, NewPluginForward},
		{responsePlugins, PluginNxLogEnabled(proxy), "", NewPluginNxLog},
		{responsePlugins, PluginBlockIPEnabled(proxy), proxy.blockIPFile, NewPluginBlockIP},
		{responsePlugins, PluginCacheResponseEnabled(proxy), "", NewPluginCacheResponse},
		{loggingPlugins, PluginQueryLogEnabled(proxy), "", NewPluginQueryLog},
	}

	for _, p := range plugins {
		if !p.pluginEnabled {
			continue
		}

		plugin := p.newPlugin()
		dlog.Noticef("Plugin [%s] enabled", plugin.Name())
		*p.pluginArray = append(*p.pluginArray, plugin)

		if proxy.hotReloadPlugins && (len(p.watchFileName) != 0) {
			if err := watchPluginFile(pluginsGlobals, p.watchFileName, p.pluginArray, p.newPlugin); err != nil {
				return err
			}
		}

		if err := plugin.Init(proxy, nil); err != nil {
			return err
		}
	}

	(*pluginsGlobals).queryPlugins = queryPlugins
	(*pluginsGlobals).responsePlugins = responsePlugins
	(*pluginsGlobals).loggingPlugins = loggingPlugins

	parseBlockedQueryResponse(proxy.blockedQueryResponse, pluginsGlobals)

	return nil
}

// blockedQueryResponse can be 'refused', 'hinfo' or IP responses 'a:IPv4,aaaa:IPv6
func parseBlockedQueryResponse(bockedResponse string, pluginsGlobals *PluginsGlobals) {
	bockedResponse = strings.ReplaceAll(strings.ToLower(bockedResponse), " ", "")

	if strings.HasPrefix(bockedResponse, "a:") {
		blockedIPStrings := strings.Split(bockedResponse, ",")
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
		switch bockedResponse {
		case "refused":
			(*pluginsGlobals).refusedCodeInResponses = true
		case "hinfo":
			(*pluginsGlobals).refusedCodeInResponses = false
		default:
			dlog.Noticef("Invalid blocked_query_response option [%s], defaulting to `hinfo`", bockedResponse)
			(*pluginsGlobals).refusedCodeInResponses = false
		}
	}
}

type Plugin interface {
	Name() string
	Description() string
	Init(proxy *Proxy, old *Plugin) error
	Drop() error
	Reload() error
	Eval(pluginsState *PluginsState, msg *dns.Msg) error
}

func NewPluginsState(proxy *Proxy, clientProto string, clientAddr *net.Addr, start time.Time) PluginsState {
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
		requestStart:   start,
	}
}

func (pluginsState *PluginsState) ApplyQueryPlugins(pluginsGlobals *PluginsGlobals, packet []byte, serverName string) ([]byte, error) {
	if len(*pluginsGlobals.queryPlugins) == 0 && len(*pluginsGlobals.loggingPlugins) == 0 {
		return packet, nil
	}
	pluginsState.serverName = serverName
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
			synth, err := RefusedResponseFromMessage(&msg, pluginsGlobals.refusedCodeInResponses, pluginsGlobals.respondWithIPv4, pluginsGlobals.respondWithIPv6, pluginsState.cacheMinTTL)
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
			synth, err := RefusedResponseFromMessage(&msg, pluginsGlobals.refusedCodeInResponses, pluginsGlobals.respondWithIPv4, pluginsGlobals.respondWithIPv6, pluginsState.cacheMinTTL)
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
	pluginsState.requestEnd = time.Now()
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
