package main

import (
	"math/rand"
	"net"
	"time"

	"github.com/jedisct1/dlog"
	clocksmith "github.com/jedisct1/go-clocksmith"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/miekg/dns"
)

// validateQuery - Performs basic validation on the incoming query
func validateQuery(query []byte) bool {
	if len(query) < MinDNSPacketSize {
		return false
	}
	if len(query) > MaxDNSPacketSize {
		return false
	}
	return true
}

// handleSynthesizedResponse - Handles a synthesized DNS response from plugins
func handleSynthesizedResponse(pluginsState *PluginsState, synth *dns.Msg) ([]byte, error) {
	var response []byte
	var err error

	response, err = synth.PackBuffer(response)
	if err != nil {
		pluginsState.returnCode = PluginsReturnCodeParseError
		// We can't access proxy from pluginsState directly, but the caller will handle logging
	}

	return response, err
}

// processDNSCryptQuery - Processes a query using the DNSCrypt protocol
func processDNSCryptQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
	serverProto string,
) ([]byte, error) {
	sharedKey, encryptedQuery, clientNonce, err := proxy.Encrypt(serverInfo, query, serverProto)
	if err != nil && serverProto == "udp" {
		dlog.Debug("Unable to pad for UDP, re-encrypting query for TCP")
		serverProto = "tcp"
		sharedKey, encryptedQuery, clientNonce, err = proxy.Encrypt(serverInfo, query, serverProto)
	}

	if err != nil {
		pluginsState.returnCode = PluginsReturnCodeParseError
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		return nil, err
	}

	serverInfo.noticeBegin(proxy)
	var response []byte

	if serverProto == "udp" {
		response, err = proxy.exchangeWithUDPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
		retryOverTCP := false
		if err == nil && len(response) >= MinDNSPacketSize && response[2]&0x02 == 0x02 {
			retryOverTCP = true
		} else if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
			dlog.Debugf("[%v] Retry over TCP after UDP timeouts", serverInfo.Name)
			retryOverTCP = true
		}
		if retryOverTCP {
			serverProto = "tcp"
			sharedKey, encryptedQuery, clientNonce, err = proxy.Encrypt(serverInfo, query, serverProto)
			if err != nil {
				pluginsState.returnCode = PluginsReturnCodeParseError
				pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
				serverInfo.noticeFailure(proxy)
				return nil, err
			}
			response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
		}
	} else {
		response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
	}

	// Check for stale response if there was an error
	if err != nil {
		if stale, ok := pluginsState.sessionData["stale"]; ok {
			dlog.Debug("Serving stale response")
			serverInfo.noticeFailure(proxy)
			if staleResponse, err := (stale.(*dns.Msg)).Pack(); err == nil {
				return staleResponse, nil
			}
		}
	}

	// Handle error cases
	if err != nil {
		if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
			pluginsState.returnCode = PluginsReturnCodeServerTimeout
		} else {
			pluginsState.returnCode = PluginsReturnCodeNetworkError
		}
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		serverInfo.noticeFailure(proxy)
		return nil, err
	}

	return response, nil
}

// processDoHQuery - Processes a query using the DoH protocol
func processDoHQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
) ([]byte, error) {
	tid := TransactionID(query)
	SetTransactionID(query, 0)
	serverInfo.noticeBegin(proxy)
	serverResponse, _, tls, _, err := proxy.xTransport.DoHQuery(serverInfo.useGet, serverInfo.URL, query, proxy.timeout)
	SetTransactionID(query, tid)

	// A response was received, and the TLS handshake was complete.
	if err == nil && tls != nil && tls.HandshakeComplete {
		// Restore the original transaction ID
		response := serverResponse
		if len(response) >= MinDNSPacketSize {
			SetTransactionID(response, tid)
		}
		return response, nil
	}

	serverInfo.noticeFailure(proxy)

	// Attempt to serve a stale response as a fallback.
	if stale, ok := pluginsState.sessionData["stale"]; ok {
		dlog.Debug("Serving stale response")
		if staleResponse, packErr := (stale.(*dns.Msg)).Pack(); packErr == nil {
			return staleResponse, nil
		}
	}

	// If no stale response was served, return the original error.
	pluginsState.returnCode = PluginsReturnCodeNetworkError
	pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
	return nil, err
}

// processODoHQuery - Processes a query using the ODoH protocol
func processODoHQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
) ([]byte, error) {
	tid := TransactionID(query)
	if len(serverInfo.odohTargetConfigs) == 0 {
		return nil, nil
	}

	serverInfo.noticeBegin(proxy)

	target := serverInfo.odohTargetConfigs[rand.Intn(len(serverInfo.odohTargetConfigs))]
	odohQuery, err := target.encryptQuery(query)
	if err != nil {
		dlog.Errorf("Failed to encrypt query for [%v]", serverInfo.Name)
		return nil, err
	}

	targetURL := serverInfo.URL
	if serverInfo.Relay != nil && serverInfo.Relay.ODoH != nil {
		targetURL = serverInfo.Relay.ODoH.URL
	}

	responseBody, responseCode, _, _, err := proxy.xTransport.ObliviousDoHQuery(
		serverInfo.useGet, targetURL, odohQuery.odohMessage, proxy.timeout)

	if err == nil && len(responseBody) > 0 && responseCode == 200 {
		response, err := odohQuery.decryptResponse(responseBody)
		if err != nil {
			dlog.Warnf("Failed to decrypt response from [%v]", serverInfo.Name)
			serverInfo.noticeFailure(proxy)
			return nil, err
		}

		// Restore the original transaction ID
		if len(response) >= MinDNSPacketSize {
			SetTransactionID(response, tid)
		}

		return response, nil
	} else if responseCode == 401 || (responseCode == 200 && len(responseBody) == 0) {
		if responseCode == 200 {
			dlog.Warnf("ODoH relay for [%v] is buggy and returns a 200 status code instead of 401 after a key update", serverInfo.Name)
		}

		dlog.Infof("Forcing key update for [%v]", serverInfo.Name)
		for _, registeredServer := range proxy.serversInfo.registeredServers {
			if registeredServer.name == serverInfo.Name {
				if err = proxy.serversInfo.refreshServer(proxy, registeredServer.name, registeredServer.stamp); err != nil {
					dlog.Noticef("Key update failed for [%v]", serverInfo.Name)
					serverInfo.noticeFailure(proxy)
					clocksmith.Sleep(10 * time.Second)
				}
				break
			}
		}
	} else {
		dlog.Warnf("Failed to receive successful response from [%v]", serverInfo.Name)
	}

	pluginsState.returnCode = PluginsReturnCodeNetworkError
	pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
	serverInfo.noticeFailure(proxy)

	return nil, err
}

// handleDNSExchange - Handles the DNS exchange with a server
func handleDNSExchange(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
	serverProto string,
) ([]byte, error) {
	var err error
	var response []byte

	if serverInfo.Proto == stamps.StampProtoTypeDNSCrypt {
		response, err = processDNSCryptQuery(proxy, serverInfo, pluginsState, query, serverProto)
	} else if serverInfo.Proto == stamps.StampProtoTypeDoH {
		response, err = processDoHQuery(proxy, serverInfo, pluginsState, query)
	} else if serverInfo.Proto == stamps.StampProtoTypeODoHTarget {
		response, err = processODoHQuery(proxy, serverInfo, pluginsState, query)
	} else {
		dlog.Fatal("Unsupported protocol")
	}

	if err != nil {
		return nil, err
	}

	if len(response) < MinDNSPacketSize || len(response) > MaxDNSPacketSize {
		pluginsState.returnCode = PluginsReturnCodeParseError
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		serverInfo.noticeFailure(proxy)
		return nil, err
	}

	return response, nil
}

// processPlugins - Processes plugins for both query and response
func processPlugins(
	proxy *Proxy,
	pluginsState *PluginsState,
	query []byte,
	serverInfo *ServerInfo,
	response []byte,
) ([]byte, error) {
	var err error

	response, err = pluginsState.ApplyResponsePlugins(&proxy.pluginsGlobals, response)
	if err != nil {
		pluginsState.returnCode = PluginsReturnCodeParseError
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		serverInfo.noticeFailure(proxy)
		return response, err
	}

	if pluginsState.action == PluginsActionDrop {
		pluginsState.returnCode = PluginsReturnCodeDrop
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		return response, nil
	}

	if pluginsState.synthResponse != nil {
		response, err = pluginsState.synthResponse.PackBuffer(response)
		if err != nil {
			pluginsState.returnCode = PluginsReturnCodeParseError
			pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
			return response, err
		}
	}

	// Check rcode and handle failures
	if rcode := Rcode(response); rcode == dns.RcodeServerFailure { // SERVFAIL
		if pluginsState.dnssec {
			dlog.Debug("A response had an invalid DNSSEC signature")
		} else {
			dlog.Infof("A response with status code 2 was received - this is usually a temporary, remote issue with the configuration of the domain name")
			serverInfo.noticeFailure(proxy)
		}
	} else {
		serverInfo.noticeSuccess(proxy)
	}

	return response, nil
}

// sendResponse - Sends the response back to the client
func sendResponse(
	proxy *Proxy,
	pluginsState *PluginsState,
	response []byte,
	clientProto string,
	clientAddr *net.Addr,
	clientPc net.Conn,
) {
	if len(response) < MinDNSPacketSize || len(response) > MaxDNSPacketSize {
		if len(response) == 0 {
			pluginsState.returnCode = PluginsReturnCodeNotReady
		} else {
			pluginsState.returnCode = PluginsReturnCodeParseError
		}
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		return
	}

	var err error
	if clientProto == "udp" {
		if len(response) > pluginsState.maxUnencryptedUDPSafePayloadSize {
			response, err = TruncatedResponse(response)
			if err != nil {
				pluginsState.returnCode = PluginsReturnCodeParseError
				pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
				return
			}
		}
		clientPc.(net.PacketConn).WriteTo(response, *clientAddr)
		if HasTCFlag(response) {
			proxy.questionSizeEstimator.blindAdjust()
		} else {
			proxy.questionSizeEstimator.adjust(ResponseOverhead + len(response))
		}
	} else if clientProto == "tcp" {
		response, err = PrefixWithSize(response)
		if err != nil {
			pluginsState.returnCode = PluginsReturnCodeParseError
			pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
			return
		}
		if clientPc != nil {
			clientPc.Write(response)
		}
	}
}

// updateMonitoringMetrics - Updates monitoring metrics if enabled
func updateMonitoringMetrics(
	proxy *Proxy,
	pluginsState *PluginsState,
) {
	if proxy.monitoringUI.Enabled && proxy.monitoringInstance != nil && pluginsState.questionMsg != nil {
		dlog.Debugf("Calling UpdateMetrics for query: %s", pluginsState.qName)
		proxy.monitoringInstance.UpdateMetrics(*pluginsState, pluginsState.questionMsg)
	} else {
		if pluginsState.questionMsg == nil {
			dlog.Debugf("Question message is nil")
		}
	}
}
