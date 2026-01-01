package main

import (
    "encoding/binary"
    "math/rand"
    "net"
    "time"

    "codeberg.org/miekg/dns"
    "github.com/jedisct1/dlog"
    clocksmith "github.com/jedisct1/go-clocksmith"
    stamps "github.com/jedisct1/go-dnsstamps"
)

// Elite: In-place Transaction ID manipulation to avoid dns.Msg parsing
func fastGetID(query []byte) uint16 {
    if len(query) < 2 {
        return 0
    }
    return binary.BigEndian.Uint16(query[0:2])
}

func fastSetID(query []byte, tid uint16) {
    if len(query) >= 2 {
        binary.BigEndian.PutUint16(query[0:2], tid)
    }
}

// processDNSCryptQuery - Upgraded with explicit buffer pool handling
func (proxy *Proxy) processDNSCryptQuery(
    serverInfo *ServerInfo,
    pluginsState *PluginsState,
    query []byte,
    serverProto string,
) ([]byte, error) {
    // Encrypt handles internal pooling; clientNonce is a fixed-size stack array
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
        // Elite: Explicit slice [:] conversion for the byte array
        response, err = proxy.exchangeWithUDPServer(serverInfo, sharedKey, encryptedQuery, clientNonce[:])
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
            response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce[:])
        }
    } else {
        response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce[:])
    }

    if err != nil {
        serverInfo.noticeFailure(proxy)
        if stale, ok := pluginsState.sessionData["stale"]; ok {
            dlog.Debug("Serving stale response")
            staleMsg := stale.(*dns.Msg)
            if packErr := staleMsg.Pack(); packErr == nil {
                return staleMsg.Data, nil
            }
        }
        if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
            pluginsState.returnCode = PluginsReturnCodeServerTimeout
        } else {
            pluginsState.returnCode = PluginsReturnCodeNetworkError
        }
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        return nil, err
    }

    return response, nil
}

// processDoHQuery - Optimized zero-copy ID restoration
func (proxy *Proxy) processDoHQuery(
    serverInfo *ServerInfo,
    pluginsState *PluginsState,
    query []byte,
) ([]byte, error) {
    tid := fastGetID(query)
    fastSetID(query, 0) // DNS-over-HTTPS spec requires 0 ID in wire format
    serverInfo.noticeBegin(proxy)
    serverResponse, _, tls, _, err := proxy.xTransport.DoHQuery(serverInfo.useGet, serverInfo.URL, query, proxy.timeout)
    fastSetID(query, tid)

    if err == nil && tls != nil && tls.HandshakeComplete {
        response := serverResponse
        if len(response) >= MinDNSPacketSize {
            fastSetID(response, tid)
        }
        return response, nil
    }

    serverInfo.noticeFailure(proxy)
    if stale, ok := pluginsState.sessionData["stale"]; ok {
        staleMsg := stale.(*dns.Msg)
        if packErr := staleMsg.Pack(); packErr == nil {
            return staleMsg.Data, nil
        }
    }

    pluginsState.returnCode = PluginsReturnCodeNetworkError
    pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
    return nil, err
}

// handleDNSExchange - Core dispatch logic
func (proxy *Proxy) handleDNSExchange(
    serverInfo *ServerInfo,
    pluginsState *PluginsState,
    query []byte,
    serverProto string,
) ([]byte, error) {
    var err error
    var response []byte

    switch serverInfo.Proto {
    case stamps.StampProtoTypeDNSCrypt:
        response, err = proxy.processDNSCryptQuery(serverInfo, pluginsState, query, serverProto)
    case stamps.StampProtoTypeDoH:
        response, err = proxy.processDoHQuery(serverInfo, pluginsState, query)
    case stamps.StampProtoTypeODoHTarget:
        response, err = proxy.processODoHQuery(serverInfo, pluginsState, query)
    default:
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

// processPlugins - High-performance response transformation
func (proxy *Proxy) processPlugins(
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
        if serverInfo != nil {
            serverInfo.noticeFailure(proxy)
        }
        return response, err
    }

    if pluginsState.action == PluginsActionDrop {
        pluginsState.returnCode = PluginsReturnCodeDrop
        pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
        return response, nil
    }

    if pluginsState.synthResponse != nil {
        if err = pluginsState.synthResponse.Pack(); err != nil {
            pluginsState.returnCode = PluginsReturnCodeParseError
            pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
            return response, err
        }
        response = pluginsState.synthResponse.Data
    }

    if rcode := Rcode(response); rcode == dns.RcodeServerFailure {
        if !pluginsState.dnssec && serverInfo != nil {
            dlog.Infof("A response with status code 2 (SERVFAIL) was received from [%v]", serverInfo.Name)
            serverInfo.noticeFailure(proxy)
        }
    } else if serverInfo != nil {
        serverInfo.noticeSuccess(proxy)
    }

    return response, nil
}

// sendResponse - Optimized network egress
func (proxy *Proxy) sendResponse(
    pluginsState *PluginsState,
    response []byte,
    clientProto string,
    clientAddr *net.Addr,
    clientPc net.Conn,
) {
    if len(response) < MinDNSPacketSize || len(response) > MaxDNSPacketSize {
        pluginsState.returnCode = PluginsReturnCodeParseError
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
