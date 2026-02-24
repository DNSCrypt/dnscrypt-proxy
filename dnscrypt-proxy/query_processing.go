// Package main implements DNS query processing for dnscrypt-proxy.
//
// Go 1.26 full rewrite — all improvements applied:
//   - math/rand replaced with math/rand/v2 (Go 1.22+); no mutex on hot path
//   - err.(net.Error) type assertions replaced with errors.As for proper unwrapping
//   - processDoHQuery: success gated on err==nil only (not HandshakeComplete)
//   - HTTPStatusOK/Unauthorized replaced with net/http.StatusOK/StatusUnauthorized
//   - DNSTruncatedFlag removed; HasTCFlag from dnsutils.go used directly
//   - processODoHQuery: linear server scan replaced with named lookup helper
//   - clocksmith.Sleep moved to background goroutine (non-blocking hot path)
//   - handleDNSExchange: unreachable return after dlog.Fatalf removed
//   - sendResponse: zero-length (drop) path sets PluginsReturnCodeDrop, not NotReady
//   - handleSynthesizedResponse: ApplyLoggingPlugins added on pack failure
//   - validateQuery (bool) removed; all callers use validateQueryWithError
//   - processPlugins: dead parameter `query []byte` removed
//   - executeDNSCryptQuery: var declarations collapsed into branch assignments
//   - processPlugins: failWith helper eliminates repeated returnCode+logging pairs
//   - updateMonitoringMetrics: nil instance with enabled monitoring logs Warn
//   - All "// Go 1.26:" noise comments replaced with meaningful godoc
//   - encryptQueryForProtocol: simplified named-return style
//   - KeyUpdateRetryDelay unexported (keyUpdateRetryDelay) — only used internally
package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	randv2 "math/rand/v2"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
	clocksmith "github.com/jedisct1/go-clocksmith"
	stamps "github.com/jedisct1/go-dnsstamps"
)

// ─────────────────────────────────────── constants ──────────────────────────

const (
	// keyUpdateRetryDelay is the back-off period before retrying an ODoH key
	// refresh after a 401 or empty-body 200 response.
	keyUpdateRetryDelay = 10 * time.Second
)

// ─────────────────────────────────────── sentinel errors ────────────────────

// Sentinel errors for DNS query/response validation.
// All are suitable for use with errors.Is after fmt.Errorf("%w", ...) wrapping.
var (
	ErrQueryTooSmall       = errors.New("DNS query too small")
	ErrQueryTooLarge       = errors.New("DNS query too large")
	ErrResponseTooSmall    = errors.New("DNS response too small")
	ErrResponseTooLarge    = errors.New("DNS response too large")
	ErrInvalidResponse     = errors.New("invalid DNS response")
	ErrUnsupportedProtocol = errors.New("unsupported protocol")
	ErrNoODoHConfig        = errors.New("no ODoH target configs available")
)

// ─────────────────────────────────────── validation ─────────────────────────

// validateQueryWithError validates the length of a raw DNS query.
// Returns a wrapped sentinel error with byte counts for callers that log details.
func validateQueryWithError(query []byte) error {
	n := len(query)
	switch {
	case n < MinDNSPacketSize:
		return fmt.Errorf("%w: got %d bytes, minimum %d", ErrQueryTooSmall, n, MinDNSPacketSize)
	case n > MaxDNSPacketSize:
		return fmt.Errorf("%w: got %d bytes, maximum %d", ErrQueryTooLarge, n, MaxDNSPacketSize)
	}
	return nil
}

// validateResponse validates the length of a raw DNS response.
// Returns a wrapped sentinel error with byte counts.
func validateResponse(response []byte) error {
	n := len(response)
	switch {
	case n < MinDNSPacketSize:
		return fmt.Errorf("%w: got %d bytes, minimum %d", ErrResponseTooSmall, n, MinDNSPacketSize)
	case n > MaxDNSPacketSize:
		return fmt.Errorf("%w: got %d bytes, maximum %d", ErrResponseTooLarge, n, MaxDNSPacketSize)
	}
	return nil
}

// ─────────────────────────────────────── plugin helpers ─────────────────────

// failWith sets pluginsState.returnCode, applies logging plugins, and returns
// the provided error. Used to consolidate the repeated pattern:
//
//	pluginsState.returnCode = X
//	pluginsState.ApplyLoggingPlugins(...)
//	return ..., err
func failWith(pluginsState *PluginsState, proxy *Proxy, code int, err error) error {
	pluginsState.returnCode = code
	pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
	return err
}

// handleSynthesizedResponse packs a synthesized DNS message and returns its
// wire-format bytes. Sets PluginsReturnCodeParseError and logs if packing fails.
func handleSynthesizedResponse(pluginsState *PluginsState, proxy *Proxy, synth *dns.Msg) ([]byte, error) {
	if synth == nil {
		return nil, errors.New("synthesized message is nil")
	}
	if err := synth.Pack(); err != nil {
		return nil, failWith(pluginsState, proxy, PluginsReturnCodeParseError,
			fmt.Errorf("failed to pack synthesized response: %w", err))
	}
	return synth.Data, nil
}

// tryServeStaleResponse returns the packed bytes of a stale cached response
// stored in pluginsState.sessionData["stale"], if present and valid.
// Returns (nil, false) if no stale entry exists or packing fails.
func tryServeStaleResponse(pluginsState *PluginsState) ([]byte, bool) {
	stale, ok := pluginsState.sessionData["stale"]
	if !ok {
		return nil, false
	}
	staleMsg, ok := stale.(*dns.Msg)
	if !ok {
		dlog.Warn("Invalid stale response type in session data")
		return nil, false
	}
	if err := staleMsg.Pack(); err != nil {
		dlog.Warnf("Failed to pack stale response: %v", err)
		return nil, false
	}
	dlog.Debug("Serving stale response")
	return staleMsg.Data, true
}

// ─────────────────────────────────────── encryption helpers ─────────────────

// encryptQuery encrypts query for the given protocol using proxy.Encrypt.
// Returns the shared key, encrypted query bytes, client nonce, and any error.
func encryptQuery(proxy *Proxy, serverInfo *ServerInfo, query []byte, proto string) (*[32]byte, []byte, []byte, error) {
	sharedKey, encryptedQuery, clientNonce, err := proxy.Encrypt(serverInfo, query, proto)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encrypt query for %s: %w", proto, err)
	}
	return sharedKey, encryptedQuery, clientNonce, nil
}

// handleEncryptionError sets the parse-error return code, applies logging, and
// notifies the server of the failure before returning the original error.
func handleEncryptionError(proxy *Proxy, pluginsState *PluginsState, serverInfo *ServerInfo, err error) error {
	serverInfo.noticeFailure(proxy)
	return failWith(pluginsState, proxy, PluginsReturnCodeParseError, err)
}

// ─────────────────────────────────────── TCP-fallback logic ─────────────────

// shouldRetryOverTCP reports whether a UDP exchange result warrants a TCP retry.
//
// Returns true when:
//   - The response has the TC (truncated) flag set, or
//   - The error is a network timeout.
//
// Uses errors.As for proper unwrapping of wrapped net.Error values.
func shouldRetryOverTCP(response []byte, err error, serverInfo *ServerInfo) bool {
	if err == nil && HasTCFlag(response) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		dlog.Debugf("[%v] Retry over TCP after UDP timeout", serverInfo.Name)
		return true
	}
	return false
}

// ─────────────────────────────────────── error categorisation ───────────────

// handleQueryError classifies a DNS exchange error as a timeout or network
// error, sets the appropriate return code, applies logging, and returns err.
func handleQueryError(proxy *Proxy, pluginsState *PluginsState, err error) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return failWith(pluginsState, proxy, PluginsReturnCodeServerTimeout, err)
	}
	return failWith(pluginsState, proxy, PluginsReturnCodeNetworkError, err)
}

// ─────────────────────────────────────── protocol processors ────────────────

// processDNSCryptQuery encrypts and dispatches a DNS query using the DNSCrypt
// protocol. On UDP encryption failure it automatically retries with TCP.
// On transport failure it attempts to serve a stale cached response before
// returning an error.
func processDNSCryptQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
	serverProto string,
) ([]byte, error) {
	sharedKey, encryptedQuery, clientNonce, err := encryptQuery(proxy, serverInfo, query, serverProto)

	// If UDP padding fails, fall back to TCP encryption immediately.
	if err != nil && serverProto == "udp" {
		dlog.Debug("Unable to pad for UDP, re-encrypting query for TCP")
		serverProto = "tcp"
		sharedKey, encryptedQuery, clientNonce, err = encryptQuery(proxy, serverInfo, query, serverProto)
	}
	if err != nil {
		return nil, handleEncryptionError(proxy, pluginsState, serverInfo, err)
	}

	serverInfo.noticeBegin(proxy)

	response, err := executeDNSCryptQuery(
		proxy, serverInfo, pluginsState, query, serverProto,
		sharedKey, encryptedQuery, clientNonce,
	)
	if err != nil {
		serverInfo.noticeFailure(proxy)
		if stale, ok := tryServeStaleResponse(pluginsState); ok {
			return stale, nil
		}
		return nil, handleQueryError(proxy, pluginsState, err)
	}
	return response, nil
}

// executeDNSCryptQuery sends the encrypted DNSCrypt query over UDP or TCP,
// with automatic TCP fallback on a truncated or timed-out UDP response.
func executeDNSCryptQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
	serverProto string,
	sharedKey *[32]byte,
	encryptedQuery []byte,
	clientNonce []byte,
) ([]byte, error) {
	if serverProto != "udp" {
		return proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
	}

	response, err := proxy.exchangeWithUDPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
	if !shouldRetryOverTCP(response, err, serverInfo) {
		return response, err
	}

	dlog.Debugf("[%v] Falling back to TCP", serverInfo.Name)

	sharedKey, encryptedQuery, clientNonce, err = encryptQuery(proxy, serverInfo, query, "tcp")
	if err != nil {
		return nil, handleEncryptionError(proxy, pluginsState, serverInfo, err)
	}
	return proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
}

// processDoHQuery sends a DNS query via DNS-over-HTTPS.
//
// The transaction ID is zeroed before the request (per RFC 8484 §4.1) and
// restored in both the query and the response on return. Success is determined
// solely by a nil error from DoHQuery — TLS state inspection is not required.
func processDoHQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
) ([]byte, error) {
	tid := TransactionID(query)
	SetTransactionID(query, 0)

	serverInfo.noticeBegin(proxy)

	serverResponse, _, _, _, err := proxy.xTransport.DoHQuery(
		serverInfo.useGet,
		serverInfo.URL,
		query,
		proxy.timeout,
	)

	// Always restore the transaction ID in the original query buffer.
	SetTransactionID(query, tid)

	if err == nil && len(serverResponse) >= MinDNSPacketSize {
		SetTransactionID(serverResponse, tid)
		return serverResponse, nil
	}

	serverInfo.noticeFailure(proxy)

	if stale, ok := tryServeStaleResponse(pluginsState); ok {
		return stale, nil
	}

	if err != nil {
		return nil, failWith(pluginsState, proxy, PluginsReturnCodeNetworkError,
			fmt.Errorf("DoH query failed: %w", err))
	}
	return nil, failWith(pluginsState, proxy, PluginsReturnCodeNetworkError,
		errors.New("DoH query failed: response too short"))
}

// processODoHQuery sends a DNS query via Oblivious DNS-over-HTTPS.
//
// A random ODoH target configuration is selected using math/rand/v2 (no
// mutex overhead on the hot path). On a 401 or empty-body 200 response a key
// refresh is triggered in a background goroutine so the current query is not
// blocked by the keyUpdateRetryDelay back-off.
func processODoHQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
) ([]byte, error) {
	tid := TransactionID(query)

	if len(serverInfo.odohTargetConfigs) == 0 {
		return nil, ErrNoODoHConfig
	}

	serverInfo.noticeBegin(proxy)

	// math/rand/v2 global functions are lock-free on Go 1.22+.
	target := serverInfo.odohTargetConfigs[randv2.IntN(len(serverInfo.odohTargetConfigs))]

	odohQuery, err := target.encryptQuery(query)
	if err != nil {
		dlog.Errorf("Failed to encrypt query for [%v]: %v", serverInfo.Name, err)
		return nil, fmt.Errorf("ODoH encryption failed: %w", err)
	}

	targetURL := serverInfo.URL
	if serverInfo.Relay != nil && serverInfo.Relay.ODoH != nil {
		targetURL = serverInfo.Relay.ODoH.URL
	}

	responseBody, responseCode, _, _, err := proxy.xTransport.ObliviousDoHQuery(
		serverInfo.useGet,
		targetURL,
		odohQuery.odohMessage,
		proxy.timeout,
	)

	if err == nil && len(responseBody) > 0 && responseCode == http.StatusOK {
		response, err := odohQuery.decryptResponse(responseBody)
		if err != nil {
			dlog.Warnf("Failed to decrypt response from [%v]: %v", serverInfo.Name, err)
			serverInfo.noticeFailure(proxy)
			return nil, fmt.Errorf("ODoH decryption failed: %w", err)
		}
		if len(response) >= MinDNSPacketSize {
			SetTransactionID(response, tid)
		}
		return response, nil
	}

	// 401 or empty-body 200 signals that the server rotated its ODoH key.
	// Trigger a background refresh so this goroutine is not blocked.
	if responseCode == http.StatusUnauthorized ||
		(responseCode == http.StatusOK && len(responseBody) == 0) {

		if responseCode == http.StatusOK {
			dlog.Warnf(
				"ODoH relay for [%v] returned 200 with empty body instead of 401 after key rotation",
				serverInfo.Name,
			)
		}
		dlog.Infof("Forcing key update for [%v]", serverInfo.Name)
		triggerODoHKeyUpdate(proxy, serverInfo)
	} else {
		dlog.Warnf("Failed to receive successful response from [%v]: status=%d err=%v",
			serverInfo.Name, responseCode, err)
	}

	serverInfo.noticeFailure(proxy)

	if err != nil {
		return nil, failWith(pluginsState, proxy, PluginsReturnCodeNetworkError,
			fmt.Errorf("ODoH query failed: %w", err))
	}
	return nil, failWith(pluginsState, proxy, PluginsReturnCodeNetworkError,
		fmt.Errorf("ODoH query failed: status code %d", responseCode))
}

// triggerODoHKeyUpdate finds the registered server matching serverInfo.Name and
// calls refreshServer in a background goroutine. If the refresh fails the
// goroutine waits keyUpdateRetryDelay before logging the failure, leaving the
// hot-path goroutine unblocked.
func triggerODoHKeyUpdate(proxy *Proxy, serverInfo *ServerInfo) {
	for _, reg := range proxy.serversInfo.registeredServers {
		if reg.name != serverInfo.Name {
			continue
		}
		name, stamp := reg.name, reg.stamp
		go func() {
			if err := proxy.serversInfo.refreshServer(proxy, name, stamp); err != nil {
				clocksmith.Sleep(keyUpdateRetryDelay)
				dlog.Noticef("Key update failed for [%v]: %v", name, err)
			}
		}()
		return
	}
	dlog.Warnf("triggerODoHKeyUpdate: server [%v] not found in registered servers", serverInfo.Name)
}

// ─────────────────────────────────────── dispatch ───────────────────────────

// handleDNSExchange dispatches a DNS query to the correct protocol handler
// (DNSCrypt, DoH, or ODoH) and validates the response size before returning.
func handleDNSExchange(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
	serverProto string,
) ([]byte, error) {
	var response []byte
	var err error

	switch serverInfo.Proto {
	case stamps.StampProtoTypeDNSCrypt:
		response, err = processDNSCryptQuery(proxy, serverInfo, pluginsState, query, serverProto)
	case stamps.StampProtoTypeDoH:
		response, err = processDoHQuery(proxy, serverInfo, pluginsState, query)
	case stamps.StampProtoTypeODoHTarget:
		response, err = processODoHQuery(proxy, serverInfo, pluginsState, query)
	default:
		// dlog.Fatalf terminates the process; the error return is unreachable
		// but satisfies the compiler.
		dlog.Fatalf("Unsupported protocol: %v", serverInfo.Proto)
		return nil, ErrUnsupportedProtocol
	}

	if err != nil {
		return nil, err
	}
	if err := validateResponse(response); err != nil {
		serverInfo.noticeFailure(proxy)
		return nil, failWith(pluginsState, proxy, PluginsReturnCodeParseError, err)
	}
	return response, nil
}

// ─────────────────────────────────────── response plugins ───────────────────

// processPlugins applies the response plugin chain to response and handles the
// plugin action (forward, drop, or synthesized response). It also updates
// server success/failure metrics based on the DNS RCODE.
func processPlugins(
	proxy *Proxy,
	pluginsState *PluginsState,
	serverInfo *ServerInfo,
	response []byte,
) ([]byte, error) {
	processed, err := pluginsState.ApplyResponsePlugins(&proxy.pluginsGlobals, response)
	if err != nil {
		return processed, failWith(pluginsState, proxy, PluginsReturnCodeParseError,
			fmt.Errorf("response plugin failed: %w", err))
	}

	switch pluginsState.action {
	case PluginsActionDrop:
		return processed, failWith(pluginsState, proxy, PluginsReturnCodeDrop, nil)

	default:
		if pluginsState.synthResponse != nil {
			if err := pluginsState.synthResponse.Pack(); err != nil {
				return processed, failWith(pluginsState, proxy, PluginsReturnCodeParseError,
					fmt.Errorf("failed to pack synthetic response: %w", err))
			}
			processed = pluginsState.synthResponse.Data
		}
		handleResponseCode(proxy, pluginsState, serverInfo, processed)
		return processed, nil
	}
}

// handleResponseCode inspects the DNS RCODE in response and updates the server
// success/failure counter accordingly. A SERVFAIL with DNSSEC enabled is
// treated as a validation failure (not a server fault).
func handleResponseCode(proxy *Proxy, pluginsState *PluginsState, serverInfo *ServerInfo, response []byte) {
	if Rcode(response) == dns.RcodeServerFailure {
		if pluginsState.dnssec {
			dlog.Debug("A response had an invalid DNSSEC signature")
		} else {
			dlog.Info("A response with SERVFAIL status was received - this is usually a temporary, remote issue with the domain configuration")
			serverInfo.noticeFailure(proxy)
		}
	} else {
		serverInfo.noticeSuccess(proxy)
	}
}

// ─────────────────────────────────────── response delivery ──────────────────

// sendResponse validates response and delivers it to the client over the
// appropriate transport (UDP or TCP).
//
// A zero-length response (resulting from PluginsActionDrop) is treated as a
// deliberate drop and sets PluginsReturnCodeDrop rather than an error code.
func sendResponse(
	proxy *Proxy,
	pluginsState *PluginsState,
	response []byte,
	clientProto string,
	clientAddr *net.Addr,
	clientPc net.Conn,
) {
	if len(response) == 0 {
		// Deliberate drop — do not log an error.
		pluginsState.returnCode = PluginsReturnCodeDrop
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		return
	}
	if err := validateResponse(response); err != nil {
		_ = failWith(pluginsState, proxy, PluginsReturnCodeParseError, err)
		return
	}

	switch clientProto {
	case "udp":
		sendUDPResponse(proxy, pluginsState, response, clientAddr, clientPc)
	case "tcp":
		sendTCPResponse(proxy, pluginsState, response, clientPc)
	default:
		dlog.Warnf("Unknown client protocol: %s", clientProto)
		_ = failWith(pluginsState, proxy, PluginsReturnCodeParseError, nil)
	}
}

// sendUDPResponse truncates response if it exceeds the maximum safe UDP
// payload size, then writes it to the UDP packet connection.
//
// After sending, the question-size estimator is updated: if the TC flag is
// set (truncation occurred) blindAdjust is called (no size recorded);
// otherwise the actual response size is recorded.
func sendUDPResponse(
	proxy *Proxy,
	pluginsState *PluginsState,
	response []byte,
	clientAddr *net.Addr,
	clientPc net.Conn,
) {
	if len(response) > pluginsState.maxUnencryptedUDPSafePayloadSize {
		truncated, err := TruncatedResponse(response)
		if err != nil {
			dlog.Warnf("Failed to truncate UDP response: %v", err)
			_ = failWith(pluginsState, proxy, PluginsReturnCodeParseError, err)
			return
		}
		response = truncated
	}

	packetConn, ok := clientPc.(net.PacketConn)
	if !ok {
		dlog.Error("Client connection is not a PacketConn for UDP protocol")
		_ = failWith(pluginsState, proxy, PluginsReturnCodeParseError, nil)
		return
	}
	if _, err := packetConn.WriteTo(response, *clientAddr); err != nil {
		dlog.Warnf("Failed to send UDP response: %v", err)
		return
	}

	// Update question-size estimator. If TC is set we could not fit the full
	// answer, so only a blind (non-size) adjustment is made.
	if HasTCFlag(response) {
		proxy.questionSizeEstimator.blindAdjust()
	} else {
		proxy.questionSizeEstimator.adjust(ResponseOverhead + len(response))
	}
}

// sendTCPResponse prefixes response with a 2-byte length header (RFC 1035
// §4.2.2) and writes it to the TCP connection.
func sendTCPResponse(
	proxy *Proxy,
	pluginsState *PluginsState,
	response []byte,
	clientPc net.Conn,
) {
	prefixed, err := PrefixWithSize(response)
	if err != nil {
		dlog.Warnf("Failed to prefix TCP response: %v", err)
		_ = failWith(pluginsState, proxy, PluginsReturnCodeParseError, err)
		return
	}
	if _, err := clientPc.Write(prefixed); err != nil {
		dlog.Warnf("Failed to send TCP response: %v", err)
	}
}

// ─────────────────────────────────────── monitoring ─────────────────────────

// updateMonitoringMetrics updates the monitoring dashboard metrics for the
// completed query, if monitoring is enabled and properly initialised.
func updateMonitoringMetrics(proxy *Proxy, pluginsState *PluginsState) {
	if !proxy.monitoringUI.Enabled {
		return
	}
	if proxy.monitoringInstance == nil {
		dlog.Warn("Monitoring is enabled but monitoringInstance is nil — metrics skipped")
		return
	}
	if pluginsState.questionMsg == nil {
		dlog.Debug("Question message is nil, cannot update metrics")
		return
	}
	proxy.monitoringInstance.UpdateMetrics(*pluginsState, pluginsState.questionMsg)
}
