// Package main implements DNS query processing for dnscrypt-proxy.
package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"

	randv2 "math/rand/v2"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
	stamps "github.com/jedisct1/go-dnsstamps"
)

// ─────────────────────────────────────── constants ──────────────────────────

// transportProto is a defined type for the DNS transport layer string constants.
// Using a defined type (not a type alias) gives compile-time enforcement:
// arbitrary strings cannot be passed where a transportProto is expected.
// Use protoUDP / protoTCP instead of bare string literals.
type transportProto string

const (
	protoUDP transportProto = "udp"
	protoTCP transportProto = "tcp"

	// keyUpdateRetryDelay is the back-off period before retrying an ODoH key
	// refresh after a 401 or empty-body 200 response.
	keyUpdateRetryDelay = 10 * time.Second
)

// ─────────────────────────────────────── sentinel errors ────────────────────

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

// packetBounds pairs the two sentinel errors for a size-range validator.
// A single validate / validateBool method pair replaces the three formerly
// duplicated switch bodies, keeping bounds-check logic in exactly one place.
//
// Both fields are assigned at package init and then read-only — safe for
// concurrent use without any synchronisation.
type packetBounds struct {
	tooSmall error // returned when len(data) < MinDNSPacketSize
	tooLarge error // returned when len(data) > MaxDNSPacketSize
}

// validate returns a wrapped sentinel error when data length is out of range,
// nil otherwise.  The wrapping includes byte counts for diagnostic logging.
func (b packetBounds) validate(data []byte) error {
	n := len(data)
	switch {
	case n < MinDNSPacketSize:
		return fmt.Errorf("%w: got %d bytes, minimum %d", b.tooSmall, n, MinDNSPacketSize)
	case n > MaxDNSPacketSize:
		return fmt.Errorf("%w: got %d bytes, maximum %d", b.tooLarge, n, MaxDNSPacketSize)
	default:
		return nil
	}
}

// validateBool is a zero-allocation fast path used on the hot forwarding path
// (proxy.go) where only a boolean gate is required.
func (b packetBounds) validateBool(data []byte) bool {
	n := len(data)
	return n >= MinDNSPacketSize && n <= MaxDNSPacketSize
}

// Package-level bound sets, constructed once at init time.
var (
	queryBounds    = packetBounds{tooSmall: ErrQueryTooSmall, tooLarge: ErrQueryTooLarge}
	responseBounds = packetBounds{tooSmall: ErrResponseTooSmall, tooLarge: ErrResponseTooLarge}
)

// validateQuery returns true when query length is within the valid DNS packet
// range.  Called directly by proxy.go on the hot path; uses validateBool to
// avoid allocating an error value.
func validateQuery(query []byte) bool { return queryBounds.validateBool(query) }

// validateQueryWithError validates the length of a raw DNS query.
// Returns a wrapped sentinel error with byte counts for callers that log details.
func validateQueryWithError(query []byte) error { return queryBounds.validate(query) }

// validateResponse validates the length of a raw DNS response.
// Returns a wrapped sentinel error with byte counts.
func validateResponse(response []byte) error { return responseBounds.validate(response) }

// ─────────────────────────────────────── plugin helpers ─────────────────────

// failWith sets pluginsState.returnCode, applies logging plugins, and returns
// the provided error.  Consolidates the repeated:
//
//	pluginsState.returnCode = X
//	pluginsState.ApplyLoggingPlugins(...)
//	return ..., err
func failWith(pluginsState *PluginsState, proxy *Proxy, code PluginsReturnCode, err error) error {
	pluginsState.returnCode = code
	pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
	return err
}

// handleSynthesizedResponse packs a synthesized DNS message and returns its
// wire-format bytes.  Sets PluginsReturnCodeParseError on pack failure.
// Signature matches the 2-argument call site in proxy.go.
func handleSynthesizedResponse(pluginsState *PluginsState, synth *dns.Msg) ([]byte, error) {
	if synth == nil {
		return nil, errors.New("synthesized message is nil")
	}
	if err := synth.Pack(); err != nil {
		pluginsState.returnCode = PluginsReturnCodeParseError
		return nil, fmt.Errorf("failed to pack synthesized response: %w", err)
	}
	return synth.Data, nil
}

// tryServeStaleResponse returns the packed bytes of a stale cached response
// stored in pluginsState.sessionData["stale"], if present and valid.
// Returns (nil, false) if no stale entry exists or packing fails.
//
// The two-step type assertion (any → *dns.Msg) uses the comma-ok form so a
// wrong concrete type produces a warning rather than a panic.
func tryServeStaleResponse(pluginsState *PluginsState) ([]byte, bool) {
	stale, ok := pluginsState.sessionData["stale"]
	if !ok {
		return nil, false
	}
	staleMsg, ok := stale.(*dns.Msg) // stale is stored as any; asserting *dns.Msg
	if !ok {
		dlog.Warnf("Invalid stale response type in session data: got %T, want *dns.Msg", stale)
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

// encryptForProto encrypts query for the given protocol string using
// proxy.Encrypt.  proto should be "udp" or "tcp".
//
// Named encryptForProto (not encryptQuery) to distinguish it from the
// inlined encrypt calls inside executeDNSCryptQuery.
func encryptForProto(
	proxy *Proxy,
	serverInfo *ServerInfo,
	query []byte,
	proto transportProto,
) (*[32]byte, []byte, []byte, error) {
	sharedKey, encryptedQuery, clientNonce, err := proxy.Encrypt(serverInfo, query, string(proto))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encrypt query for %s: %w", string(proto), err)
	}
	return sharedKey, encryptedQuery, clientNonce, nil
}

// handleEncryptionError sets the parse-error return code, notifies the server
// of failure, and returns the original error.
func handleEncryptionError(
	proxy *Proxy,
	pluginsState *PluginsState,
	serverInfo *ServerInfo,
	err error,
) error {
	serverInfo.noticeFailure(proxy)
	return failWith(pluginsState, proxy, PluginsReturnCodeParseError, err)
}

// ─────────────────────────────────────── TCP-fallback logic ─────────────────

// shouldRetryOverTCP reports whether a UDP exchange result warrants a TCP retry.
// Returns true when:
//   - err is nil and the TC (truncation) flag is set in response, or
//   - err unwraps to a net.Error with Timeout() == true.
//
// Uses errors.AsType[net.Error] (Go 1.26) — lock-free, zero-allocation
// unwrapping; replaces the older var+errors.As two-step pattern.
func shouldRetryOverTCP(response []byte, err error, serverInfo *ServerInfo) bool {
	if err == nil && HasTCFlag(response) {
		return true
	}
	// errors.AsType[net.Error] is the Go 1.26 generic form of errors.As;
	// the compiler emits a direct interface comparison with no heap escape.
	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		dlog.Debugf("[%v] Retry over TCP after UDP timeout", serverInfo.Name)
		return true
	}
	return false
}

// ─────────────────────────────────────── error categorisation ───────────────

// handleQueryError classifies a DNS exchange error as a timeout or network
// error, sets the appropriate return code, applies logging, and returns err.
//
// Uses errors.AsType[net.Error] (Go 1.26) — lock-free, zero-allocation
// unwrapping; replaces the older var+errors.As two-step pattern.
func handleQueryError(proxy *Proxy, pluginsState *PluginsState, err error) error {
	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		return failWith(pluginsState, proxy, PluginsReturnCodeServerTimeout, err)
	}
	return failWith(pluginsState, proxy, PluginsReturnCodeNetworkError, err)
}

// ─────────────────────────────────────── protocol processors ────────────────

// processDNSCryptQuery encrypts and dispatches a DNS query using the DNSCrypt
// protocol.  On UDP padding failure it retries with TCP encryption immediately.
// On transport failure it attempts to serve a stale cached response before
// returning an error.
func processDNSCryptQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
	serverProto transportProto,
) ([]byte, error) {
	sharedKey, encryptedQuery, clientNonce, err := encryptForProto(proxy, serverInfo, query, serverProto)

	// If UDP padding fails, fall back to TCP encryption immediately.
	if err != nil && serverProto == protoUDP {
		dlog.Debug("Unable to pad for UDP, re-encrypting query for TCP")
		serverProto = protoTCP
		sharedKey, encryptedQuery, clientNonce, err = encryptForProto(proxy, serverInfo, query, serverProto)
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
//
// The two inner proxy.Encrypt calls are inlined here (rather than calling
// encryptForProto) to avoid an extra stack frame on the hot TCP-retry path.
func executeDNSCryptQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
	serverProto transportProto,
	sharedKey *[32]byte,
	encryptedQuery []byte,
	clientNonce []byte,
) ([]byte, error) {
	// Fast path: TCP — no truncation possible, send immediately.
	if serverProto != protoUDP {
		return proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
	}

	// UDP path: attempt exchange, then check for truncation / timeout.
	response, err := proxy.exchangeWithUDPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
	if !shouldRetryOverTCP(response, err, serverInfo) {
		return response, err
	}

	dlog.Debugf("[%v] Falling back to TCP", serverInfo.Name)

	// Re-encrypt inline for TCP — avoids encryptForProto call overhead on retry.
	sharedKey, encryptedQuery, clientNonce, err = proxy.Encrypt(serverInfo, query, string(protoTCP))
	if err != nil {
		return nil, handleEncryptionError(proxy, pluginsState, serverInfo,
			fmt.Errorf("failed to encrypt query for tcp: %w", err))
	}
	return proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)
}

// processDoHQuery sends a DNS query via DNS-over-HTTPS.
//
// The transaction ID is zeroed before the request (per RFC 8484 §4.1).
// A copy of the query buffer is used for the outgoing request so the caller's
// slice is never mutated — this prevents subtle bugs if the caller retains a
// reference for logging, retries, or plugin use.
//
// Success is defined as a nil error from DoHQuery.  A nil TLS state (plain-HTTP
// transport, e.g. a localhost test relay) is explicitly accepted — only an
// incomplete TLS handshake on a non-nil TLS state is treated as failure.
//
// The failure path is extracted into handleDoHFailure so that the success path
// is a straight-line sequence of instructions with no embedded branches; this
// aids CPU branch-prediction on the common case.
func processDoHQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
) ([]byte, error) {
	// Work on a copy so the caller's query buffer is never mutated.
	q := append([]byte(nil), query...)
	tid := TransactionID(q)
	SetTransactionID(q, 0)

	serverInfo.noticeBegin(proxy)

	serverResponse, _, tls, _, err := proxy.xTransport.DoHQuery(
		serverInfo.useGet,
		serverInfo.URL,
		q,
		proxy.timeout,
	)

	// Accept: no error AND (plain-HTTP with nil tls, OR TLS handshake complete).
	if err == nil && (tls == nil || tls.HandshakeComplete) {
		if len(serverResponse) >= MinDNSPacketSize {
			SetTransactionID(serverResponse, tid)
		}
		return serverResponse, nil
	}

	// Failure path: out-of-line to keep the success path branch-predictor friendly.
	return handleDoHFailure(proxy, pluginsState, serverInfo, err)
}

// handleDoHFailure handles the error branch of processDoHQuery.
// It is intentionally out-of-line so the success path in processDoHQuery
// remains a straight-line sequence with no embedded branches.
func handleDoHFailure(
	proxy *Proxy,
	pluginsState *PluginsState,
	serverInfo *ServerInfo,
	err error,
) ([]byte, error) {
	serverInfo.noticeFailure(proxy)

	if stale, ok := tryServeStaleResponse(pluginsState); ok {
		return stale, nil
	}

	if err != nil {
		return nil, handleQueryError(proxy, pluginsState,
			fmt.Errorf("DoH query to [%v] (%v) failed: %w", serverInfo.Name, serverInfo.URL, err))
	}
	return nil, failWith(pluginsState, proxy, PluginsReturnCodeNetworkError,
		fmt.Errorf("DoH query to [%v] (%v) failed: incomplete TLS handshake", serverInfo.Name, serverInfo.URL))
}

// processODoHQuery sends a DNS query via Oblivious DNS-over-HTTPS.
//
// A random ODoH target configuration is selected using math/rand/v2 (no mutex
// overhead, no seeding required — Go 1.22+).  On a 401 or empty-body 200
// response a key refresh is triggered in a background goroutine so the current
// query goroutine is never blocked waiting for key material.
func processODoHQuery(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
) ([]byte, error) {
	if len(serverInfo.odohTargetConfigs) == 0 {
		return nil, ErrNoODoHConfig
	}

	tid := TransactionID(query)
	serverInfo.noticeBegin(proxy)

	// math/rand/v2 IntN is lock-free on Go 1.22+; no mutex, no global seed.
	target := serverInfo.odohTargetConfigs[randv2.IntN(len(serverInfo.odohTargetConfigs))]

	odohQuery, err := target.encryptQuery(query)
	if err != nil {
		dlog.Errorf("Failed to encrypt query for [%v]: %v", serverInfo.Name, err)
		return nil, fmt.Errorf("ODoH encryption failed: %w", err)
	}

	// Prefer the relay URL when an ODoH relay is configured.
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

	// ── Happy path ──────────────────────────────────────────────────────────
	if err == nil && len(responseBody) > 0 && responseCode == http.StatusOK {
		response, err := odohQuery.decryptResponse(responseBody)
		if err != nil {
			dlog.Warnf("Failed to decrypt ODoH response from [%v] (url=%v): %v", serverInfo.Name, targetURL, err)
			serverInfo.noticeFailure(proxy)
			return nil, fmt.Errorf("ODoH decryption failed for [%v]: %w", serverInfo.Name, err)
		}
		if len(response) >= MinDNSPacketSize {
			SetTransactionID(response, tid)
		}
		return response, nil
	}

	// ── Key-rotation signals (401 or empty 200) ──────────────────────────────
	// Trigger background refresh; never block the query goroutine on key I/O.
	if responseCode == http.StatusUnauthorized ||
		(responseCode == http.StatusOK && len(responseBody) == 0) {
		if responseCode == http.StatusOK {
			dlog.Warnf(
				"ODoH relay for [%v] (url=%v) returned 200 with empty body instead of 401 after key rotation",
				serverInfo.Name, targetURL,
			)
		}
		dlog.Infof("Forcing key update for [%v]", serverInfo.Name)
		triggerODoHKeyUpdate(proxy, serverInfo)
	} else {
		dlog.Warnf("Failed to receive successful ODoH response from [%v] (url=%v): status=%d err=%v",
			serverInfo.Name, targetURL, responseCode, err)
	}

	// ── Error path ───────────────────────────────────────────────────────────
	serverInfo.noticeFailure(proxy)
	if err != nil {
		return nil, handleQueryError(proxy, pluginsState,
			fmt.Errorf("ODoH query to [%v] (url=%v) failed: %w", serverInfo.Name, targetURL, err))
	}
	return nil, failWith(pluginsState, proxy, PluginsReturnCodeNetworkError,
		fmt.Errorf("ODoH query to [%v] (url=%v) failed: status code %d", serverInfo.Name, targetURL, responseCode))
}

// triggerODoHKeyUpdate finds the registered server matching serverInfo.Name and
// calls refreshServer in a fire-and-forget background goroutine.
//
// Stampede protection: if a refresh is already in progress for the given
// server (odohKeyUpdateInProgress is true), a new goroutine is not spawned.
// This prevents many concurrent query goroutines from all triggering key
// refreshes simultaneously on a 401 response.
//
// The goroutine recovers from any panic so a transient bug cannot crash the
// entire proxy.
//
// The retry delay is implemented as a context-aware select so the goroutine
// exits promptly when the proxy shuts down (proxy.shutdownCtx is cancelled).
//
// slices.Values (Go 1.23 range-over-func) drives the server-search loop,
// giving clean early-break semantics without index arithmetic.
//
// If no matching server is found a warning is emitted; the caller is never
// blocked in either case.
func triggerODoHKeyUpdate(proxy *Proxy, serverInfo *ServerInfo) {
	// Stampede gate: only one refresh goroutine per server at a time.
	if !serverInfo.odohKeyUpdateInProgress.CompareAndSwap(false, true) {
		dlog.Debugf("ODoH key update already in progress for [%v], skipping duplicate trigger", serverInfo.Name)
		return
	}

	// slices.Values returns an iter.Seq[T] — range-over-func, Go 1.23+.
	for reg := range slices.Values(proxy.serversInfo.registeredServers) {
		if reg.name != serverInfo.Name {
			continue
		}

		// Capture immutable copies before the goroutine launch so that
		// future loop iterations (if any) cannot race with the goroutine.
		name, stamp := reg.name, reg.stamp
		shutdownCtx := proxy.shutdownCtx

		// Fire-and-forget: the key refresh runs in the background so the
		// calling query goroutine is never blocked on network I/O.
		go func() {
			retryTimer := time.NewTimer(0)
			if !retryTimer.Stop() {
				select {
				case <-retryTimer.C:
				default:
				}
			}
			defer retryTimer.Stop()

			// Panic recovery: a bug in refreshServer must not crash the process.
			defer func() {
				if r := recover(); r != nil {
					dlog.Errorf("Panic during ODoH key update for [%v]: %v", name, r)
				}
			}()
			// Always clear the in-progress flag when the goroutine exits.
			defer serverInfo.odohKeyUpdateInProgress.Store(false)

			if err := proxy.serversInfo.refreshServer(proxy, name, stamp); err != nil {
				// Context-aware delay: exit early if the proxy is shutting down.
				resetRetryTimer(retryTimer, keyUpdateRetryDelay)
				select {
				case <-shutdownCtx.Done():
					dlog.Debugf("ODoH key update delay cancelled for [%v] (proxy shutting down)", name)
					return
				case <-retryTimer.C:
				}
				dlog.Noticef("Key update failed for [%v]: %v", name, err)
			}
		}()
		return
	}

	// Server not found — release the gate so a future rename/reload can retry.
	serverInfo.odohKeyUpdateInProgress.Store(false)
	dlog.Warnf("triggerODoHKeyUpdate: server [%v] not found in registered servers", serverInfo.Name)
}

func resetRetryTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

// ─────────────────────────────────────── dispatch ───────────────────────────

// handleDNSExchange dispatches a DNS query to the correct protocol handler
// (DNSCrypt, DoH, or ODoH) and validates the response size before returning.
//
// The default branch calls dlog.Fatalf which terminates the process; the
// subsequent return is unreachable but satisfies the compiler's return analysis.
func handleDNSExchange(
	proxy *Proxy,
	serverInfo *ServerInfo,
	pluginsState *PluginsState,
	query []byte,
	serverProto transportProto,
) ([]byte, error) {
	// Use explicit typed variables instead of := multi-assign so that the
	// compiler can prove response is only written once per branch.
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
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedProtocol, serverInfo.Proto)
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

// processPlugins applies the response plugin chain and handles the resulting
// action (forward, drop, or synthesized response).  It also updates server
// success/failure metrics based on the DNS RCODE.
//
// Rewritten with guard-clause early returns (no switch statement) so the
// common forward path has no branches after the plugin chain completes — the
// CPU branch predictor sees a straight line in the typical case.
//
// The query parameter is accepted for API compatibility with proxy.go
// (5-argument call site) but is not used in this function body.
func processPlugins(
	proxy *Proxy,
	pluginsState *PluginsState,
	query []byte, //nolint:revive // kept for caller API compatibility with proxy.go
	serverInfo *ServerInfo,
	response []byte,
) ([]byte, error) {
	_ = query // intentionally unused; see godoc above

	processed, err := pluginsState.ApplyResponsePlugins(&proxy.pluginsGlobals, response)
	if err != nil {
		return processed, failWith(pluginsState, proxy, PluginsReturnCodeParseError,
			fmt.Errorf("response plugin failed: %w", err))
	}

	// ── Drop action: guard-clause early return ───────────────────────────────
	if pluginsState.action == PluginsActionDrop {
		return processed, failWith(pluginsState, proxy, PluginsReturnCodeDrop, nil)
	}

	// ── Synthesized response: pack and replace processed bytes ───────────────
	if pluginsState.synthResponse != nil {
		packed, err := handleSynthesizedResponse(pluginsState, pluginsState.synthResponse)
		if err != nil {
			return processed, failWith(pluginsState, proxy, PluginsReturnCodeParseError, err)
		}
		processed = packed
	}

	// ── Forward path: update success/failure counters ────────────────────────
	handleResponseCode(proxy, pluginsState, serverInfo, processed)
	return processed, nil
}

// handleResponseCode inspects the DNS RCODE in response and updates the server
// success/failure counter accordingly.  A SERVFAIL with DNSSEC enabled is
// treated as a DNSSEC validation failure (not a server fault).
func handleResponseCode(
	proxy *Proxy,
	pluginsState *PluginsState,
	serverInfo *ServerInfo,
	response []byte,
) {
	if Rcode(response) != dns.RcodeServerFailure {
		serverInfo.noticeSuccess(proxy)
		return
	}
	// SERVFAIL branch — distinguish DNSSEC validation from server error.
	if pluginsState.dnssec {
		dlog.Debug("A response had an invalid DNSSEC signature")
	} else {
		dlog.Info("A response with SERVFAIL status was received - this is usually a temporary, remote issue with the domain configuration")
		serverInfo.noticeFailure(proxy)
	}
}

// ─────────────────────────────────────── response delivery ──────────────────

// sendResponse delivers a DNS response to the client over UDP or TCP.
//
// A zero-length response (produced by PluginsActionDrop) is treated as a
// deliberate drop and sets PluginsReturnCodeDrop without logging an error.
// All other responses are assumed valid — validateResponse is intentionally
// omitted here because handleDNSExchange already validated every non-synthetic
// response before returning it to the call chain.
func sendResponse(
	proxy *Proxy,
	pluginsState *PluginsState,
	response []byte,
	clientProto transportProto,
	clientAddr *net.Addr,
	clientPc net.Conn,
) {
	// Guard-clause: zero-length means deliberate drop — do not log as error.
	if len(response) == 0 {
		pluginsState.returnCode = PluginsReturnCodeDrop
		pluginsState.ApplyLoggingPlugins(&proxy.pluginsGlobals)
		return
	}

	switch clientProto {
	case protoUDP:
		sendUDPResponse(proxy, pluginsState, response, clientAddr, clientPc)
	case protoTCP:
		sendTCPResponse(proxy, pluginsState, response, clientPc)
	default:
		dlog.Warnf("Unknown client protocol: %s", clientProto)
		_ = failWith(pluginsState, proxy, PluginsReturnCodeParseError, nil)
	}
}

// sendUDPResponse truncates response if it exceeds the maximum safe UDP payload
// size, then writes it to the UDP packet connection.
//
// The net.PacketConn assertion is performed once at the top of the function
// body — before any conditional work — so the interface dispatch is paid only
// once regardless of the truncation branch taken.
//
// After sending, the question-size estimator is updated: if the TC flag is set
// (truncation occurred), blindAdjust is called; otherwise the actual response
// size is recorded using the min builtin (Go 1.21+) to clamp overhead.
func sendUDPResponse(
	proxy *Proxy,
	pluginsState *PluginsState,
	response []byte,
	clientAddr *net.Addr,
	clientPc net.Conn,
) {
	// Guard against nil clientAddr to prevent a panic on the WriteTo deref below.
	if clientAddr == nil {
		dlog.Errorf("sendUDPResponse: clientAddr is nil — cannot send UDP response, dropping")
		_ = failWith(pluginsState, proxy, PluginsReturnCodeNetworkError, nil)
		return
	}

	// Assert net.PacketConn once, upfront — avoids a second interface dispatch
	// inside the WriteTo call and surfaces misconfiguration immediately.
	packetConn, ok := clientPc.(net.PacketConn)
	if !ok {
		dlog.Errorf("Client connection is not a net.PacketConn for UDP protocol (got %T, client_addr=%v) — this is a programming error", clientPc, clientAddr)
		_ = failWith(pluginsState, proxy, PluginsReturnCodeParseError, nil)
		return
	}

	if len(response) > pluginsState.maxUnencryptedUDPSafePayloadSize {
		truncated, err := TruncatedResponse(response)
		if err != nil {
			dlog.Warnf("Failed to truncate UDP response: %v", err)
			_ = failWith(pluginsState, proxy, PluginsReturnCodeParseError, err)
			return
		}
		response = truncated
	}

	if _, err := packetConn.WriteTo(response, *clientAddr); err != nil {
		dlog.Warnf("Failed to send UDP response: %v", err)
		return
	}

	// Update question-size estimator.  If TC is set, the full answer did not
	// fit, so only a blind (non-size) adjustment is made.
	// min builtin (Go 1.21+) used for clamping — replaces manual ternary idiom.
	if HasTCFlag(response) {
		proxy.questionSizeEstimator.blindAdjust()
	} else {
		proxy.questionSizeEstimator.adjust(min(ResponseOverhead+len(response), MaxDNSPacketSize))
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
//
// All three guard clauses use early returns, keeping the happy path
// (monitoring disabled) as a single branch with no further evaluation.
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
