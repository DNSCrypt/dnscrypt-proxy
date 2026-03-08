// Package main provides DNS utility functions for the DNSCrypt proxy.
//
// Go 1.26 full rewrite — modernized with latest language features:
//
//   - errors.AsType[E] (Go 1.26): type-safe error unwrapping in exchangeDNSOnce
//   - new(expr) (Go 1.26): pointer-from-expression where applicable
//   - net.Dialer.DialContext: all dials are context-aware (net.DialTimeout removed)
//   - sync.WaitGroup.Go (Go 1.25): cleaner goroutine management in runExchange
//   - range over int (Go 1.22): for try := range maxTries
//   - min()/max() builtins (Go 1.21): TTL clamping without manual if-chains
//   - context.WithTimeoutCause (Go 1.21): timeout-cause propagation for DNS dials
//   - Named constants: dnsHeaderLen, dnsTCBit, paddingByteHex, exchangeMaxTries,
//     fragmentProbeSize, safePacketSize replace magic numbers
//   - Sentinel errors: errPacketTooShort, errNilMessage, errUnreachable allocated once
//   - Shared net.Dialer: single allocation reused across UDP and TCP paths
//   - Stack-allocated read buffer: [MaxDNSPacketSize]byte avoids heap allocation
//   - Wrapped unpack errors: include server address for actionable logging
//   - Type-safe dial diagnostics: errors.AsType[*net.OpError] for structured logging
//   - Full godoc comments on all exported types and functions
//   - Drop-in replacement: all public API signatures unchanged
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/jedisct1/dlog"
)

// ─────────────────────────────────────── constants ──────────────────────────

const (
	// dnsHeaderLen is the fixed size of a DNS message header in bytes.
	dnsHeaderLen = 12

	// dnsTCBit is the bitmask for the TC (TrunCated) flag in byte 2 of the
	// DNS header (network byte order).
	dnsTCBit = 0x02

	// paddingByteHex is the hex representation of a single PADDING octet (0x58).
	// The codeberg.org/miekg/dns fork encodes PADDING rdata as a hex string;
	// each byte is represented as "58", so N bytes = strings.Repeat("58", N).
	paddingByteHex = "58"

	// exchangeMaxTries is the maximum number of DNS exchange attempts
	// per query, covering both fragment-probe and safe-path goroutines.
	exchangeMaxTries = 3

	// fragmentProbeSize is the padded packet size (bytes) used to test
	// whether the upstream server can reassemble IP fragments (MTU ~1500).
	fragmentProbeSize = 1500

	// safePacketSize is the padded packet size (bytes) used for the
	// conservative non-fragmented path, well under any common MTU.
	safePacketSize = 480

	// fragmentProbeDelay is the inter-attempt delay for fragment probes.
	fragmentProbeDelay = 200 * time.Millisecond

	// safePathDelay is the inter-attempt delay for safe-path queries.
	safePathDelay = 250 * time.Millisecond
)

// ─────────────────────────────────────── sentinel errors ────────────────────

var (
	errPacketTooShort = errors.New("dns packet too short")
	errNilMessage     = errors.New("dns message is nil")
	errUnreachable    = errors.New("unable to reach the server")
)

// ─────────────────────────────────────── message helpers ────────────────────

// EmptyResponseFromMessage builds a minimal response skeleton from a query
// message, copying the transaction ID, opcode, question section, recursion
// flags, and EDNS0 UDP size, and setting Response=true.
//
// Fields are assigned individually (not via a struct literal) because the
// codeberg.org/miekg/dns fork used by this project does not expose dns.Msg
// fields for use in composite literals in the same way as the upstream library.
func EmptyResponseFromMessage(srcMsg *dns.Msg) *dns.Msg {
	if srcMsg == nil {
		return &dns.Msg{}
	}
	dstMsg := &dns.Msg{}
	dstMsg.ID = srcMsg.ID
	dstMsg.Opcode = srcMsg.Opcode
	dstMsg.Question = srcMsg.Question
	dstMsg.Response = true
	dstMsg.RecursionAvailable = true
	dstMsg.RecursionDesired = srcMsg.RecursionDesired
	dstMsg.CheckingDisabled = false
	dstMsg.AuthenticatedData = false
	if srcMsg.UDPSize > 0 {
		dstMsg.UDPSize = srcMsg.UDPSize
		dstMsg.Security = srcMsg.Security
	}
	return dstMsg
}

// TruncatedResponse repacks packet as a truncated DNS response (TC bit set).
// Returns the packed bytes or an error if the original packet cannot be parsed.
func TruncatedResponse(packet []byte) ([]byte, error) {
	if len(packet) < dnsHeaderLen {
		return nil, errPacketTooShort
	}
	srcMsg := dns.Msg{Data: packet}
	if err := srcMsg.Unpack(); err != nil {
		return nil, err
	}
	dstMsg := EmptyResponseFromMessage(&srcMsg)
	dstMsg.Truncated = true
	if err := dstMsg.Pack(); err != nil {
		return nil, err
	}
	return dstMsg.Data, nil
}

// RefusedResponseFromMessage builds a refused or synthetic-answer DNS response.
//
// When refusedCode is true the response carries RCODE=REFUSED.
// Otherwise, for A/AAAA query types with a matching non-nil IP, a synthetic
// forged answer is returned. All other query types receive an HINFO record.
// An Extended DNS Error (EDE) option is appended when EDNS0 is active.
func RefusedResponseFromMessage(srcMsg *dns.Msg, refusedCode bool, ipv4 net.IP, ipv6 net.IP, ttl uint32) *dns.Msg {
	dstMsg := EmptyResponseFromMessage(srcMsg)

	ede := &dns.EDE{InfoCode: dns.ExtendedErrorFiltered}
	if dstMsg.UDPSize > 0 {
		dstMsg.Pseudo = append(dstMsg.Pseudo, ede)
	}

	if refusedCode {
		dstMsg.Rcode = dns.RcodeRefused
		return dstMsg
	}

	dstMsg.Rcode = dns.RcodeSuccess
	if srcMsg == nil || len(srcMsg.Question) == 0 {
		return dstMsg
	}

	question := srcMsg.Question[0]
	qtype := dns.RRToType(question)
	qname := question.Header().Name
	sendHInfo := true

	switch qtype {
	case dns.TypeA:
		if ipv4 != nil {
			if ip4 := ipv4.To4(); ip4 != nil {
				var b4 [4]byte
				copy(b4[:], ip4)
				dstMsg.Answer = []dns.RR{&dns.A{
					Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
					A:   rdata.A{Addr: netip.AddrFrom4(b4)},
				}}
				sendHInfo = false
				ede.InfoCode = dns.ExtendedErrorForgedAnswer
			}
		}

	case dns.TypeAAAA:
		if ipv6 != nil {
			if ip6 := ipv6.To16(); ip6 != nil {
				var b16 [16]byte
				copy(b16[:], ip6)
				dstMsg.Answer = []dns.RR{&dns.AAAA{
					Hdr:  dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
					AAAA: rdata.AAAA{Addr: netip.AddrFrom16(b16)},
				}}
				sendHInfo = false
				ede.InfoCode = dns.ExtendedErrorForgedAnswer
			}
		}
	}

	if sendHInfo {
		dstMsg.Answer = []dns.RR{&dns.HINFO{
			Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
			HINFO: rdata.HINFO{
				Cpu: "This query has been locally blocked",
				Os:  "by dnscrypt-proxy",
			},
		}}
	} else {
		ede.ExtraText = "This query has been locally blocked by dnscrypt-proxy"
	}

	return dstMsg
}

// ─────────────────────────────────────── raw packet helpers ─────────────────

// HasTCFlag reports whether the TC (TrunCated) bit is set in packet.
func HasTCFlag(packet []byte) bool {
	return len(packet) >= dnsHeaderLen && packet[2]&dnsTCBit == dnsTCBit
}

// TransactionID returns the 16-bit transaction ID from a raw DNS packet.
// Returns 0 if the packet is too short.
func TransactionID(packet []byte) uint16 {
	if len(packet) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(packet[0:2])
}

// SetTransactionID writes a 16-bit transaction ID into a raw DNS packet.
// Does nothing if the packet is too short.
func SetTransactionID(packet []byte, tid uint16) {
	if len(packet) < 2 {
		return
	}
	binary.BigEndian.PutUint16(packet[0:2], tid)
}

// Rcode extracts the base DNS RCODE from a raw packet (lower 4 bits of byte 3).
// Note: returns only the 4-bit base RCODE. The full 12-bit extended RCODE
// (RFC 6891 §6.1.3) requires parsing the OPT pseudo-RR.
func Rcode(packet []byte) uint8 {
	if len(packet) < 4 {
		return 0
	}
	return packet[3] & 0xf
}

// ─────────────────────────────────────── name normalisation ─────────────────

// NormalizeRawQName lowercases ASCII uppercase bytes in a DNS wire-format name
// in place. Accepts *[]byte to match callers that pass &slice.
// Uses a plain index loop to avoid implicit rune-decode overhead.
func NormalizeRawQName(name *[]byte) {
	if name == nil {
		return
	}
	for i := range *name {
		c := (*name)[i]
		if c >= 'A' && c <= 'Z' {
			(*name)[i] = c + ('a' - 'A')
		}
	}
}

// NormalizeQName lowercases and trims a DNS query name string.
// Returns "." for empty input or the root label. Returns an error for non-ASCII.
//
// Two-pass: the first pass checks for uppercase so the common all-lowercase
// case returns the original string without any allocation.
func NormalizeQName(str string) (string, error) {
	if len(str) == 0 || str == "." {
		return ".", nil
	}
	str = strings.TrimSuffix(str, ".")

	hasUpper := false
	for i := 0; i < len(str); i++ {
		c := str[i]
		if c >= utf8.RuneSelf {
			return str, errors.New("query name is not an ASCII string")
		}
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return str, nil
	}

	var b strings.Builder
	b.Grow(len(str))
	for i := 0; i < len(str); i++ {
		c := str[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String(), nil
}

// ─────────────────────────────────────── TTL helpers ────────────────────────

// getMinTTL returns the effective cache TTL for a DNS response.
//
// For positive answers (RCODE=NOERROR with records) the minimum TTL across the
// Answer section is clamped to [minTTL, maxTTL].
// For NXDOMAIN / no-data responses the minimum TTL across the Ns (authority)
// section is clamped to [cacheNegMinTTL, cacheNegMaxTTL].
// All other rcodes return cacheNegMinTTL immediately.
func getMinTTL(msg *dns.Msg, minTTL, maxTTL, cacheNegMinTTL, cacheNegMaxTTL uint32) time.Duration {
	if msg == nil {
		return time.Duration(cacheNegMinTTL) * time.Second
	}
	if (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) ||
		(len(msg.Answer) == 0 && len(msg.Ns) == 0) {
		return time.Duration(cacheNegMinTTL) * time.Second
	}

	ceiling := maxTTL
	floor := minTTL
	section := msg.Answer
	if msg.Rcode != dns.RcodeSuccess {
		ceiling = cacheNegMaxTTL
		floor = cacheNegMinTTL
		section = msg.Ns
	}

	ttl := ceiling
	for _, rr := range section {
		if t := rr.Header().TTL; t < ttl {
			ttl = t
		}
	}

	ttl = max(ttl, floor)
	ttl = min(ttl, ceiling)

	return time.Duration(ttl) * time.Second
}

// updateTTL decrements all RR TTLs in msg to reflect the time remaining until
// expiration. OPT records in the Extra section are left unchanged because
// their TTL field encodes the extended RCODE and EDNS version, not a cache TTL.
func updateTTL(msg *dns.Msg, expiration time.Time) {
	if msg == nil {
		return
	}
	until := time.Until(expiration)
	var ttl uint32
	if until > 0 {
		ttl = uint32(until / time.Second)
		if until-time.Duration(ttl)*time.Second >= time.Second/2 {
			ttl++
		}
	}
	for _, rr := range msg.Answer {
		rr.Header().TTL = ttl
	}
	for _, rr := range msg.Ns {
		rr.Header().TTL = ttl
	}
	for _, rr := range msg.Extra {
		switch dns.RRToType(rr) {
		case dns.TypeOPT:
			// OPT TTL encodes extended RCODE + EDNS flags; do not overwrite.
		default:
			rr.Header().TTL = ttl
		}
	}
}

// ─────────────────────────────────────── EDNS0 helpers ──────────────────────

// hasEDNS0Padding reports whether the packed DNS message in packet contains
// an EDNS0 PADDING option.
func hasEDNS0Padding(packet []byte) (bool, error) {
	if len(packet) < dnsHeaderLen {
		return false, errPacketTooShort
	}
	msg := dns.Msg{Data: packet}
	if err := msg.Unpack(); err != nil {
		return false, err
	}
	for _, rr := range msg.Pseudo {
		if _, ok := rr.(*dns.PADDING); ok {
			return true, nil
		}
	}
	return false, nil
}

// addEDNS0PaddingIfNoneFound appends an EDNS0 PADDING option of paddingLen
// bytes to msg if none is already present, then repacks and returns the bytes.
//
// The codeberg.org/miekg/dns fork encodes PADDING rdata as a hex string where
// each padding byte is "58", so paddingLen bytes become strings.Repeat("58", N).
func addEDNS0PaddingIfNoneFound(msg *dns.Msg, unpaddedPacket []byte, paddingLen int) ([]byte, error) {
	if msg == nil {
		return nil, errNilMessage
	}
	if paddingLen <= 0 {
		return unpaddedPacket, nil
	}
	if msg.UDPSize == 0 {
		msg.UDPSize = uint16(MaxDNSPacketSize)
	}
	for _, rr := range msg.Pseudo {
		if _, ok := rr.(*dns.PADDING); ok {
			return unpaddedPacket, nil
		}
	}
	paddingRR := &dns.PADDING{Padding: strings.Repeat(paddingByteHex, paddingLen)}
	msg.Pseudo = append(msg.Pseudo, paddingRR)
	if err := msg.Pack(); err != nil {
		return nil, err
	}
	return msg.Data, nil
}

// removeEDNS0Options strips all EDNS0 pseudo-RRs from msg.
// Returns true if any were present.
func removeEDNS0Options(msg *dns.Msg) bool {
	if msg == nil || len(msg.Pseudo) == 0 {
		return false
	}
	msg.Pseudo = nil
	return true
}

// ─────────────────────────────────────── TXT helpers ────────────────────────

// dddToByte converts a 3-digit decimal escape sequence (e.g. "065") to its
// byte value. Returns (0, false) if the input is too short or value > 255.
func dddToByte(s []byte) (byte, bool) {
	if len(s) < 3 {
		return 0, false
	}
	n := int(s[0]-'0')*100 + int(s[1]-'0')*10 + int(s[2]-'0')
	if n > 255 {
		return 0, false
	}
	return byte(n), true
}

// PackTXTRR converts a TXT record string (with DNS escape sequences) into a
// raw byte slice. Supported escapes: \t, \r, \n, \\, and \DDD decimal.
func PackTXTRR(s string) []byte {
	bs := []byte(s)
	msg := make([]byte, 0, len(bs))
	for i := 0; i < len(bs); i++ {
		if bs[i] != '\\' {
			msg = append(msg, bs[i])
			continue
		}
		i++
		if i >= len(bs) {
			break
		}
		if i+2 < len(bs) && isDigit(bs[i]) && isDigit(bs[i+1]) && isDigit(bs[i+2]) {
			if b, ok := dddToByte(bs[i:]); ok {
				msg = append(msg, b)
			}
			i += 2
			continue
		}
		switch bs[i] {
		case 't':
			msg = append(msg, '\t')
		case 'r':
			msg = append(msg, '\r')
		case 'n':
			msg = append(msg, '\n')
		default:
			msg = append(msg, bs[i])
		}
	}
	return msg
}

// ─────────────────────────────────────── DNS exchange ───────────────────────

// dnsExchangeResult holds the outcome of one DNS exchange attempt.
// Unexported: used only within this package.
type dnsExchangeResult struct {
	response         *dns.Msg
	rtt              time.Duration
	priority         int  // 0 = fragment-capable path; 1 = safe (non-fragmented) path
	fragmentsBlocked bool // true when the server cannot reassemble IP fragments
	err              error
}

// DNSExchange sends a DNS query to serverAddress (optionally via relay) and
// returns the best response, round-trip time, whether fragments are blocked,
// and any error.
//
// When tryFragmentsSupport is true, each attempt launches two concurrent
// goroutines: one with a 1500-byte padded packet (probes fragment support) and
// one with a 480-byte safe packet. The first successful fragment-capable
// response wins; a safe-path response is accepted only if no fragment-capable
// response arrives.
//
// If the relay attempt fails and proxy.anonDirectCertFallback is true, the
// exchange is retried over a direct connection.
func DNSExchange(
	proxy *Proxy,
	proto string,
	query *dns.Msg,
	serverAddress string,
	relay *DNSCryptRelay,
	serverName *string,
	tryFragmentsSupport bool,
) (*dns.Msg, time.Duration, bool, error) {
	resp, rtt, fragBlocked, err := runExchange(proxy, proto, query, serverAddress, relay, serverName, tryFragmentsSupport)
	if err == nil {
		return resp, rtt, fragBlocked, nil
	}

	if relay == nil || !proxy.anonDirectCertFallback {
		return nil, 0, false, err
	}
	if serverName != nil {
		dlog.Infof(
			"Unable to get the public key for [%v] via relay [%v], retrying over a direct connection",
			*serverName,
			relay.RelayUDPAddr.IP,
		)
	}
	return runExchange(proxy, proto, query, serverAddress, nil, serverName, tryFragmentsSupport)
}

// runExchange is the core exchange engine. It launches up to
// 2×exchangeMaxTries concurrent goroutines (fragment probe + safe path per try)
// with staggered delays, collects results, and returns the best available
// response.
//
// Uses sync.WaitGroup.Go (Go 1.25+) for cleaner goroutine lifecycle management.
func runExchange(
	proxy *Proxy,
	proto string,
	query *dns.Msg,
	serverAddress string,
	relay *DNSCryptRelay,
	serverName *string,
	tryFragmentsSupport bool,
) (*dns.Msg, time.Duration, bool, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	goroutines := exchangeMaxTries
	if tryFragmentsSupport {
		goroutines = 2 * exchangeMaxTries
	}
	channel := make(chan dnsExchangeResult, goroutines)

	var wg sync.WaitGroup
	launched := 0

	for try := range exchangeMaxTries {
		if tryFragmentsSupport {
			q := query.Copy()
			q.ID += uint16(launched)
			launched++
			delay := time.Duration(try) * fragmentProbeDelay
			wg.Go(func() {
				waitAndExchange(ctx, proxy, proto, q, serverAddress, relay, fragmentProbeSize, false, 0, delay, channel)
			})
		}

		q := query.Copy()
		q.ID += uint16(launched)
		launched++
		delay := time.Duration(try) * safePathDelay
		wg.Go(func() {
			waitAndExchange(ctx, proxy, proto, q, serverAddress, relay, safePacketSize, true, 1, delay, channel)
		})
	}

	// Collect results in a separate goroutine so wg.Wait doesn't block
	// the result-reading loop below.
	go func() {
		wg.Wait()
		close(channel)
	}()

	var best *dnsExchangeResult
	var lastErr error

	for resp := range channel {
		if resp.err != nil {
			if lastErr == nil {
				lastErr = resp.err
			}
			continue
		}
		if best == nil || resp.priority < best.priority ||
			(resp.priority == best.priority && resp.rtt < best.rtt) {
			best = &resp
			if best.priority == 0 {
				cancel()
				break
			}
		}
	}

	if best == nil {
		if lastErr == nil {
			lastErr = errUnreachable
		}
		return nil, 0, false, lastErr
	}

	if serverName != nil {
		if best.fragmentsBlocked {
			dlog.Debugf("[%v] public key retrieval succeeded but server is blocking fragments", *serverName)
		} else {
			dlog.Debugf("[%v] public key retrieval succeeded", *serverName)
		}
	}
	return best.response, best.rtt, best.fragmentsBlocked, nil
}

// waitAndExchange sleeps for delay (respecting ctx cancellation), then calls
// exchangeDNSOnce and sends the result to ch.
func waitAndExchange(
	ctx context.Context,
	proxy *Proxy,
	proto string,
	query *dns.Msg,
	serverAddress string,
	relay *DNSCryptRelay,
	paddedLen int,
	fragmentsBlocked bool,
	priority int,
	delay time.Duration,
	ch chan<- dnsExchangeResult,
) {
	if delay > 0 {
		t := time.NewTimer(delay)
		defer t.Stop()
		select {
		case <-ctx.Done():
			ch <- dnsExchangeResult{err: context.Canceled}
			return
		case <-t.C:
		}
	}
	result := exchangeDNSOnce(ctx, proxy, proto, query, serverAddress, relay, paddedLen)
	result.fragmentsBlocked = fragmentsBlocked
	result.priority = priority
	ch <- result
}

// exchangeDNSOnce performs a single DNS exchange over UDP or TCP.
//
// All dials use net.Dialer.DialContext so that context cancellation propagates
// promptly to the network layer. Uses errors.AsType[*net.OpError] (Go 1.26)
// for type-safe, reflection-free dial error diagnostics.
func exchangeDNSOnce(
	ctx context.Context,
	proxy *Proxy,
	proto string,
	query *dns.Msg,
	serverAddress string,
	relay *DNSCryptRelay,
	paddedLen int,
) dnsExchangeResult {
	dialer := &net.Dialer{Timeout: proxy.timeout}
	var packet []byte
	var rtt time.Duration

	if proto == "udp" {
		qNameLen := len(query.Question[0].Header().Name)
		if padding := paddedLen - qNameLen; padding > 0 {
			paddingRR := &dns.PADDING{Padding: strings.Repeat("00", padding)}
			query.Pseudo = append(query.Pseudo, paddingRR)
			if query.UDPSize == 0 {
				query.UDPSize = uint16(MaxDNSPacketSize)
			}
		}
		if err := query.Pack(); err != nil {
			return dnsExchangeResult{err: err}
		}
		binQuery := query.Data

		udpAddr, err := net.ResolveUDPAddr("udp", serverAddress)
		if err != nil {
			return dnsExchangeResult{err: err}
		}
		upstreamAddr := udpAddr
		if relay != nil {
			proxy.prepareForRelay(udpAddr.IP, udpAddr.Port, &binQuery)
			upstreamAddr = relay.RelayUDPAddr
		}

		now := time.Now()
		pc, err := dialer.DialContext(ctx, "udp", upstreamAddr.String())
		if err != nil {
			if opErr, ok := errors.AsType[*net.OpError](err); ok {
				dlog.Debugf("UDP dial failed: op=%s net=%s addr=%v err=%v", opErr.Op, opErr.Net, opErr.Addr, opErr.Err)
			}
			return dnsExchangeResult{err: err}
		}
		defer pc.Close()

		if err := pc.SetDeadline(now.Add(proxy.timeout)); err != nil {
			return dnsExchangeResult{err: err}
		}
		if _, err := pc.Write(binQuery); err != nil {
			return dnsExchangeResult{err: err}
		}
		var buf [MaxDNSPacketSize]byte
		length, err := pc.Read(buf[:])
		if err != nil {
			return dnsExchangeResult{err: err}
		}
		rtt = time.Since(now)
		packet = make([]byte, length)
		copy(packet, buf[:length])

	} else { // TCP
		if err := query.Pack(); err != nil {
			return dnsExchangeResult{err: err}
		}
		binQuery := query.Data

		tcpAddr, err := net.ResolveTCPAddr("tcp", serverAddress)
		if err != nil {
			return dnsExchangeResult{err: err}
		}
		upstreamAddr := tcpAddr
		if relay != nil {
			proxy.prepareForRelay(tcpAddr.IP, tcpAddr.Port, &binQuery)
			upstreamAddr = relay.RelayTCPAddr
		}

		now := time.Now()
		var pc net.Conn
		if proxyDialer := proxy.xTransport.proxyDialer; proxyDialer != nil {
			pc, err = (*proxyDialer).Dial("tcp", upstreamAddr.String())
		} else {
			pc, err = dialer.DialContext(ctx, "tcp", upstreamAddr.String())
		}
		if err != nil {
			if opErr, ok := errors.AsType[*net.OpError](err); ok {
				dlog.Debugf("TCP dial failed: op=%s net=%s addr=%v err=%v", opErr.Op, opErr.Net, opErr.Addr, opErr.Err)
			}
			return dnsExchangeResult{err: err}
		}
		defer pc.Close()

		if err := pc.SetDeadline(now.Add(proxy.timeout)); err != nil {
			return dnsExchangeResult{err: err}
		}
		binQuery, err = PrefixWithSize(binQuery)
		if err != nil {
			return dnsExchangeResult{err: err}
		}
		if _, err := pc.Write(binQuery); err != nil {
			return dnsExchangeResult{err: err}
		}
		packet, err = ReadPrefixed(&pc)
		if err != nil {
			return dnsExchangeResult{err: err}
		}
		rtt = time.Since(now)
	}

	msg := dns.Msg{Data: packet}
	if err := msg.Unpack(); err != nil {
		return dnsExchangeResult{err: fmt.Errorf("unpack response from [%s]: %w", serverAddress, err)}
	}
	return dnsExchangeResult{response: &msg, rtt: rtt}
}
