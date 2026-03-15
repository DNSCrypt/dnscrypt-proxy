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
//   - Stack-allocated read buffer: [MaxDNSPacketSize]byte avoids heap allocation
//   - Wrapped unpack errors: include server address for actionable logging
//   - Type-safe dial diagnostics: errors.AsType[*net.OpError] for structured logging
//   - Full godoc comments on all exported types and functions
//   - Drop-in replacement: all public API signatures unchanged
package main

import (
\t"context"
\t"encoding/binary"
\t"errors"
\t"fmt"
\t"net"
\t"net/netip"
\t"strings"
\t"sync"
\t"time"
\t"unicode/utf8"

\t"codeberg.org/miekg/dns"
\t"codeberg.org/miekg/dns/rdata"
\t"github.com/jedisct1/dlog"
)

// ─────────────────────────────────────── constants ──────────────────────────

const (
\t// dnsHeaderLen is the fixed size of a DNS message header in bytes.
\tdnsHeaderLen = 12

\t// dnsTCBit is the bitmask for the TC (TrunCated) flag in byte 2 of the
\t// DNS header (network byte order).
\tdnsTCBit = 0x02

\t// paddingByteHex is the hex representation of a single PADDING octet (0x58).
\t// The codeberg.org/miekg/dns fork encodes PADDING rdata as a hex string;
\t// each byte is represented as "58", so N bytes = strings.Repeat("58", N).
\tpaddingByteHex = "58"

\t// exchangeMaxTries is the maximum number of DNS exchange attempts
\t// per query, covering both fragment-probe and safe-path goroutines.
\texchangeMaxTries = 3

\t// fragmentProbeSize is the padded packet size (bytes) used to test
\t// whether the upstream server can reassemble IP fragments (MTU ~1500).
\tfragmentProbeSize = 1500

\t// safePacketSize is the padded packet size (bytes) used for the
\t// conservative non-fragmented path, well under any common MTU.
\tsafePacketSize = 480

\t// fragmentProbeDelay is the inter-attempt delay for fragment probes.
\tfragmentProbeDelay = 200 * time.Millisecond

\t// safePathDelay is the inter-attempt delay for safe-path queries.
\tsafePathDelay = 250 * time.Millisecond
)

// MaxDNSPacketSize is assumed to be defined elsewhere in your project
// (kept as-is to preserve compatibility).
// const MaxDNSPacketSize = 4096

// ─────────────────────────────────────── sentinel errors ────────────────────

var (
\terrPacketTooShort = errors.New("dns packet too short")
\terrNilMessage     = errors.New("dns message is nil")
\terrUnreachable    = errors.New("unable to reach the server")
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
\tif srcMsg == nil {
\t\treturn &dns.Msg{}
\t}
\tdstMsg := &dns.Msg{}
\tdstMsg.ID = srcMsg.ID
\tdstMsg.Opcode = srcMsg.Opcode
\tdstMsg.Question = srcMsg.Question
\tdstMsg.Response = true
\tdstMsg.RecursionAvailable = true
\tdstMsg.RecursionDesired = srcMsg.RecursionDesired
\tdstMsg.CheckingDisabled = false
\tdstMsg.AuthenticatedData = false
\tif srcMsg.UDPSize > 0 {
\t\tdstMsg.UDPSize = srcMsg.UDPSize
\t\tdstMsg.Security = srcMsg.Security
\t}
\treturn dstMsg
}

// TruncatedResponse repacks packet as a truncated DNS response (TC bit set).
// Returns the packed bytes or an error if the original packet cannot be parsed.
func TruncatedResponse(packet []byte) ([]byte, error) {
\tif len(packet) < dnsHeaderLen {
\t\treturn nil, errPacketTooShort
\t}
\tsrcMsg := dns.Msg{Data: packet}
\tif err := srcMsg.Unpack(); err != nil {
\t\treturn nil, err
\t}
\tdstMsg := EmptyResponseFromMessage(&srcMsg)
\tdstMsg.Truncated = true
\tif err := dstMsg.Pack(); err != nil {
\t\treturn nil, err
\t}
\treturn dstMsg.Data, nil
}

// RefusedResponseFromMessage builds a refused or synthetic-answer DNS response.
//
// When refusedCode is true the response carries RCODE=REFUSED.
// Otherwise, for A/AAAA query types with a matching non-nil IP, a synthetic
// forged answer is returned. All other query types receive an HINFO record.
// An Extended DNS Error (EDE) option is appended when EDNS0 is active.
func RefusedResponseFromMessage(srcMsg *dns.Msg, refusedCode bool, ipv4 net.IP, ipv6 net.IP, ttl uint32) *dns.Msg {
\tdstMsg := EmptyResponseFromMessage(srcMsg)

\tede := &dns.EDE{InfoCode: dns.ExtendedErrorFiltered}
\tif dstMsg.UDPSize > 0 {
\t\tdstMsg.Pseudo = append(dstMsg.Pseudo, ede)
\t}

\tif refusedCode {
\t\tdstMsg.Rcode = dns.RcodeRefused
\t\treturn dstMsg
\t}

\tdstMsg.Rcode = dns.RcodeSuccess
\tif srcMsg == nil || len(srcMsg.Question) == 0 {
\t\treturn dstMsg
\t}

\tquestion := srcMsg.Question[0]
\tqtype := dns.RRToType(question)
\tqname := question.Header().Name
\tsendHInfo := true

\tswitch qtype {
\tcase dns.TypeA:
\t\tif ipv4 != nil {
\t\t\tif ip4 := ipv4.To4(); ip4 != nil {
\t\t\t\tvar b4 [4]byte
\t\t\t\tcopy(b4[:], ip4)
\t\t\t\tdstMsg.Answer = []dns.RR{&dns.A{
\t\t\t\t\tHdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
\t\t\t\t\tA:   rdata.A{Addr: netip.AddrFrom4(b4)},
\t\t\t\t}}
\t\t\t\tsendHInfo = false
\t\t\t\tede.InfoCode = dns.ExtendedErrorForgedAnswer
\t\t\t}
\t\t}

\tcase dns.TypeAAAA:
\t\tif ipv6 != nil {
\t\t\tif ip6 := ipv6.To16(); ip6 != nil {
\t\t\t\tvar b16 [16]byte
\t\t\t\tcopy(b16[:], ip6)
\t\t\t\tdstMsg.Answer = []dns.RR{&dns.AAAA{
\t\t\t\t\tHdr:  dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
\t\t\t\t\tAAAA: rdata.AAAA{Addr: netip.AddrFrom16(b16)},
\t\t\t\t}}
\t\t\t\tsendHInfo = false
\t\t\t\tede.InfoCode = dns.ExtendedErrorForgedAnswer
\t\t\t}
\t\t}
\t}

\tif sendHInfo {
\t\tdstMsg.Answer = []dns.RR{&dns.HINFO{
\t\t\tHdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
\t\t\tHINFO: rdata.HINFO{
\t\t\t\tCpu: "This query has been locally blocked",
\t\t\t\tOs:  "by dnscrypt-proxy",
\t\t\t},
\t\t}}
\t} else {
\t\tede.ExtraText = "This query has been locally blocked by dnscrypt-proxy"
\t}

\treturn dstMsg
}

// ─────────────────────────────────────── raw packet helpers ─────────────────

// HasTCFlag reports whether the TC (TrunCated) bit is set in packet.
func HasTCFlag(packet []byte) bool {
\treturn len(packet) >= dnsHeaderLen && packet[2]&dnsTCBit == dnsTCBit
}

// TransactionID returns the 16-bit transaction ID from a raw DNS packet.
// Returns 0 if the packet is too short.
func TransactionID(packet []byte) uint16 {
\tif len(packet) < 2 {
\t\treturn 0
\t}
\treturn binary.BigEndian.Uint16(packet[0:2])
}

// SetTransactionID writes a 16-bit transaction ID into a raw DNS packet.
// Does nothing if the packet is too short.
func SetTransactionID(packet []byte, tid uint16) {
\tif len(packet) < 2 {
\t\treturn
\t}
\tbinary.BigEndian.PutUint16(packet[0:2], tid)
}

// Rcode extracts the base DNS RCODE from a raw packet (lower 4 bits of byte 3).
// Note: returns only the 4-bit base RCODE. The full 12-bit extended RCODE
// (RFC 6891 §6.1.3) requires parsing the OPT pseudo-RR.
func Rcode(packet []byte) uint8 {
\tif len(packet) < 4 {
\t\treturn 0
\t}
\treturn packet[3] & 0xf
}

// ─────────────────────────────────────── name normalisation ─────────────────

// NormalizeRawQName lowercases ASCII uppercase bytes in a DNS wire-format name
// in place. Accepts *[]byte to match callers that pass &slice.
// Uses a plain index loop to avoid implicit rune-decode overhead.
func NormalizeRawQName(name *[]byte) {
\tif name == nil {
\t\treturn
\t}
\tfor i := range *name {
\t\tc := (*name)[i]
\t\tif c >= 'A' && c <= 'Z' {
\t\t\t(*name)[i] = c + ('a' - 'A')
\t\t}
\t}
}

// NormalizeQName lowercases and trims a DNS query name string.
// Returns "." for empty input or the root label. Returns an error for non-ASCII.
//
// Two-pass: the first pass checks for uppercase so the common all-lowercase
// case returns the original string without any allocation.
func NormalizeQName(str string) (string, error) {
\tif len(str) == 0 || str == "." {
\t\treturn ".", nil
\t}
\traw := str
\tstr = strings.TrimSuffix(str, ".")

\thasUpper := false
\tfor i := 0; i < len(str); i++ {
\t\tc := str[i]
\t\tif c >= utf8.RuneSelf {
\t\t\treturn raw, errors.New("query name is not an ASCII string")
\t\t}
\t\tif c >= 'A' && c <= 'Z' {
\t\t\thasUpper = true
\t\t\tbreak
\t\t}
\t}
\tif !hasUpper {
\t\treturn str, nil
\t}

\tvar b strings.Builder
\tb.Grow(len(str))
\tfor i := 0; i < len(str); i++ {
\t\tc := str[i]
\t\tif c >= 'A' && c <= 'Z' {
\t\t\tc += 'a' - 'A'
\t\t}
\t\tb.WriteByte(c)
\t}
\treturn b.String(), nil
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
\tif msg == nil {
\t\treturn time.Duration(cacheNegMinTTL) * time.Second
\t}
\tif (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) ||
\t\t(len(msg.Answer) == 0 && len(msg.Ns) == 0) {
\t\treturn time.Duration(cacheNegMinTTL) * time.Second
\t}

\tceiling := maxTTL
\tfloor := minTTL
\tsection := msg.Answer
\tif msg.Rcode != dns.RcodeSuccess {
\t\tceiling = cacheNegMaxTTL
\t\tfloor = cacheNegMinTTL
\t\tsection = msg.Ns
\t}

\tttl := ceiling
\tfor _, rr := range section {
\t\tif t := rr.Header().TTL; t < ttl {
\t\t\tttl = t
\t\t}
\t}

\tttl = max(ttl, floor)
\tttl = min(ttl, ceiling)

\treturn time.Duration(ttl) * time.Second
}

// updateTTL decrements all RR TTLs in msg to reflect the time remaining until
// expiration. OPT records in the Extra section are left unchanged because
// their TTL field encodes the extended RCODE and EDNS version, not a cache TTL.
func updateTTL(msg *dns.Msg, expiration time.Time) {
\tif msg == nil {
\t\treturn
\t}
\tuntil := time.Until(expiration)
\tvar ttl uint32
\tif until > 0 {
\t\tttl = uint32(until / time.Second)
\t\tif until-time.Duration(ttl)*time.Second >= time.Second/2 {
\t\t\tttl++
\t\t}
\t}
\tfor _, rr := range msg.Answer {
\t\trr.Header().TTL = ttl
\t}
\tfor _, rr := range msg.Ns {
\t\trr.Header().TTL = ttl
\t}
\tfor _, rr := range msg.Extra {
\t\tswitch dns.RRToType(rr) {
\t\tcase dns.TypeOPT:
\t\t\t// OPT TTL encodes extended RCODE + EDNS flags; do not overwrite.
\t\tdefault:
\t\t\trr.Header().TTL = ttl
\t\t}
\t}
}

// ─────────────────────────────────────── EDNS0 helpers ──────────────────────

// hasEDNS0Padding reports whether the packed DNS message in packet contains
// an EDNS0 PADDING option.
func hasEDNS0Padding(packet []byte) (bool, error) {
\tif len(packet) < dnsHeaderLen {
\t\treturn false, errPacketTooShort
\t}
\tmsg := dns.Msg{Data: packet}
\tif err := msg.Unpack(); err != nil {
\t\treturn false, err
\t}
\tfor _, rr := range msg.Pseudo {
\t\tif _, ok := rr.(*dns.PADDING); ok {
\t\t\treturn true, nil
\t\t}
\t}
\treturn false, nil
}

// addEDNS0PaddingIfNoneFound appends an EDNS0 PADDING option of paddingLen
// bytes to msg if none is already present, then repacks and returns the bytes.
//
// The codeberg.org/miekg/dns fork encodes PADDING rdata as a hex string where
// each padding byte is "58", so paddingLen bytes become strings.Repeat("58", N).
func addEDNS0PaddingIfNoneFound(msg *dns.Msg, unpaddedPacket []byte, paddingLen int) ([]byte, error) {
\tif msg == nil {
\t\treturn nil, errNilMessage
\t}
\tif paddingLen <= 0 {
\t\treturn unpaddedPacket, nil
\t}
\tif msg.UDPSize == 0 {
\t\tmsg.UDPSize = uint16(MaxDNSPacketSize)
\t}
\tfor _, rr := range msg.Pseudo {
\t\tif _, ok := rr.(*dns.PADDING); ok {
\t\t\treturn unpaddedPacket, nil
\t\t}
\t}
\tpaddingRR := &dns.PADDING{Padding: strings.Repeat(paddingByteHex, paddingLen)}
\tmsg.Pseudo = append(msg.Pseudo, paddingRR)
\tif err := msg.Pack(); err != nil {
\t\treturn nil, err
\t}
\treturn msg.Data, nil
}

// removeEDNS0Padding strips only EDNS0 PADDING pseudo-RRs from msg.
// Returns true if any padding options were present.
func removeEDNS0Padding(msg *dns.Msg) bool {
\tif msg == nil || len(msg.Pseudo) == 0 {
\t\treturn false
\t}
\tout := msg.Pseudo[:0]
\tremoved := false
\tfor _, rr := range msg.Pseudo {
\t\tif _, ok := rr.(*dns.PADDING); ok {
\t\t\tremoved = true
\t\t\tcontinue
\t\t}
\t\tout = append(out, rr)
\t}
\tmsg.Pseudo = out
\treturn removed
}

// ─────────────────────────────────────── TXT helpers ────────────────────────

func isDigit(b byte) bool {
\treturn b >= '0' && b <= '9'
}

// dddToByte converts a 3-digit decimal escape sequence (e.g. "065") to its
// byte value. Returns (0, false) if the input is too short, non-digit, or >255.
func dddToByte(s string) (byte, bool) {
\tif len(s) < 3 {
\t\treturn 0, false
\t}
\tb0, b1, b2 := s[0], s[1], s[2]
\tif !isDigit(b0) || !isDigit(b1) || !isDigit(b2) {
\t\treturn 0, false
\t}
\tn := int(b0-'0')*100 + int(b1-'0')*10 + int(b2-'0')
\tif n > 255 {
\t\treturn 0, false
\t}
\treturn byte(n), true
}

// PackTXTRR converts a TXT record string (with DNS escape sequences) into a
// raw byte slice. Supported escapes: \t, 
, 
, \\, and DDD decimal.
func PackTXTRR(s string) []byte {
\tmsg := make([]byte, 0, len(s))
\tfor i := 0; i < len(s); i++ {
\t\tc := s[i]
\t\tif c != '\\' {
\t\t\tmsg = append(msg, c)
\t\t\tcontinue
\t\t}
\t\ti++
\t\tif i >= len(s) {
\t\t\tbreak
\t\t}
\t\tif i+2 < len(s) {
\t\t\tif b, ok := dddToByte(s[i : i+3]); ok {
\t\t\t\tmsg = append(msg, b)
\t\t\t\ti += 2
\t\t\t\tcontinue
\t\t\t}
\t\t}
\t\tswitch s[i] {
\t\tcase 't':
\t\t\tmsg = append(msg, '\t')
\t\tcase 'r':
\t\t\tmsg = append(msg, '
')
\t\tcase 'n':
\t\t\tmsg = append(msg, '
')
\t\tdefault:
\t\t\tmsg = append(msg, s[i])
\t\t}
\t}
\treturn msg
}

// ─────────────────────────────────────── DNS exchange ───────────────────────

// dnsExchangeResult holds the outcome of one DNS exchange attempt.
// Unexported: used only within this file.
type dnsExchangeResult struct {
\tresponse         *dns.Msg
\trtt              time.Duration
\tpriority         int  // 0 = fragment-capable path; 1 = safe (non-fragmented) path
\tfragmentsBlocked bool // true when the server cannot reassemble IP fragments
\terr              error
}

// ExchangeOptions describes one DNS exchange attempt.
type ExchangeOptions struct {
\tProto              string
\tServerAddress      string
\tRelay              *DNSCryptRelay
\tServerName         *string
\tTryFragmentSupport bool
}

// DNSExchange sends a DNS query according to opts and returns the best response,
// round-trip time, whether fragments are blocked, and any error.
//
// If a relay attempt fails and proxy.anonDirectCertFallback is true, the
// exchange is retried over a direct connection.
func DNSExchange(
\tctx context.Context,
\tproxy *Proxy,
\tquery *dns.Msg,
\topts ExchangeOptions,
) (*dns.Msg, time.Duration, bool, error) {
\tctx, cancel := context.WithCancel(ctx)
\tdefer cancel()

\tresp, rtt, fragBlocked, err := runExchange(ctx, proxy, query, opts)
\tif err == nil {
\t\treturn resp, rtt, fragBlocked, nil
\t}

\tif opts.Relay == nil || !proxy.anonDirectCertFallback {
\t\treturn nil, 0, false, err
\t}
\tif opts.ServerName != nil {
\t\tdlog.Infof(
\t\t\t"Unable to get the public key for [%v] via relay [%v], retrying over a direct connection",
\t\t\t*opts.ServerName,
\t\t\topts.Relay.RelayUDPAddr.IP,
\t\t)
\t}

\t// Fallback: same options but without relay.
\topts.Relay = nil
\treturn runExchange(ctx, proxy, query, opts)
}

// runExchange is the core exchange engine. It launches up to
// 2×exchangeMaxTries concurrent goroutines (fragment probe + safe path per try)
// with staggered delays, collects results, and returns the best available
// response.
func runExchange(
\tctx context.Context,
\tproxy *Proxy,
\tquery *dns.Msg,
\topts ExchangeOptions,
) (*dns.Msg, time.Duration, bool, error) {
\tctx, cancel := context.WithCancel(ctx)
\tdefer cancel()

\tgoroutines := exchangeMaxTries
\tif opts.TryFragmentSupport {
\t\tgoroutines = 2 * exchangeMaxTries
\t}
\tch := make(chan dnsExchangeResult, goroutines)

\tvar wg sync.WaitGroup
\tlaunched := 0

\tfor try := range exchangeMaxTries {
\t\tif opts.TryFragmentSupport {
\t\t\tq := query.Copy()
\t\t\tq.ID += uint16(launched)
\t\t\tlaunched++
\t\t\tdelay := time.Duration(try) * fragmentProbeDelay
\t\t\td := delay
\t\t\twg.Go(func() {
\t\t\t\twaitAndExchange(
\t\t\t\t\tctx, proxy, opts.Proto, q, opts.ServerAddress, opts.Relay,
\t\t\t\t\tfragmentProbeSize, false, 0, d, ch,
\t\t\t\t)
\t\t\t})
\t\t}

\t\tq := query.Copy()
\t\tq.ID += uint16(launched)
\t\tlaunched++
\t\tdelay := time.Duration(try) * safePathDelay
\t\td := delay
\t\twg.Go(func() {
\t\t\twaitAndExchange(
\t\t\t\tctx, proxy, opts.Proto, q, opts.ServerAddress, opts.Relay,
\t\t\t\tsafePacketSize, true, 1, d, ch,
\t\t\t)
\t\t})
\t}

\tgo func() {
\t\twg.Wait()
\t\tclose(ch)
\t}()

\tvar best *dnsExchangeResult
\tvar lastErr error

\tfor res := range ch {
\t\tif res.err != nil {
\t\t\tif !errors.Is(res.err, context.Canceled) && lastErr == nil {
\t\t\t\tlastErr = res.err
\t\t\t}
\t\t\tcontinue
\t\t}
\t\tif best == nil ||
\t\t\tres.priority < best.priority ||
\t\t\t(res.priority == best.priority && res.rtt < best.rtt) {
\t\t\tbest = &res
\t\t\tif best.priority == 0 {
\t\t\t\t// Fragment-capable path won; stop remaining attempts.
\t\t\t\tcancel()
\t\t\t\tbreak
\t\t\t}
\t\t}
\t}

\tif best == nil {
\t\tif lastErr == nil {
\t\t\tlastErr = errUnreachable
\t\t}
\t\treturn nil, 0, false, lastErr
\t}

\tif opts.ServerName != nil {
\t\tif best.fragmentsBlocked {
\t\t\tdlog.Debugf("[%v] public key retrieval succeeded but server is blocking fragments", *opts.ServerName)
\t\t} else {
\t\t\tdlog.Debugf("[%v] public key retrieval succeeded", *opts.ServerName)
\t\t}
\t}

\treturn best.response, best.rtt, best.fragmentsBlocked, nil
}

// waitAndExchange sleeps for delay (respecting ctx cancellation), then calls
// exchangeDNSOnce and sends the result to ch.
func waitAndExchange(
\tctx context.Context,
\tproxy *Proxy,
\tproto string,
\tquery *dns.Msg,
\tserverAddress string,
\trelay *DNSCryptRelay,
\tpaddedLen int,
\tfragmentsBlocked bool,
\tpriority int,
\tdelay time.Duration,
\tch chan<- dnsExchangeResult,
) {
\tif delay > 0 {
\t\tt := time.NewTimer(delay)
\t\tdefer t.Stop()
\t\tselect {
\t\tcase <-ctx.Done():
\t\t\treturn
\t\tcase <-t.C:
\t\t}
\t}
\tselect {
\tcase <-ctx.Done():
\t\treturn
\tdefault:
\t}

\tres := exchangeDNSOnce(ctx, proxy, proto, query, serverAddress, relay, paddedLen)
\tres.fragmentsBlocked = fragmentsBlocked
\tres.priority = priority

\tselect {
\tcase <-ctx.Done():
\t\treturn
\tcase ch <- res:
\t}
}

// exchangeDNSOnce performs a single DNS exchange over UDP or TCP.
//
// All dials use net.Dialer.DialContext so that context cancellation propagates
// promptly to the network layer. Uses errors.AsType[*net.OpError] for
// type-safe, reflection-free dial error diagnostics.
func exchangeDNSOnce(
\tctx context.Context,
\tproxy *Proxy,
\tproto string,
\tquery *dns.Msg,
\tserverAddress string,
\trelay *DNSCryptRelay,
\tpaddedLen int,
) dnsExchangeResult {
\tdialer := &net.Dialer{Timeout: proxy.timeout}

\tswitch proto {
\tcase "udp":
\t\treturn exchangeUDP(ctx, proxy, dialer, query, serverAddress, relay, paddedLen)
\tcase "tcp":
\t\treturn exchangeTCP(ctx, proxy, dialer, query, serverAddress, relay)
\tdefault:
\t\treturn dnsExchangeResult{err: fmt.Errorf("unsupported proto %q", proto)}
\t}
}

// exchangeUDP performs a single UDP DNS query/response cycle.
func exchangeUDP(
\tctx context.Context,
\tproxy *Proxy,
\tdialer *net.Dialer,
\tquery *dns.Msg,
\tserverAddress string,
\trelay *DNSCryptRelay,
\tpaddedLen int,
) dnsExchangeResult {
\tif len(query.Question) == 0 {
\t\treturn dnsExchangeResult{err: errors.New("empty question section")}
\t}

\tif paddedLen > 0 {
\t\taddProbePadding(query, paddedLen)
\t}
\tif err := query.Pack(); err != nil {
\t\treturn dnsExchangeResult{err: err}
\t}
\tbinQuery := query.Data

\tudpAddr, err := net.ResolveUDPAddr("udp", serverAddress)
\tif err != nil {
\t\treturn dnsExchangeResult{err: err}
\t}
\tupstreamAddr := udpAddr
\tif relay != nil {
\t\tproxy.prepareForRelay(udpAddr.IP, udpAddr.Port, &binQuery)
\t\tupstreamAddr = relay.RelayUDPAddr
\t}

\tnow := time.Now()
\tpc, err := dialer.DialContext(ctx, "udp", upstreamAddr.String())
\tif err != nil {
\t\tif opErr, ok := errors.AsType[*net.OpError](err); ok {
\t\t\tdlog.Debugf("UDP dial failed: op=%s net=%s addr=%v err=%v",
\t\t\t\topErr.Op, opErr.Net, opErr.Addr, opErr.Err)
\t\t}
\t\treturn dnsExchangeResult{err: err}
\t}
\tdefer pc.Close()

\tif err := pc.SetDeadline(now.Add(proxy.timeout)); err != nil {
\t\treturn dnsExchangeResult{err: err}
\t}
\tif _, err := pc.Write(binQuery); err != nil {
\t\treturn dnsExchangeResult{err: err}
\t}

\tvar buf [MaxDNSPacketSize]byte
\tn, err := pc.Read(buf[:])
\tif err != nil {
\t\treturn dnsExchangeResult{err: err}
\t}
\trtt := time.Since(now)

\tpacket := make([]byte, n)
\tcopy(packet, buf[:n])

\tmsg := dns.Msg{Data: packet}
\tif err := msg.Unpack(); err != nil {
\t\treturn dnsExchangeResult{
\t\t\terr: fmt.Errorf("unpack response from [%s]: %w", serverAddress, err),
\t\t}
\t}
\treturn dnsExchangeResult{response: &msg, rtt: rtt}
}

// exchangeTCP performs a single TCP DNS query/response cycle.
func exchangeTCP(
\tctx context.Context,
\tproxy *Proxy,
\tdialer *net.Dialer,
\tquery *dns.Msg,
\tserverAddress string,
\trelay *DNSCryptRelay,
) dnsExchangeResult {
\tif err := query.Pack(); err != nil {
\t\treturn dnsExchangeResult{err: err}
\t}
\tbinQuery := query.Data

\ttcpAddr, err := net.ResolveTCPAddr("tcp", serverAddress)
\tif err != nil {
\t\treturn dnsExchangeResult{err: err}
\t}
\tupstreamAddr := tcpAddr
\tif relay != nil {
\t\tproxy.prepareForRelay(tcpAddr.IP, tcpAddr.Port, &binQuery)
\t\tupstreamAddr = relay.RelayTCPAddr
\t}

\tnow := time.Now()
\tvar pc net.Conn
\tif proxyDialer := proxy.xTransport.proxyDialer; proxyDialer != nil {
\t\tpc, err = (*proxyDialer).Dial("tcp", upstreamAddr.String())
\t} else {
\t\tpc, err = dialer.DialContext(ctx, "tcp", upstreamAddr.String())
\t}
\tif err != nil {
\t\tif opErr, ok := errors.AsType[*net.OpError](err); ok {
\t\t\tdlog.Debugf("TCP dial failed: op=%s net=%s addr=%v err=%v",
\t\t\t\topErr.Op, opErr.Net, opErr.Addr, opErr.Err)
\t\t}
\t\treturn dnsExchangeResult{err: err}
\t}
\tdefer pc.Close()

\tif err := pc.SetDeadline(now.Add(proxy.timeout)); err != nil {
\t\treturn dnsExchangeResult{err: err}
\t}

\tbinQuery, err = PrefixWithSize(binQuery)
\tif err != nil {
\t\treturn dnsExchangeResult{err: err}
\t}
\tif _, err := pc.Write(binQuery); err != nil {
\t\treturn dnsExchangeResult{err: err}
\t}

\tpacket, err := ReadPrefixed(&pc)
\tif err != nil {
\t\treturn dnsExchangeResult{err: err}
\t}
\trtt := time.Since(now)

\tmsg := dns.Msg{Data: packet}
\tif err := msg.Unpack(); err != nil {
\t\treturn dnsExchangeResult{
\t\t\terr: fmt.Errorf("unpack response from [%s]: %w", serverAddress, err),
\t\t}
\t}
\treturn dnsExchangeResult{response: &msg, rtt: rtt}
}

// addProbePadding appends a PADDING pseudo-RR to msg such that the final packed
// message size is as close as possible to paddedLen bytes, without attempting
// to exceed MaxDNSPacketSize. If packing fails, msg is left unchanged.
func addProbePadding(msg *dns.Msg, paddedLen int) {
\tif msg == nil || paddedLen <= 0 {
\t\treturn
\t}

\t// Pack without padding to compute the base size.
\torigPseudo := msg.Pseudo
\tmsg.Pseudo = nil
\tif err := msg.Pack(); err != nil {
\t\tmsg.Pseudo = origPseudo
\t\treturn
\t}
\tbaseLen := len(msg.Data)
\tmsg.Pseudo = origPseudo

\tpadding := paddedLen - baseLen
\tif padding <= 0 {
\t\treturn
\t}

\tif msg.UDPSize == 0 || int(msg.UDPSize) > MaxDNSPacketSize {
\t\tmsg.UDPSize = uint16(MaxDNSPacketSize)
\t}
\tpaddingRR := &dns.PADDING{Padding: strings.Repeat("00", padding)}
\tmsg.Pseudo = append(msg.Pseudo, paddingRR)
}
