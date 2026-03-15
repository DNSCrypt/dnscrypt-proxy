// Package main provides DNS utility functions for the DNSCrypt proxy.
//
// This file contains DNS message helpers, EDNS0 utilities, TXT packing,
// and the DNSExchange engine with fragment probing and relay support.
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

// MaxDNSPacketSize is expected to be defined elsewhere in the project.

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
func TransactionID(packet []byte) uint16 {
    if len(packet) < 2 {
        return 0
    }
    return binary.BigEndian.Uint16(packet[0:2])
}

// SetTransactionID writes a 16-bit transaction ID into a raw DNS packet.
func SetTransactionID(packet []byte, tid uint16) {
    if len(packet) < 2 {
        return
    }
    binary.BigEndian.PutUint16(packet[0:2], tid)
}

// Rcode extracts the base DNS RCODE from a raw packet.
func Rcode(packet []byte) uint8 {
    if len(packet) < 4 {
        return 0
    }
    return packet[3] & 0xf
}

// ─────────────────────────────────────── name normalisation ─────────────────

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

func NormalizeQName(str string) (string, error) {
    if len(str) == 0 || str == "." {
        return ".", nil
    }
    raw := str
    str = strings.TrimSuffix(str, ".")

    hasUpper := false
    for i := 0; i < len(str); i++ {
        c := str[i]
        if c >= utf8.RuneSelf {
            return raw, errors.New("query name is not an ASCII string")
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
        default:
            rr.Header().TTL = ttl
        }
    }
}

// ─────────────────────────────────────── EDNS0 helpers ──────────────────────

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

func removeEDNS0Padding(msg *dns.Msg) bool {
    if msg == nil || len(msg.Pseudo) == 0 {
        return false
    }
    out := msg.Pseudo[:0]
    removed := false
    for _, rr := range msg.Pseudo {
        if _, ok := rr.(*dns.PADDING); ok {
            removed = true
            continue
        }
        out = append(out, rr)
    }
    msg.Pseudo = out
    return removed
}

// ─────────────────────────────────────── TXT helpers ────────────────────────

func isDigit(b byte) bool {
    return b >= '0' && b <= '9'
}

func dddToByte(s string) (byte, bool) {
    if len(s) < 3 {
        return 0, false
    }
    b0, b1, b2 := s[0], s[1], s[2]
    if !isDigit(b0) || !isDigit(b1) || !isDigit(b2) {
        return 0, false
    }
    n := int(b0-'0')*100 + int(b1-'0')*10 + int(b2-'0')
    if n > 255 {
        return 0, false
    }
    return byte(n), true
}

func PackTXTRR(s string) []byte {
    msg := make([]byte, 0, len(s))
    for i := 0; i < len(s); i++ {
        c := s[i]
        if c != '\\' {
            msg = append(msg, c)
            continue
        }
        i++
        if i >= len(s) {
            break
        }
        if i+2 < len(s) {
            if b, ok := dddToByte(s[i : i+3]); ok {
                msg = append(msg, b)
                i += 2
                continue
            }
        }
        switch s[i] {
        case 't':
            msg = append(msg, '\t')
        case 'r':
            msg = append(msg, '
')
        case 'n':
            msg = append(msg, '
')
        default:
            msg = append(msg, s[i])
        }
    }
    return msg
}

// ─────────────────────────────────────── DNS exchange ───────────────────────

type dnsExchangeResult struct {
    response         *dns.Msg
    rtt              time.Duration
    priority         int
    fragmentsBlocked bool
    err              error
}

type ExchangeOptions struct {
    Proto              string
    ServerAddress      string
    Relay              *DNSCryptRelay
    ServerName         *string
    TryFragmentSupport bool
}

func DNSExchange(
    ctx context.Context,
    proxy *Proxy,
    query *dns.Msg,
    opts ExchangeOptions,
) (*dns.Msg, time.Duration, bool, error) {
    ctx, cancel := context.WithCancel(ctx)
    defer cancel()

    resp, rtt, fragBlocked, err := runExchange(ctx, proxy, query, opts)
    if err == nil {
        return resp, rtt, fragBlocked, nil
    }

    if opts.Relay == nil || !proxy.anonDirectCertFallback {
        return nil, 0, false, err
    }
    if opts.ServerName != nil {
        dlog.Infof(
            "Unable to get the public key for [%v] via relay [%v], retrying over a direct connection",
            *opts.ServerName,
            opts.Relay.RelayUDPAddr.IP,
        )
    }

    opts.Relay = nil
    return runExchange(ctx, proxy, query, opts)
}

func runExchange(
    ctx context.Context,
    proxy *Proxy,
    query *dns.Msg,
    opts ExchangeOptions,
) (*dns.Msg, time.Duration, bool, error) {
    ctx, cancel := context.WithCancel(ctx)
    defer cancel()

    goroutines := exchangeMaxTries
    if opts.TryFragmentSupport {
        goroutines = 2 * exchangeMaxTries
    }
    ch := make(chan dnsExchangeResult, goroutines)

    var wg sync.WaitGroup
    launched := 0

    for try := range exchangeMaxTries {
        if opts.TryFragmentSupport {
            q := query.Copy()
            q.ID += uint16(launched)
            launched++
            delay := time.Duration(try) * fragmentProbeDelay
            d := delay
            wg.Go(func() {
                waitAndExchange(
                    ctx, proxy, opts.Proto, q, opts.ServerAddress, opts.Relay,
                    fragmentProbeSize, false, 0, d, ch,
                )
            })
        }

        q := query.Copy()
        q.ID += uint16(launched)
        launched++
        delay := time.Duration(try) * safePathDelay
        d := delay
        wg.Go(func() {
            waitAndExchange(
                ctx, proxy, opts.Proto, q, opts.ServerAddress, opts.Relay,
                safePacketSize, true, 1, d, ch,
            )
        })
    }

    go func() {
        wg.Wait()
        close(ch)
    }()

    var best *dnsExchangeResult
    var lastErr error

    for res := range ch {
        if res.err != nil {
            if !errors.Is(res.err, context.Canceled) && lastErr == nil {
                lastErr = res.err
            }
            continue
        }
        if best == nil ||
            res.priority < best.priority ||
            (res.priority == best.priority && res.rtt < best.rtt) {
            best = &res
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

    if opts.ServerName != nil {
        if best.fragmentsBlocked {
            dlog.Debugf("[%v] public key retrieval succeeded but server is blocking fragments", *opts.ServerName)
        } else {
            dlog.Debugf("[%v] public key retrieval succeeded", *opts.ServerName)
        }
    }

    return best.response, best.rtt, best.fragmentsBlocked, nil
}

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
            return
        case <-t.C:
        }
    }
    select {
    case <-ctx.Done():
        return
    default:
    }

    res := exchangeDNSOnce(ctx, proxy, proto, query, serverAddress, relay, paddedLen)
    res.fragmentsBlocked = fragmentsBlocked
    res.priority = priority

    select {
    case <-ctx.Done():
        return
    case ch <- res:
    }
}

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

    switch proto {
    case "udp":
        return exchangeUDP(ctx, proxy, dialer, query, serverAddress, relay, paddedLen)
    case "tcp":
        return exchangeTCP(ctx, proxy, dialer, query, serverAddress, relay)
    default:
        return dnsExchangeResult{err: fmt.Errorf("unsupported proto %q", proto)}
    }
}

func exchangeUDP(
    ctx context.Context,
    proxy *Proxy,
    dialer *net.Dialer,
    query *dns.Msg,
    serverAddress string,
    relay *DNSCryptRelay,
    paddedLen int,
) dnsExchangeResult {
    if len(query.Question) == 0 {
        return dnsExchangeResult{err: errors.New("empty question section")}
    }

    if paddedLen > 0 {
        addProbePadding(query, paddedLen)
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
            dlog.Debugf("UDP dial failed: op=%s net=%s addr=%v err=%v",
                opErr.Op, opErr.Net, opErr.Addr, opErr.Err)
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
    n, err := pc.Read(buf[:])
    if err != nil {
        return dnsExchangeResult{err: err}
    }
    rtt := time.Since(now)

    packet := make([]byte, n)
    copy(packet, buf[:n])

    msg := dns.Msg{Data: packet}
    if err := msg.Unpack(); err != nil {
        return dnsExchangeResult{
            err: fmt.Errorf("unpack response from [%s]: %w", serverAddress, err),
        }
    }
    return dnsExchangeResult{response: &msg, rtt: rtt}
}

func exchangeTCP(
    ctx context.Context,
    proxy *Proxy,
    dialer *net.Dialer,
    query *dns.Msg,
    serverAddress string,
    relay *DNSCryptRelay,
) dnsExchangeResult {
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
            dlog.Debugf("TCP dial failed: op=%s net=%s addr=%v err=%v",
                opErr.Op, opErr.Net, opErr.Addr, opErr.Err)
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

    packet, err := ReadPrefixed(&pc)
    if err != nil {
        return dnsExchangeResult{err: err}
    }
    rtt := time.Since(now)

    msg := dns.Msg{Data: packet}
    if err := msg.Unpack(); err != nil {
        return dnsExchangeResult{
            err: fmt.Errorf("unpack response from [%s]: %w", serverAddress, err),
        }
    }
    return dnsExchangeResult{response: &msg, rtt: rtt}
}

func addProbePadding(msg *dns.Msg, paddedLen int) {
    if msg == nil || paddedLen <= 0 {
        return
    }

    origPseudo := msg.Pseudo
    msg.Pseudo = nil
    if err := msg.Pack(); err != nil {
        msg.Pseudo = origPseudo
        return
    }
    baseLen := len(msg.Data)
    msg.Pseudo = origPseudo

    padding := paddedLen - baseLen
    if padding <= 0 {
        return
    }

    if msg.UDPSize == 0 || int(msg.UDPSize) > MaxDNSPacketSize {
        msg.UDPSize = uint16(MaxDNSPacketSize)
    }
    paddingRR := &dns.PADDING{Padding: strings.Repeat("00", padding)}
    msg.Pseudo = append(msg.Pseudo, paddingRR)
}
