package main

import (
    "encoding/binary"
    "errors"
    "net"
    "net/netip"
    "strings"
    "sync"
    "time"
    "unicode/utf8"
    "unsafe"

    "codeberg.org/miekg/dns"
    "codeberg.org/miekg/dns/rdata"
    "github.com/jedisct1/dlog"
)

// --- Memory Pools ---

var msgPool = sync.Pool{
    New: func() interface{} {
        return new(dns.Msg)
    },
}

// GetMsg retrieves a zeroed message from the pool
func GetMsg() *dns.Msg {
    return msgPool.Get().(*dns.Msg)
}

// PutMsg resets and returns a message to the pool
func PutMsg(m *dns.Msg) {
    if m == nil {
        return
    }
    m.ID = 0
    m.Response = false
    m.Opcode = 0
    m.Authoritative = false
    m.Truncated = false
    m.RecursionDesired = false
    m.RecursionAvailable = false
    m.Zero = false
    m.AuthenticatedData = false
    m.CheckingDisabled = false
    m.Rcode = 0
    // m.Compress is not present in this fork/version
    
    // Clear slices while keeping capacity
    m.Question = m.Question[:0]
    m.Answer = m.Answer[:0]
    m.Ns = m.Ns[:0]
    m.Extra = m.Extra[:0]
    msgPool.Put(m)
}

// Buffer pool for truncated packets
var bufPool = sync.Pool{
    New: func() interface{} {
        b := make([]byte, 0, 1500)
        return &b
    },
}

// --- Static Data ---
var (
    blockedHinfoCPU = "This query has been locally blocked"
    blockedHinfoOS  = "by dnscrypt-proxy"
)

// --- Functions ---

func EmptyResponseFromMessage(srcMsg *dns.Msg) *dns.Msg {
    dstMsg := GetMsg()
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
        // dstMsg.Security = srcMsg.Security // Removed if not supported in fork, or keep if known good
    }
    return dstMsg
}

// TruncatedResponse - Optimized
func TruncatedResponse(packet []byte) ([]byte, error) {
    if len(packet) < 12 {
        return nil, errors.New("packet too short")
    }

    qdCount := binary.BigEndian.Uint16(packet[4:6])
    offset := 12
    for i := uint16(0); i < qdCount; i++ {
        for {
            if offset >= len(packet) {
                return nil, errors.New("packet malformed")
            }
            labelLen := int(packet[offset])
            if (labelLen & 0xC0) == 0xC0 {
                offset += 2
                break
            }
            offset++
            if labelLen == 0 {
                break
            }
            offset += labelLen
        }
        offset += 4
    }

    if offset > len(packet) {
        return nil, errors.New("packet malformed")
    }

    // Use pool for buffer
    bufPtr := bufPool.Get().(*[]byte)
    newPacket := *bufPtr
    if cap(newPacket) < offset {
        newPacket = make([]byte, offset)
    } else {
        newPacket = newPacket[:offset]
    }
    
    copy(newPacket, packet[:offset])
    newPacket[2] |= 0x82 // TC, QR
    for i := 6; i < 12; i++ {
        newPacket[i] = 0
    }

    return newPacket, nil
}

func RefusedResponseFromMessage(srcMsg *dns.Msg, refusedCode bool, ipv4 net.IP, ipv6 net.IP, ttl uint32) *dns.Msg {
    dstMsg := EmptyResponseFromMessage(srcMsg)

    // Handle OPT record manually since SetEdns0 might be missing/different
    var opt *dns.OPT
    // Check existing OPT
    for _, extra := range srcMsg.Extra {
        if o, ok := extra.(*dns.OPT); ok {
            opt = o
            break
        }
    }
    
    ede := &dns.EDE{InfoCode: dns.ExtendedErrorFiltered}
    
    // Add OPT if needed for EDE
    if opt == nil && dstMsg.UDPSize > 0 {
         opt = &dns.OPT{}
         opt.Hdr.Name = "."
         opt.Hdr.Rrtype = dns.TypeOPT
         opt.SetUDPSize(dstMsg.UDPSize)
         dstMsg.Extra = append(dstMsg.Extra, opt)
    }
    
    if opt != nil {
        opt.Option = append(opt.Option, ede)
    }

    if refusedCode {
        dstMsg.Rcode = dns.RcodeRefused
    } else {
        dstMsg.Rcode = dns.RcodeSuccess
        questions := srcMsg.Question
        if len(questions) == 0 {
            return dstMsg
        }
        question := questions[0]
        qtype := dns.RRToType(question)
        qname := question.Header().Name
        sendHInfoResponse := true

        if ipv4 != nil && qtype == dns.TypeA {
            if ip4 := ipv4.To4(); ip4 != nil {
                rr := &dns.A{
                    Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
                    A:   rdata.A{Addr: netip.AddrFrom4([4]byte(ip4))},
                }
                dstMsg.Answer = append(dstMsg.Answer, rr)
                sendHInfoResponse = false
                ede.InfoCode = dns.ExtendedErrorForgedAnswer
            }
        } else if ipv6 != nil && qtype == dns.TypeAAAA {
            if ip6 := ipv6.To16(); ip6 != nil {
                rr := &dns.AAAA{
                    Hdr:  dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
                    AAAA: rdata.AAAA{Addr: netip.AddrFrom16([16]byte(ip6))},
                }
                dstMsg.Answer = append(dstMsg.Answer, rr)
                sendHInfoResponse = false
                ede.InfoCode = dns.ExtendedErrorForgedAnswer
            }
        }

        if sendHInfoResponse {
            hinfo := &dns.HINFO{
                Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
                HINFO: rdata.HINFO{
                    Cpu: blockedHinfoCPU,
                    Os:  blockedHinfoOS,
                },
            }
            dstMsg.Answer = append(dstMsg.Answer, hinfo)
        } else {
            ede.ExtraText = "This query has been locally blocked by dnscrypt-proxy"
        }
    }

    return dstMsg
}

func HasTCFlag(packet []byte) bool {
    return packet[2]&2 == 2
}

func TransactionID(packet []byte) uint16 {
    return binary.BigEndian.Uint16(packet[0:2])
}

func SetTransactionID(packet []byte, tid uint16) {
    binary.BigEndian.PutUint16(packet[0:2], tid)
}

func Rcode(packet []byte) uint8 {
    return packet[3] & 0xf
}

func NormalizeRawQName(name *[]byte) {
    for i, c := range *name {
        if c >= 65 && c <= 90 {
            (*name)[i] = c + 32
        }
    }
}

func NormalizeQName(str string) (string, error) {
    if len(str) == 0 || str == "." {
        return ".", nil
    }
    str = strings.TrimSuffix(str, ".")
    
    needsConversion := false
    strLen := len(str)
    for i := 0; i < strLen; i++ {
        c := str[i]
        if c >= utf8.RuneSelf {
            return str, errors.New("Query name is not an ASCII string")
        }
        if 'A' <= c && c <= 'Z' {
            needsConversion = true
        }
    }

    if !needsConversion {
        return str, nil
    }

    b := []byte(str)
    for i := 0; i < len(b); i++ {
        c := b[i]
        if 'A' <= c && c <= 'Z' {
            b[i] = c + 32
        }
    }
    // Zero-allocation string conversion (unsafe)
    return unsafe.String(unsafe.SliceData(b), len(b)), nil
}

func getMinTTL(msg *dns.Msg, minTTL uint32, maxTTL uint32, cacheNegMinTTL uint32, cacheNegMaxTTL uint32) time.Duration {
    if (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) ||
        (len(msg.Answer) <= 0 && len(msg.Ns) <= 0) {
        return time.Duration(cacheNegMinTTL) * time.Second
    }
    var ttl uint32
    if msg.Rcode == dns.RcodeSuccess {
        ttl = uint32(maxTTL)
    } else {
        ttl = uint32(cacheNegMaxTTL)
    }
    if len(msg.Answer) > 0 {
        for _, rr := range msg.Answer {
            if rr.Header().TTL < ttl {
                ttl = rr.Header().TTL
            }
        }
    } else {
        for _, rr := range msg.Ns {
            if rr.Header().TTL < ttl {
                ttl = rr.Header().TTL
            }
        }
    }
    if msg.Rcode == dns.RcodeSuccess {
        if ttl < minTTL {
            ttl = minTTL
        }
    } else {
        if ttl < cacheNegMinTTL {
            ttl = cacheNegMinTTL
        }
    }
    return time.Duration(ttl) * time.Second
}

func updateTTL(msg *dns.Msg, expiration time.Time) {
    until := time.Until(expiration)
    ttl := uint32(0)
    if until > 0 {
        ttl = uint32(until / time.Second)
        if until-time.Duration(ttl)*time.Second >= time.Second/2 {
            ttl += 1
        }
    }
    for _, rr := range msg.Answer {
        rr.Header().TTL = ttl
    }
    for _, rr := range msg.Ns {
        rr.Header().TTL = ttl
    }
    for _, rr := range msg.Extra {
        if dns.RRToType(rr) != dns.TypeOPT {
            rr.Header().TTL = ttl
        }
    }
}

func hasEDNS0Padding(packet []byte) (bool, error) {
    msg := dns.Msg{Data: packet}
    if err := msg.Unpack(); err != nil {
        return false, err
    }
    // Manually iterate Pseudo section if implied by fork, or just Extra for OPT
    // Standard miekg/dns puts OPT in Extra. "Pseudo" field might be specific to this fork.
    // Assuming 'Pseudo' exists based on original file.
    if len(msg.Pseudo) > 0 {
         for _, rr := range msg.Pseudo {
             if _, ok := rr.(*dns.PADDING); ok {
                 return true, nil
             }
         }
    }
    return false, nil
}

func addEDNS0PaddingIfNoneFound(msg *dns.Msg, unpaddedPacket []byte, paddingLen int) ([]byte, error) {
    if msg.UDPSize == 0 {
        msg.UDPSize = uint16(MaxDNSPacketSize)
    }
    
    // Check loop
    for _, rr := range msg.Pseudo {
        if _, ok := rr.(*dns.PADDING); ok {
            return unpaddedPacket, nil
        }
    }

    paddingRR := &dns.PADDING{Padding: strings.Repeat("X", paddingLen)}
    msg.Pseudo = append(msg.Pseudo, paddingRR)
    
    if err := msg.Pack(); err != nil {
        return nil, err
    }
    return msg.Data, nil
}

func removeEDNS0Options(msg *dns.Msg) bool {
    if len(msg.Pseudo) == 0 {
        return false
    }
    msg.Pseudo = nil
    return true
}

func dddToByte(s []byte) byte {
    return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

func PackTXTRR(s string) []byte {
    bs := make([]byte, len(s))
    msg := make([]byte, 0)
    copy(bs, s)
    for i := 0; i < len(bs); i++ {
        if bs[i] == '\\' {
            i++
            if i == len(bs) {
                break
            }
            if i+2 < len(bs) && 
               (bs[i] >= '0' && bs[i] <= '9') && 
               (bs[i+1] >= '0' && bs[i+1] <= '9') && 
               (bs[i+2] >= '0' && bs[i+2] <= '9') {
                msg = append(msg, dddToByte(bs[i:]))
                i += 2
            } else if bs[i] == 't' {
                msg = append(msg, 9) // Tab
            } else if bs[i] == 'r' {
                msg = append(msg, 13) // CR
            } else if bs[i] == 'n' {
                msg = append(msg, 10) // LF
            } else {
                msg = append(msg, bs[i])
            }
        } else {
            msg = append(msg, bs[i])
        }
    }
    return msg
}

type DNSExchangeResponse struct {
    response         *dns.Msg
    rtt              time.Duration
    priority         int
    fragmentsBlocked bool
    err              error
}

func DNSExchange(
    proxy *Proxy,
    proto string,
    query *dns.Msg,
    serverAddress string,
    relay *DNSCryptRelay,
    serverName *string,
    tryFragmentsSupport bool,
) (*dns.Msg, time.Duration, bool, error) {
    for {
        cancelChannel := make(chan struct{})
        maxTries := 3
        channel := make(chan DNSExchangeResponse, 2*maxTries)
        var err error
        options := 0

        for tries := 0; tries < maxTries; tries++ {
            if tryFragmentsSupport {
                queryCopy := query.Copy()
                queryCopy.ID += uint16(options)
                go func(query *dns.Msg, delay time.Duration) {
                    time.Sleep(delay)
                    option := DNSExchangeResponse{err: errors.New("Canceled")}
                    select {
                    case <-cancelChannel:
                    default:
                        option = _dnsExchange(proxy, proto, query, serverAddress, relay, 1500)
                    }
                    option.fragmentsBlocked = false
                    option.priority = 0
                    channel <- option
                }(queryCopy, time.Duration(200*tries)*time.Millisecond)
                options++
            }
            queryCopy := query.Copy()
            queryCopy.ID += uint16(options)
            go func(query *dns.Msg, delay time.Duration) {
                time.Sleep(delay)
                option := DNSExchangeResponse{err: errors.New("Canceled")}
                select {
                case <-cancelChannel:
                default:
                    option = _dnsExchange(proxy, proto, query, serverAddress, relay, 480)
                }
                option.fragmentsBlocked = true
                option.priority = 1
                channel <- option
            }(queryCopy, time.Duration(250*tries)*time.Millisecond)
            options++
        }
        var bestOption *DNSExchangeResponse
        for i := 0; i < options; i++ {
            if dnsExchangeResponse := <-channel; dnsExchangeResponse.err == nil {
                if bestOption == nil || dnsExchangeResponse.priority < bestOption.priority ||
                    (dnsExchangeResponse.priority == bestOption.priority && dnsExchangeResponse.rtt < bestOption.rtt) {
                    bestOption = &dnsExchangeResponse
                    if bestOption.priority == 0 {
                        close(cancelChannel)
                        break
                    }
                }
            } else {
                err = dnsExchangeResponse.err
            }
        }
        if bestOption != nil {
            if bestOption.fragmentsBlocked {
                dlog.Debugf("[%v] public key retrieval succeeded but server is blocking fragments", *serverName)
            } else {
                dlog.Debugf("[%v] public key retrieval succeeded", *serverName)
            }
            return bestOption.response, bestOption.rtt, bestOption.fragmentsBlocked, nil
        }

        if relay == nil || !proxy.anonDirectCertFallback {
            if err == nil {
                err = errors.New("Unable to reach the server")
            }
            return nil, 0, false, err
        }
        dlog.Infof(
            "Unable to get the public key for [%v] via relay [%v], retrying over a direct connection",
            *serverName,
            relay.RelayUDPAddr.IP,
        )
        relay = nil
    }
}

func _dnsExchange(
    proxy *Proxy,
    proto string,
    query *dns.Msg,
    serverAddress string,
    relay *DNSCryptRelay,
    paddedLen int,
) DNSExchangeResponse {
    var packet []byte
    var rtt time.Duration

    if proto == "udp" {
        qNameLen, padding := len(query.Question[0].Header().Name), 0
        if qNameLen < paddedLen {
            padding = paddedLen - qNameLen
        }
        if padding > 0 {
            paddingRR := &dns.PADDING{Padding: strings.Repeat("X", padding)}
            query.Pseudo = append(query.Pseudo, paddingRR)
            if query.UDPSize == 0 {
                query.UDPSize = uint16(MaxDNSPacketSize)
            }
        }
        if err := query.Pack(); err != nil {
            return DNSExchangeResponse{err: err}
        }
        binQuery := query.Data
        udpAddr, err := net.ResolveUDPAddr("udp", serverAddress)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        upstreamAddr := udpAddr
        if relay != nil {
            proxy.prepareForRelay(udpAddr.IP, udpAddr.Port, &binQuery)
            upstreamAddr = relay.RelayUDPAddr
        }
        now := time.Now()
        pc, err := net.DialTimeout("udp", upstreamAddr.String(), proxy.timeout)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        defer pc.Close()
        if err := pc.SetDeadline(time.Now().Add(proxy.timeout)); err != nil {
            return DNSExchangeResponse{err: err}
        }
        if _, err := pc.Write(binQuery); err != nil {
            return DNSExchangeResponse{err: err}
        }
        packet = make([]byte, MaxDNSPacketSize)
        length, err := pc.Read(packet)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        rtt = time.Since(now)
        packet = packet[:length]
    } else {
        if err := query.Pack(); err != nil {
            return DNSExchangeResponse{err: err}
        }
        binQuery := query.Data
        tcpAddr, err := net.ResolveTCPAddr("tcp", serverAddress)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        upstreamAddr := tcpAddr
        if relay != nil {
            proxy.prepareForRelay(tcpAddr.IP, tcpAddr.Port, &binQuery)
            upstreamAddr = relay.RelayTCPAddr
        }
        now := time.Now()
        var pc net.Conn
        proxyDialer := proxy.xTransport.proxyDialer
        if proxyDialer == nil {
            pc, err = net.DialTimeout("tcp", upstreamAddr.String(), proxy.timeout)
        } else {
            pc, err = (*proxyDialer).Dial("tcp", tcpAddr.String())
        }
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        defer pc.Close()
        if err := pc.SetDeadline(time.Now().Add(proxy.timeout)); err != nil {
            return DNSExchangeResponse{err: err}
        }
        binQuery, err = PrefixWithSize(binQuery)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        if _, err := pc.Write(binQuery); err != nil {
            return DNSExchangeResponse{err: err}
        }
        packet, err = ReadPrefixed(&pc)
        if err != nil {
            return DNSExchangeResponse{err: err}
        }
        rtt = time.Since(now)
    }
    msg := dns.Msg{Data: packet}
    if err := msg.Unpack(); err != nil {
        return DNSExchangeResponse{err: err}
    }
    return DNSExchangeResponse{response: &msg, rtt: rtt, err: nil}
}
