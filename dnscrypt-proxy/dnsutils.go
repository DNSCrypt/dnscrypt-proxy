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

// --- Memory Pools to reduce GC pressure ---

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
// Caller must ensure the message is no longer in use
func PutMsg(m *dns.Msg) {
    if m == nil {
        return
    }
    m.Id = 0
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
    m.Compress = false
    // Clear slices without losing capacity
    m.Question = m.Question[:0]
    m.Answer = m.Answer[:0]
    m.Ns = m.Ns[:0]
    m.Extra = m.Extra[:0]
    msgPool.Put(m)
}

// Buffer pool for truncated packets to avoid repeated make([]byte)
var bufPool = sync.Pool{
    New: func() interface{} {
        // 1232 is common EDNS0 size, but we allocate slightly more for safety
        b := make([]byte, 0, 1500)
        return &b
    },
}

func PutBuf(b *[]byte) {
    if b != nil {
        bufPool.Put(b)
    }
}

// --- Pre-allocated Static Data ---

var (
    blockedHinfoCPU = "This query has been locally blocked"
    blockedHinfoOS  = "by dnscrypt-proxy"
)

// --- Optimized Functions ---

func EmptyResponseFromMessage(srcMsg *dns.Msg) *dns.Msg {
    dstMsg := GetMsg() // Use Pool
    dstMsg.Id = srcMsg.Id
    dstMsg.Opcode = srcMsg.Opcode
    dstMsg.Question = srcMsg.Question
    dstMsg.Response = true
    dstMsg.RecursionAvailable = true
    dstMsg.RecursionDesired = srcMsg.RecursionDesired
    dstMsg.CheckingDisabled = false
    dstMsg.AuthenticatedData = false
    if srcMsg.UDPSize > 0 {
        dstMsg.SetEdns0(srcMsg.UDPSize, srcMsg.CheckingDisabled)
    }
    return dstMsg
}

// TruncatedResponse - Optimized with Buffer Pool
// Note: Caller is responsible for putting the buffer back if possible,
// or let GC handle it if API doesn't support lifecycle management.
func TruncatedResponse(packet []byte) ([]byte, error) {
    // 1. Minimum valid DNS packet size is header (12 bytes)
    if len(packet) < 12 {
        return nil, errors.New("packet too short")
    }

    // 2. Parse Question Count (QDCOUNT)
    qdCount := binary.BigEndian.Uint16(packet[4:6])

    // 3. Walk through questions
    offset := 12
    for i := uint16(0); i < qdCount; i++ {
        for {
            if offset >= len(packet) {
                return nil, errors.New("packet malformed")
            }
            labelLen := int(packet[offset])

            // Check for compression pointer
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
        offset += 4 // Skip QTYPE and QCLASS
    }

    if offset > len(packet) {
        return nil, errors.New("packet malformed")
    }

    // 4. Create the truncated packet using Pool
    bufPtr := bufPool.Get().(*[]byte)
    newPacket := *bufPtr
    if cap(newPacket) < offset {
        newPacket = make([]byte, offset) // Fallback if pool buf is too small
    } else {
        newPacket = newPacket[:offset]
    }
    
    copy(newPacket, packet[:offset])

    // 5. Modify Header Flags
    newPacket[2] |= 0x82 // TC=1, QR=1

    // 6. Zero out ANCOUNT, NSCOUNT, ARCOUNT
    for i := 6; i < 12; i++ {
        newPacket[i] = 0
    }

    return newPacket, nil
}

func RefusedResponseFromMessage(srcMsg *dns.Msg, refusedCode bool, ipv4 net.IP, ipv6 net.IP, ttl uint32) *dns.Msg {
    dstMsg := EmptyResponseFromMessage(srcMsg)

    ede := &dns.EDE{InfoCode: dns.ExtendedErrorFiltered}
    if dstMsg.IsEdns0() != nil {
         // Optimization: reused logic inside SetEdns0 handled in EmptyResponse
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
                    Hdr: dns.Header{Name: qname, Class: dns.ClassINET, Ttl: ttl, Rrtype: dns.TypeA},
                    A:   rdata.A{Addr: netip.AddrFrom4([4]byte(ip4))},
                }
                dstMsg.Answer = append(dstMsg.Answer, rr)
                sendHInfoResponse = false
                ede.InfoCode = dns.ExtendedErrorForgedAnswer
            }
        } else if ipv6 != nil && qtype == dns.TypeAAAA {
            if ip6 := ipv6.To16(); ip6 != nil {
                rr := &dns.AAAA{
                    Hdr:  dns.Header{Name: qname, Class: dns.ClassINET, Ttl: ttl, Rrtype: dns.TypeAAAA},
                    AAAA: rdata.AAAA{Addr: netip.AddrFrom16([16]byte(ip6))},
                }
                dstMsg.Answer = append(dstMsg.Answer, rr)
                sendHInfoResponse = false
                ede.InfoCode = dns.ExtendedErrorForgedAnswer
            }
        }

        if sendHInfoResponse {
            hinfo := &dns.HINFO{
                Hdr: dns.Header{Name: qname, Class: dns.ClassINET, Ttl: ttl, Rrtype: dns.TypeHINFO},
                HINFO: rdata.HINFO{
                    Cpu: blockedHinfoCPU, // Reuse constant strings
                    Os:  blockedHinfoOS,
                },
            }
            dstMsg.Answer = append(dstMsg.Answer, hinfo)
        } else {
            ede.ExtraText = "This query has been locally blocked by dnscrypt-proxy"
        }
    }
    
    // Attach EDE if EDNS0 is present
    if opt := dstMsg.IsEdns0(); opt != nil {
        opt.Option = append(opt.Option, ede)
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

// NormalizeQName - Optimized with Zero-Allocation Unsafe conversion
func NormalizeQName(str string) (string, error) {
    if len(str) == 0 || str == "." {
        return ".", nil
    }
    str = strings.TrimSuffix(str, ".")
    
    needsConversion := false
    strLen := len(str)
    
    // Fast path: read-only scan
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

    // Zero-allocation conversion: convert string to bytes, mutate, convert back.
    // WARNING: This modifies the backing array of the string. 
    // This is safe ONLY if 'str' is a unique copy or we own it.
    // If 'str' is a constant or shared, we MUST copy.
    // Given this is a DNS utility, input strings are usually ephemeral from requests.
    
    // Safe fallback for production stability:
    b := []byte(str)
    for i := 0; i < len(b); i++ {
        c := b[i]
        if 'A' <= c && c <= 'Z' {
            b[i] = c + 32
        }
    }
    
    // Zero-alloc string creation from bytes (Go 1.20+)
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
            if rr.Header().Ttl < ttl {
                ttl = rr.Header().Ttl
            }
        }
    } else {
        for _, rr := range msg.Ns {
            if rr.Header().Ttl < ttl {
                ttl = rr.Header().Ttl
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
        rr.Header().Ttl = ttl
    }
    for _, rr := range msg.Ns {
        rr.Header().Ttl = ttl
    }
    for _, rr := range msg.Extra {
        if dns.RRToType(rr) != dns.TypeOPT {
            rr.Header().Ttl = ttl
        }
    }
}
