package main

import (
    "encoding/binary"
    "errors"
    "net"
    "net/netip"
    "strings"
    "time"
    "unicode/utf8"

    "codeberg.org/miekg/dns"
    "codeberg.org/miekg/dns/rdata"
    "github.com/jedisct1/dlog"
)

func EmptyResponseFromMessage(srcMsg *dns.Msg) *dns.Msg {
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

// TruncatedResponse - Optimized to avoid full Unpack/Pack allocations
func TruncatedResponse(packet []byte) ([]byte, error) {
    // 1. Minimum valid DNS packet size is header (12 bytes)
    if len(packet) < 12 {
        return nil, errors.New("packet too short")
    }

    // 2. Parse Question Count (QDCOUNT) to find where Question section ends
    qdCount := binary.BigEndian.Uint16(packet[4:6])

    // 3. Walk through questions to find the cut-off point
    // We only want to keep Header + Question, discarding Answer/Auth/Add.
    offset := 12
    for i := uint16(0); i < qdCount; i++ {
        // Skip domain name labels
        for {
            if offset >= len(packet) {
                return nil, errors.New("packet malformed")
            }
            labelLen := int(packet[offset])
            
            // Check for compression pointer (starts with 11xx xxxx)
            if (labelLen & 0xC0) == 0xC0 {
                // Compression pointer is 2 bytes total
                offset += 2
                break
            }
            
            // Regular label
            offset++ // consume length byte
            if labelLen == 0 {
                break // End of name (root label)
            }
            offset += labelLen
        }
        
        // Skip QTYPE (2) and QCLASS (2)
        offset += 4
    }

    if offset > len(packet) {
        return nil, errors.New("packet malformed")
    }

    // 4. Create the truncated packet
    // Copy just the needed bytes to a new slice
    newPacket := make([]byte, offset)
    copy(newPacket, packet[:offset])

    // 5. Modify Header Flags
    // Set TC bit (bit 1 of byte 2, 0-indexed) -> 0000 0010 = 0x02
    newPacket[2] |= 0x02
    // Set QR bit (Response) -> 1000 0000 = 0x80
    newPacket[2] |= 0x80

    // 6. Zero out ANCOUNT, NSCOUNT, ARCOUNT (bytes 6-11)
    // We stripped these sections, so counts must be 0
    for i := 6; i < 12; i++ {
        newPacket[i] = 0
    }

    return newPacket, nil
}

func RefusedResponseFromMessage(srcMsg *dns.Msg, refusedCode bool, ipv4 net.IP, ipv6 net.IP, ttl uint32) *dns.Msg {
    // Create an empty response based on the source message
    dstMsg := EmptyResponseFromMessage(srcMsg)

    // Add Extended DNS Error (EDE) field to pseudo section
    ede := &dns.EDE{InfoCode: dns.ExtendedErrorFiltered}
    if dstMsg.UDPSize > 0 {
        dstMsg.Pseudo = append(dstMsg.Pseudo, ede)
    }

    // Either return with refused code or a synthetic response
    if refusedCode {
        // Return a simple refused response
        dstMsg.Rcode = dns.RcodeRefused
    } else {
        // Return a synthetic response
        dstMsg.Rcode = dns.RcodeSuccess
        questions := srcMsg.Question
        if len(questions) == 0 {
            return dstMsg
        }
        question := questions[0]
        qtype := dns.RRToType(question)
        qname := question.Header().Name
        sendHInfoResponse := true

        // For A records, provide synthetic IPv4 if available
        if ipv4 != nil && qtype == dns.TypeA {
            if ip4 := ipv4.To4(); ip4 != nil {
                rr := &dns.A{
                    Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
                    A:   rdata.A{Addr: netip.AddrFrom4([4]byte(ip4))},
                }
                dstMsg.Answer = []dns.RR{rr}
                sendHInfoResponse = false
                ede.InfoCode = dns.ExtendedErrorForgedAnswer
            }
        } else if ipv6 != nil && qtype == dns.TypeAAAA {
            // For AAAA records, provide synthetic IPv6 if available
            if ip6 := ipv6.To16(); ip6 != nil {
                rr := &dns.AAAA{
                    Hdr:  dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
                    AAAA: rdata.AAAA{Addr: netip.AddrFrom16([16]byte(ip6))},
                }
                dstMsg.Answer = []dns.RR{rr}
                sendHInfoResponse = false
                ede.InfoCode = dns.ExtendedErrorForgedAnswer
            }
        }

        if sendHInfoResponse {
            hinfo := &dns.HINFO{
                Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: ttl},
                HINFO: rdata.HINFO{
                    Cpu: "This query has been locally blocked",
                    Os:  "by dnscrypt-proxy",
                },
            }
            dstMsg.Answer = []dns.RR{hinfo}
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

// NormalizeQName - Optimized for single-pass check and minimal allocation
func NormalizeQName(str string) (string, error) {
    if len(str) == 0 || str == "." {
        return ".", nil
    }
    str = strings.TrimSuffix(str, ".")
    
    // Fast path: Verify ASCII and check for uppercase in one pass
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

    // Conversion path: Direct byte manipulation
    b := []byte(str)
    for i := 0; i < len(b); i++ {
        c := b[i]
        if 'A' <= c && c <= 'Z' {
            b[i] = c + 32
        }
    }
    return string(b), nil
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

// hasEDNS0Padding - Updated signature to use *dns.Msg to avoid double unpacking
func hasEDNS0Padding(msg *dns.Msg) (bool, error) {
    // Caller must have already Unpacked the message
    for _, rr := range msg.Pseudo {
        if _, ok := rr.(*dns.PADDING); ok {
            return true, nil
        }
    }
    return false, nil
}

func addEDNS0PaddingIfNoneFound(msg *dns.Msg, unpaddedPacket []byte, paddingLen int) ([]byte, error) {
    // Enable EDNS0 if not already enabled
    if msg.UDPSize == 0 {
        msg.UDPSize = uint16(MaxDNSPacketSize)
    }
    
    // Check if padding already exists using the updated helper
    // Note: This relies on msg being fully populated/unpacked
    if exists, _ := hasEDNS0Padding(msg); exists {
        return unpaddedPacket, nil
    }

    // Add padding using efficient string repetition
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
