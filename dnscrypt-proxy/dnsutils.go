package main

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/miekg/dns"
)

func EmptyResponseFromMessage(srcMsg *dns.Msg) *dns.Msg {
	dstMsg := dns.Msg{MsgHdr: srcMsg.MsgHdr, Compress: true}
	dstMsg.Question = srcMsg.Question
	dstMsg.Response = true
	if srcMsg.RecursionDesired {
		dstMsg.RecursionAvailable = true
	}
	dstMsg.RecursionDesired = false
	dstMsg.CheckingDisabled = false
	dstMsg.AuthenticatedData = false
	if edns0 := srcMsg.IsEdns0(); edns0 != nil {
		dstMsg.SetEdns0(edns0.UDPSize(), edns0.Do())
	}
	return &dstMsg
}

func TruncatedResponse(packet []byte) ([]byte, error) {
	srcMsg := dns.Msg{}
	if err := srcMsg.Unpack(packet); err != nil {
		return nil, err
	}
	dstMsg := EmptyResponseFromMessage(&srcMsg)
	dstMsg.Truncated = true
	return dstMsg.Pack()
}

func RefusedResponseFromMessage(srcMsg *dns.Msg, refusedCode bool, ipv4 net.IP, ipv6 net.IP, ttl uint32) *dns.Msg {
	dstMsg := EmptyResponseFromMessage(srcMsg)
	if refusedCode {
		dstMsg.Rcode = dns.RcodeRefused
	} else {
		dstMsg.Rcode = dns.RcodeSuccess
		questions := srcMsg.Question
		if len(questions) == 0 {
			return dstMsg
		}
		question := questions[0]
		sendHInfoResponse := true

		if ipv4 != nil && question.Qtype == dns.TypeA {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
			rr.A = ipv4.To4()
			if rr.A != nil {
				dstMsg.Answer = []dns.RR{rr}
				sendHInfoResponse = false
			}
		} else if ipv6 != nil && question.Qtype == dns.TypeAAAA {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			rr.AAAA = ipv6.To16()
			if rr.AAAA != nil {
				dstMsg.Answer = []dns.RR{rr}
				sendHInfoResponse = false
			}
		}

		if sendHInfoResponse {
			hinfo := new(dns.HINFO)
			hinfo.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeHINFO,
				Class: dns.ClassINET, Ttl: 1}
			hinfo.Cpu = "This query has been locally blocked"
			hinfo.Os = "by dnscrypt-proxy"
			dstMsg.Answer = []dns.RR{hinfo}
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
	hasUpper := false
	str = strings.TrimSuffix(str, ".")
	strLen := len(str)
	for i := 0; i < strLen; i++ {
		c := str[i]
		if c >= utf8.RuneSelf {
			return str, errors.New("Query name is not an ASCII string")
		}
		hasUpper = hasUpper || ('A' <= c && c <= 'Z')
	}
	if !hasUpper {
		return str, nil
	}
	var b strings.Builder
	b.Grow(len(str))
	for i := 0; i < strLen; i++ {
		c := str[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String(), nil
}

func getMinTTL(msg *dns.Msg, minTTL uint32, maxTTL uint32, cacheNegMinTTL uint32, cacheNegMaxTTL uint32) time.Duration {
	if (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) || (len(msg.Answer) <= 0 && len(msg.Ns) <= 0) {
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

func setMaxTTL(msg *dns.Msg, ttl uint32) {
	for _, rr := range msg.Answer {
		if ttl < rr.Header().Ttl {
			rr.Header().Ttl = ttl
		}
	}
	for _, rr := range msg.Ns {
		if ttl < rr.Header().Ttl {
			rr.Header().Ttl = ttl
		}
	}
	for _, rr := range msg.Extra {
		header := rr.Header()
		if header.Rrtype == dns.TypeOPT {
			continue
		}
		if ttl < rr.Header().Ttl {
			rr.Header().Ttl = ttl
		}
	}
}

func updateTTL(msg *dns.Msg, expiration time.Time) {
	until := time.Until(expiration)
	ttl := uint32(0)
	if until > 0 {
		ttl = uint32(until / time.Second)
	}
	for _, rr := range msg.Answer {
		rr.Header().Ttl = ttl
	}
	for _, rr := range msg.Ns {
		rr.Header().Ttl = ttl
	}
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttl
		}
	}
}

func addPaddingIfNoneFound(packet *[]byte, paddingLen int) *[]byte {
	msg := dns.Msg{Compress: true}
	if msg.Unpack(*packet) != nil {
		return packet
	}
	edns0 := msg.IsEdns0()
	if edns0 == nil {
		msg.SetEdns0(uint16(MaxDNSPacketSize), false)
		edns0 = msg.IsEdns0()
		if edns0 == nil {
			return packet
		}
	}
	for _, option := range edns0.Option {
		if option.Option() == dns.EDNS0PADDING {
			return packet
		}
	}
	ext := new(dns.EDNS0_PADDING)
	ext.Padding = make([]byte, paddingLen)
	edns0.Option = append(edns0.Option, ext)
	paddedPacket, err := msg.Pack()
	if err != nil {
		return packet
	}
	return &paddedPacket
}
