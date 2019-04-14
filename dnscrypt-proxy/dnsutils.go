package main

import (
	"encoding/binary"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func TruncatedResponse(packet []byte) ([]byte, error) {
	srcMsg := new(dns.Msg)
	if err := srcMsg.Unpack(packet); err != nil {
		return nil, err
	}
	dstMsg := srcMsg
	dstMsg.Response = true
	dstMsg.Answer = make([]dns.RR, 0)
	dstMsg.Ns = make([]dns.RR, 0)
	dstMsg.Extra = make([]dns.RR, 0)
	dstMsg.Truncated = true
	return dstMsg.Pack()
}

func EmptyResponseFromMessage(srcMsg *dns.Msg) (*dns.Msg, error) {
	dstMsg := srcMsg
	dstMsg.Response = true
	dstMsg.Answer = make([]dns.RR, 0)
	dstMsg.Ns = make([]dns.RR, 0)
	dstMsg.Extra = make([]dns.RR, 0)
	return dstMsg, nil
}

func RefusedResponseFromMessage(srcMsg *dns.Msg, refusedCode bool) (*dns.Msg, error) {
	dstMsg, err := EmptyResponseFromMessage(srcMsg)
	if err != nil {
		return dstMsg, err
	}
	if refusedCode {
		dstMsg.Rcode = dns.RcodeRefused
	} else {
		dstMsg.Rcode = dns.RcodeSuccess
		questions := srcMsg.Question
		if len(questions) > 0 {
			hinfo := new(dns.HINFO)
			hinfo.Hdr = dns.RR_Header{Name: questions[0].Name, Rrtype: dns.TypeHINFO,
				Class: dns.ClassINET, Ttl: 1}
			hinfo.Cpu = "This query has been locally blocked"
			hinfo.Os = "by dnscrypt-proxy"
			dstMsg.Answer = []dns.RR{hinfo}
		}
	}
	return dstMsg, nil
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

func NormalizeName(name *[]byte) {
	for i, c := range *name {
		if c >= 65 && c <= 90 {
			(*name)[i] = c + 32
		}
	}
}

func StripTrailingDot(str string) string {
	if len(str) > 1 && strings.HasSuffix(str, ".") {
		str = str[:len(str)-1]
	}
	return str
}

func updateMsgTTLs(msg *dns.Msg, minTTL uint32, maxTTL uint32, cacheNegMinTTL uint32, cacheNegMaxTTL uint32) {
	if (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) || (len(msg.Answer) <= 0 && len(msg.Ns) <= 0) {
		return
	}

	var ttl uint32

	if len(msg.Answer) > 0 {
		for _, rr := range msg.Answer {
			if msg.Rcode == dns.RcodeSuccess {
				ttl = uint32(maxTTL)
			} else {
				ttl = uint32(cacheNegMaxTTL)
			}
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
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
			rr.Header().Ttl = ttl
		}
	}

	for _, rr := range msg.Ns {
		if msg.Rcode == dns.RcodeSuccess {
			ttl = uint32(maxTTL)
		} else {
			ttl = uint32(cacheNegMaxTTL)
		}
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
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
		rr.Header().Ttl = ttl
	}
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

func updateTTLs(msg *dns.Msg, since time.Time)  {

	ttl := uint32( time.Now().Sub( since ).Seconds() )

	for _, rr := range msg.Answer {
		rr.Header().Ttl -= ttl
	}
	for _, rr := range msg.Ns {
		rr.Header().Ttl -= ttl
	}

}
