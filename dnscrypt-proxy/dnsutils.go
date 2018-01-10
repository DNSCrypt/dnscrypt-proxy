package main

import (
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

func HasTCFlag(packet []byte) bool {
	return packet[2]&2 == 2
}

func NormalizeName(name *[]byte) {
	for i, c := range *name {
		if c >= 65 && c <= 90 {
			(*name)[i] = c + 32
		}
	}
}

func getMinTTL(msg *dns.Msg, minTTL uint32, maxTTL uint32, negCacheMinTTL uint32) time.Duration {
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) <= 0 {
		return time.Duration(negCacheMinTTL) * time.Second
	}
	ttl := uint32(maxTTL)
	for _, rr := range msg.Answer {
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	if ttl < minTTL {
		ttl = minTTL
	}
	return time.Duration(ttl) * time.Second
}
