package main

import (
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

func HasTCFlag(packet []byte) bool {
	return packet[2]&2 == 2
}
