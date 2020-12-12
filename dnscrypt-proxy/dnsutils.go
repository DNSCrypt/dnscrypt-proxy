package main

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jedisct1/dlog"
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

func hasEDNS0Padding(packet []byte) (bool, error) {
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return false, err
	}
	if edns0 := msg.IsEdns0(); edns0 != nil {
		for _, option := range edns0.Option {
			if option.Option() == dns.EDNS0PADDING {
				return true, nil
			}
		}
	}
	return false, nil
}

func addEDNS0PaddingIfNoneFound(msg *dns.Msg, unpaddedPacket []byte, paddingLen int) ([]byte, error) {
	edns0 := msg.IsEdns0()
	if edns0 == nil {
		msg.SetEdns0(uint16(MaxDNSPacketSize), false)
		edns0 = msg.IsEdns0()
		if edns0 == nil {
			return unpaddedPacket, nil
		}
	}
	for _, option := range edns0.Option {
		if option.Option() == dns.EDNS0PADDING {
			return unpaddedPacket, nil
		}
	}
	ext := new(dns.EDNS0_PADDING)
	padding := make([]byte, paddingLen)
	for i := range padding {
		padding[i] = 'X'
	}
	ext.Padding = padding[:paddingLen]
	edns0.Option = append(edns0.Option, ext)
	return msg.Pack()
}

func removeEDNS0Options(msg *dns.Msg) bool {
	edns0 := msg.IsEdns0()
	if edns0 == nil {
		return false
	}
	edns0.Option = []dns.EDNS0{}
	return true
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

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
			if i+2 < len(bs) && isDigit(bs[i]) && isDigit(bs[i+1]) && isDigit(bs[i+2]) {
				msg = append(msg, dddToByte(bs[i:]))
				i += 2
			} else if bs[i] == 't' {
				msg = append(msg, '\t')
			} else if bs[i] == 'r' {
				msg = append(msg, '\r')
			} else if bs[i] == 'n' {
				msg = append(msg, '\n')
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

func DNSExchange(proxy *Proxy, proto string, query *dns.Msg, serverAddress string, relay *DNSCryptRelay, serverName *string, tryFragmentsSupport bool) (*dns.Msg, time.Duration, bool, error) {
	for {
		cancelChannel := make(chan struct{})
		channel := make(chan DNSExchangeResponse)
		var err error
		options := 0

		for tries := 0; tries < 3; tries++ {
			if tryFragmentsSupport {
				queryCopy := query.Copy()
				queryCopy.Id += uint16(options)
				go func(query *dns.Msg, delay time.Duration) {
					option := _dnsExchange(proxy, proto, query, serverAddress, relay, 1500)
					option.fragmentsBlocked = false
					option.priority = 0
					channel <- option
					time.Sleep(delay)
					select {
					case <-cancelChannel:
						return
					default:
					}
				}(queryCopy, time.Duration(200*tries)*time.Millisecond)
				options++
			}
			queryCopy := query.Copy()
			queryCopy.Id += uint16(options)
			go func(query *dns.Msg, delay time.Duration) {
				option := _dnsExchange(proxy, proto, query, serverAddress, relay, 480)
				option.fragmentsBlocked = true
				option.priority = 1
				channel <- option
				time.Sleep(delay)
				select {
				case <-cancelChannel:
					return
				default:
				}
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
		dlog.Infof("Unable to get the public key for [%v] via relay [%v], retrying over a direct connection", *serverName, relay.RelayUDPAddr.IP)
		relay = nil
	}
}

func _dnsExchange(proxy *Proxy, proto string, query *dns.Msg, serverAddress string, relay *DNSCryptRelay, paddedLen int) DNSExchangeResponse {
	var packet []byte
	var rtt time.Duration

	if proto == "udp" {
		qNameLen, padding := len(query.Question[0].Name), 0
		if qNameLen < paddedLen {
			padding = paddedLen - qNameLen
		}
		if padding > 0 {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			ext := new(dns.EDNS0_PADDING)
			ext.Padding = make([]byte, padding)
			opt.Option = append(opt.Option, ext)
			query.Extra = []dns.RR{opt}
		}
		binQuery, err := query.Pack()
		if err != nil {
			return DNSExchangeResponse{err: err}
		}
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
		pc, err := net.DialUDP("udp", nil, upstreamAddr)
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
		binQuery, err := query.Pack()
		if err != nil {
			return DNSExchangeResponse{err: err}
		}
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
			pc, err = net.DialTCP("tcp", nil, upstreamAddr)
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
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return DNSExchangeResponse{err: err}
	}
	return DNSExchangeResponse{response: &msg, rtt: rtt, err: nil}
}
