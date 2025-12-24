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

func TruncatedResponse(packet []byte) ([]byte, error) {
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

func setMaxTTL(msg *dns.Msg, ttl uint32) {
	for _, rr := range msg.Answer {
		if ttl < rr.Header().TTL {
			rr.Header().TTL = ttl
		}
	}
	for _, rr := range msg.Ns {
		if ttl < rr.Header().TTL {
			rr.Header().TTL = ttl
		}
	}
	for _, rr := range msg.Extra {
		if dns.RRToType(rr) == dns.TypeOPT {
			continue
		}
		if ttl < rr.Header().TTL {
			rr.Header().TTL = ttl
		}
	}
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
	// Check if padding already exists
	for _, rr := range msg.Pseudo {
		if _, ok := rr.(*dns.PADDING); ok {
			return unpaddedPacket, nil
		}
	}
	// Add padding
	padding := make([]byte, paddingLen)
	for i := range padding {
		padding[i] = 'X'
	}
	paddingRR := &dns.PADDING{Padding: string(padding)}
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
			paddingRR := &dns.PADDING{Padding: string(make([]byte, padding))}
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
		defer func(pc net.Conn) {
			if pc != nil {
				_ = pc.Close()
			}
		}(pc)
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
		defer func(pc net.Conn) {
			if pc != nil {
				_ = pc.Close()
			}
		}(pc)
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
