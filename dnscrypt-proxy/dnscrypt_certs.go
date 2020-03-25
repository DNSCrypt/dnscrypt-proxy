package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"
)

type CertInfo struct {
	ServerPk           [32]byte
	SharedKey          [32]byte
	MagicQuery         [ClientMagicLen]byte
	CryptoConstruction CryptoConstruction
	ForwardSecurity    bool
}

func FetchCurrentDNSCryptCert(proxy *Proxy, serverName *string, proto string, pk ed25519.PublicKey, serverAddress string, providerName string, isNew bool, relayUDPAddr *net.UDPAddr, relayTCPAddr *net.TCPAddr, knownBugs ServerBugs) (CertInfo, int, bool, error) {
	if len(pk) != ed25519.PublicKeySize {
		return CertInfo{}, 0, false, errors.New("Invalid public key length")
	}
	if !strings.HasSuffix(providerName, ".") {
		providerName = providerName + "."
	}
	if serverName == nil {
		serverName = &providerName
	}
	query := dns.Msg{}
	query.SetQuestion(providerName, dns.TypeTXT)
	if !strings.HasPrefix(providerName, "2.dnscrypt-cert.") {
		dlog.Warnf("[%v] uses a non-standard provider name ('%v' doesn't start with '2.dnscrypt-cert.')", *serverName, providerName)
		relayUDPAddr, relayTCPAddr = nil, nil
	}
	tryFragmentsSupport := true
	if knownBugs.fragmentsBlocked {
		tryFragmentsSupport = false
	}
	in, rtt, fragmentsBlocked, err := dnsExchange(proxy, proto, &query, serverAddress, relayUDPAddr, relayTCPAddr, serverName, tryFragmentsSupport)
	if err != nil {
		dlog.Noticef("[%s] TIMEOUT", *serverName)
		return CertInfo{}, 0, fragmentsBlocked, err
	}
	now := uint32(time.Now().Unix())
	certInfo := CertInfo{CryptoConstruction: UndefinedConstruction}
	highestSerial := uint32(0)
	var certCountStr string
	for _, answerRr := range in.Answer {
		var txt string
		if t, ok := answerRr.(*dns.TXT); !ok {
			dlog.Noticef("[%v] Extra record of type [%v] found in certificate", *serverName, answerRr.Header().Rrtype)
			continue
		} else {
			txt = strings.Join(t.Txt, "")
		}
		binCert := packTxtString(txt)
		if len(binCert) < 124 {
			dlog.Warnf("[%v] Certificate too short", *serverName)
			continue
		}
		if !bytes.Equal(binCert[:4], CertMagic[:4]) {
			dlog.Warnf("[%v] Invalid cert magic", *serverName)
			continue
		}
		cryptoConstruction := CryptoConstruction(0)
		switch esVersion := binary.BigEndian.Uint16(binCert[4:6]); esVersion {
		case 0x0001:
			cryptoConstruction = XSalsa20Poly1305
		case 0x0002:
			cryptoConstruction = XChacha20Poly1305
		default:
			dlog.Noticef("[%v] Unsupported crypto construction", *serverName)
			continue
		}
		signature := binCert[8:72]
		signed := binCert[72:]
		if !ed25519.Verify(pk, signed, signature) {
			dlog.Warnf("[%v] Incorrect signature for provider name: [%v]", *serverName, providerName)
			continue
		}
		serial := binary.BigEndian.Uint32(binCert[112:116])
		tsBegin := binary.BigEndian.Uint32(binCert[116:120])
		tsEnd := binary.BigEndian.Uint32(binCert[120:124])
		if tsBegin >= tsEnd {
			dlog.Warnf("[%v] certificate ends before it starts (%v >= %v)", *serverName, tsBegin, tsEnd)
			continue
		}
		ttl := tsEnd - tsBegin
		if ttl > 86400*7 {
			dlog.Infof("[%v] the key validity period for this server is excessively long (%d days), significantly reducing reliability and forward security.", *serverName, ttl/86400)
			daysLeft := (tsEnd - now) / 86400
			if daysLeft < 1 {
				dlog.Criticalf("[%v] certificate will expire today -- Switch to a different resolver as soon as possible", *serverName)
			} else if daysLeft <= 7 {
				dlog.Warnf("[%v] certificate is about to expire -- if you don't manage this server, tell the server operator about it", *serverName)
			} else if daysLeft <= 30 {
				dlog.Infof("[%v] certificate will expire in %d days", *serverName, daysLeft)
			}
			certInfo.ForwardSecurity = false
		} else {
			certInfo.ForwardSecurity = true
		}
		if !proxy.certIgnoreTimestamp {
			if now > tsEnd || now < tsBegin {
				dlog.Debugf("[%v] Certificate not valid at the current date (now: %v is not in [%v..%v])", *serverName, now, tsBegin, tsEnd)
				continue
			}
		}
		if serial < highestSerial {
			dlog.Debugf("[%v] Superseded by a previous certificate", *serverName)
			continue
		}
		if serial == highestSerial {
			if cryptoConstruction < certInfo.CryptoConstruction {
				dlog.Debugf("[%v] Keeping the previous, preferred crypto construction", *serverName)
				continue
			} else {
				dlog.Debugf("[%v] Upgrading the construction from %v to %v", *serverName, certInfo.CryptoConstruction, cryptoConstruction)
			}
		}
		if cryptoConstruction != XChacha20Poly1305 && cryptoConstruction != XSalsa20Poly1305 {
			dlog.Noticef("[%v] Cryptographic construction %v not supported", *serverName, cryptoConstruction)
			continue
		}
		var serverPk [32]byte
		copy(serverPk[:], binCert[72:104])
		sharedKey := ComputeSharedKey(cryptoConstruction, &proxy.proxySecretKey, &serverPk, &providerName)
		certInfo.SharedKey = sharedKey
		highestSerial = serial
		certInfo.CryptoConstruction = cryptoConstruction
		copy(certInfo.ServerPk[:], serverPk[:])
		copy(certInfo.MagicQuery[:], binCert[104:112])
		if isNew {
			dlog.Noticef("[%s] OK (DNSCrypt) - rtt: %dms%s", *serverName, rtt.Nanoseconds()/1000000, certCountStr)
		} else {
			dlog.Infof("[%s] OK (DNSCrypt) - rtt: %dms%s", *serverName, rtt.Nanoseconds()/1000000, certCountStr)
		}
		certCountStr = " - additional certificate"
	}
	if certInfo.CryptoConstruction == UndefinedConstruction {
		return certInfo, 0, fragmentsBlocked, errors.New("No useable certificate found")
	}
	return certInfo, int(rtt.Nanoseconds() / 1000000), fragmentsBlocked, nil
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func dddToByte(s []byte) byte {
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

func packTxtString(s string) []byte {
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

type dnsExchangeResponse struct {
	response         *dns.Msg
	rtt              time.Duration
	priority         int
	fragmentsBlocked bool
	err              error
}

func dnsExchange(proxy *Proxy, proto string, query *dns.Msg, serverAddress string, relayUDPAddr *net.UDPAddr, relayTCPAddr *net.TCPAddr, serverName *string, tryFragmentsSupport bool) (*dns.Msg, time.Duration, bool, error) {
	for {
		channel := make(chan dnsExchangeResponse)
		var err error
		options := 0

		for tries := 1; tries >= 0; tries-- {
			if tryFragmentsSupport {
				go func(query *dns.Msg, delay time.Duration) {
					time.Sleep(delay)
					option := _dnsExchange(proxy, proto, query, serverAddress, relayUDPAddr, relayTCPAddr, 1500)
					option.fragmentsBlocked = false
					option.priority = 0
					channel <- option
				}(query.Copy(), time.Duration(10*tries)*time.Millisecond)
				options++
			}
			go func(query *dns.Msg, delay time.Duration) {
				time.Sleep(delay)
				option := _dnsExchange(proxy, proto, query, serverAddress, relayUDPAddr, relayTCPAddr, 480)
				option.fragmentsBlocked = true
				option.priority = 1
				channel <- option
			}(query.Copy(), time.Duration(15*tries)*time.Millisecond)
			options++
		}
		var bestOption *dnsExchangeResponse
		for i := 0; i < options; i++ {
			if dnsExchangeResponse := <-channel; dnsExchangeResponse.err == nil {
				if bestOption == nil || dnsExchangeResponse.priority < bestOption.priority ||
					(dnsExchangeResponse.priority == bestOption.priority && dnsExchangeResponse.rtt < bestOption.rtt) {
					bestOption = &dnsExchangeResponse
					if bestOption.priority == 0 {
						break
					}
				}
			} else {
				err = dnsExchangeResponse.err
			}
		}
		if bestOption != nil {
			if bestOption.fragmentsBlocked {
				dlog.Debugf("Certificate retrieval for [%v] succeeded but server is blocking fragments", *serverName)
			} else {
				dlog.Debugf("Certificate retrieval for [%v] succeeded", *serverName)
			}
			return bestOption.response, bestOption.rtt, bestOption.fragmentsBlocked, nil
		}

		if relayUDPAddr == nil {
			if err == nil {
				err = errors.New("Unable to reach the server")
			}
			return nil, 0, false, err
		}
		dlog.Infof("Unable to get a certificate for [%v] via relay [%v], retrying over a direct connection", *serverName, relayUDPAddr.IP)
		relayUDPAddr, relayTCPAddr = nil, nil
	}
}

func _dnsExchange(proxy *Proxy, proto string, query *dns.Msg, serverAddress string, relayUDPAddr *net.UDPAddr, relayTCPAddr *net.TCPAddr, paddedLen int) dnsExchangeResponse {
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
			return dnsExchangeResponse{err: err}
		}
		udpAddr, err := net.ResolveUDPAddr("udp", serverAddress)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		upstreamAddr := udpAddr
		if relayUDPAddr != nil {
			proxy.prepareForRelay(udpAddr.IP, udpAddr.Port, &binQuery)
			upstreamAddr = relayUDPAddr
		}
		now := time.Now()
		pc, err := net.DialUDP("udp", nil, upstreamAddr)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		defer pc.Close()
		if err := pc.SetDeadline(time.Now().Add(proxy.timeout)); err != nil {
			return dnsExchangeResponse{err: err}
		}
		if _, err := pc.Write(binQuery); err != nil {
			return dnsExchangeResponse{err: err}
		}
		packet = make([]byte, MaxDNSPacketSize)
		length, err := pc.Read(packet)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		rtt = time.Since(now)
		packet = packet[:length]
	} else {
		binQuery, err := query.Pack()
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		tcpAddr, err := net.ResolveTCPAddr("tcp", serverAddress)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		upstreamAddr := tcpAddr
		if relayTCPAddr != nil {
			proxy.prepareForRelay(tcpAddr.IP, tcpAddr.Port, &binQuery)
			upstreamAddr = relayTCPAddr
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
			return dnsExchangeResponse{err: err}
		}
		defer pc.Close()
		if err := pc.SetDeadline(time.Now().Add(proxy.timeout)); err != nil {
			return dnsExchangeResponse{err: err}
		}
		binQuery, err = PrefixWithSize(binQuery)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		if _, err := pc.Write(binQuery); err != nil {
			return dnsExchangeResponse{err: err}
		}
		packet, err = ReadPrefixed(&pc)
		if err != nil {
			return dnsExchangeResponse{err: err}
		}
		rtt = time.Since(now)
	}
	msg := dns.Msg{}
	if err := msg.Unpack(packet); err != nil {
		return dnsExchangeResponse{err: err}
	}
	return dnsExchangeResponse{response: &msg, rtt: rtt, err: nil}
}
