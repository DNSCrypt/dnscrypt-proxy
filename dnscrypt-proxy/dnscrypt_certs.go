package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
	"golang.org/x/crypto/ed25519"
)

type CertInfo struct {
	ServerPk           [32]byte
	SharedKey          [32]byte
	MagicQuery         [ClientMagicLen]byte
	CryptoConstruction CryptoConstruction
	ForwardSecurity    bool
	PqPublicKey        []byte
	PqCertContext      []byte
}

func FetchCurrentDNSCryptCert(
	proxy *Proxy,
	serverName *string,
	proto string,
	pk ed25519.PublicKey,
	serverAddress string,
	providerName string,
	isNew bool,
	relay *DNSCryptRelay,
	knownBugs ServerBugs,
) (CertInfo, int, bool, error) {
	if len(pk) != ed25519.PublicKeySize {
		return CertInfo{}, 0, false, errors.New("Invalid public key length")
	}
	if !strings.HasSuffix(providerName, ".") {
		providerName += "."
	}
	if serverName == nil {
		serverName = &providerName
	}
	query := dns.NewMsg(providerName, dns.TypeTXT)
	if !strings.HasPrefix(providerName, "2.dnscrypt-cert.") {
		if relay != nil && !proxy.anonDirectCertFallback {
			dlog.Warnf(
				"[%v] uses a non-standard provider name, enable direct cert fallback to use with a relay ('%v' doesn't start with '2.dnscrypt-cert.')",
				*serverName,
				providerName,
			)
		} else {
			dlog.Warnf("[%v] uses a non-standard provider name ('%v' doesn't start with '2.dnscrypt-cert.')", *serverName, providerName)
			relay = nil
		}
	}
	tryFragmentsSupport := true
	if knownBugs.fragmentsBlocked {
		tryFragmentsSupport = false
	}
	in, rtt, fragmentsBlocked, err := DNSExchange(
		proxy,
		proto,
		query,
		serverAddress,
		relay,
		serverName,
		tryFragmentsSupport,
	)
	if err != nil {
		dlog.Noticef("[%s] TIMEOUT", *serverName)
		return CertInfo{}, 0, fragmentsBlocked, err
	}
	if in.Truncated && proto != "tcp" {
		dlog.Debugf("[%v] certificate response was truncated, retrying over TCP", *serverName)
		if inTCP, rttTCP, _, errTCP := DNSExchange(
			proxy,
			"tcp",
			query,
			serverAddress,
			relay,
			serverName,
			false,
		); errTCP == nil {
			in, rtt = inTCP, rttTCP
		}
	}
	now := uint32(time.Now().Unix())
	certInfo := CertInfo{CryptoConstruction: UndefinedConstruction}
	highestSerial := uint32(0)
	certCountStr := ""
	for _, answerRr := range in.Answer {
		var txt string
		if t, ok := answerRr.(*dns.TXT); !ok {
			dlog.Noticef("[%v] Extra record of type [%v] found in certificate", *serverName, dns.RRToType(answerRr))
			continue
		} else {
			txt = strings.Join(t.Txt, "")
		}
		binCert := PackTXTRR(txt)
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
			dlog.Noticef("[%v] should upgrade to XChaCha20 for encryption", *serverName)
		case 0x0002:
			cryptoConstruction = XChacha20Poly1305
		case 0x0003:
			cryptoConstruction = XWingPQ
		default:
			dlog.Debugf("[%v] uses an unsupported encryption system", *serverName)
			continue
		}
		isPQ := cryptoConstruction == XWingPQ
		if isPQ && !proxy.pqDNSCrypt {
			dlog.Debugf("[%v] ignoring post-quantum certificate, disabled in the configuration", *serverName)
			continue
		}
		if isPQ && len(binCert) < 1320 {
			dlog.Warnf("[%v] PQ certificate too short", *serverName)
			continue
		}
		signature := binCert[8:72]
		signed := binCert[72:]
		if !ed25519.Verify(pk, signed, signature) {
			dlog.Warnf("[%v] Incorrect signature for provider name: [%v]", *serverName, providerName)
			continue
		}
		var serialOff, tsBeginOff, tsEndOff int
		if isPQ {
			ext := binCert[1308:1320]
			if !bytes.Equal(ext, pqProfileExtension()) || !bytes.Equal(binCert[4:6], ext[4:6]) {
				dlog.Warnf("[%v] invalid PQ profile extension", *serverName)
				continue
			}
			serialOff, tsBeginOff, tsEndOff = 1296, 1300, 1304
		} else {
			serialOff, tsBeginOff, tsEndOff = 112, 116, 120
		}
		serial := binary.BigEndian.Uint32(binCert[serialOff : serialOff+4])
		tsBegin := binary.BigEndian.Uint32(binCert[tsBeginOff : tsBeginOff+4])
		tsEnd := binary.BigEndian.Uint32(binCert[tsEndOff : tsEndOff+4])
		if tsBegin >= tsEnd {
			dlog.Warnf("[%v] certificate has invalid time range: start >= end (%v >= %v)", *serverName, tsBegin, tsEnd)
			continue
		}
		ttl := tsEnd - tsBegin
		if ttl > 86400*7 {
			dlog.Infof(
				"[%v] the key validity period for this server is excessively long (%d days), significantly reducing reliability and forward security.",
				*serverName,
				ttl/86400,
			)
			daysLeft := (tsEnd - now) / 86400
			if daysLeft < 1 {
				dlog.Criticalf(
					"[%v] certificate will expire today -- Switch to a different resolver as soon as possible",
					*serverName,
				)
			} else if daysLeft <= 7 {
				dlog.Warnf("[%v] certificate is about to expire -- if you don't manage this server, tell the server operator about it", *serverName)
			} else if daysLeft <= 30 {
				dlog.Infof("[%v] certificate will expire in %d days", *serverName, daysLeft)
			} else {
				dlog.Debugf("[%v] certificate still valid for %d days", *serverName, daysLeft)
			}
		}
		if !proxy.certIgnoreTimestamp {
			if now > tsEnd || now < tsBegin {
				dlog.Debugf(
					"[%v] Certificate not valid at the current date (now: %v is not in [%v..%v])",
					*serverName,
					now,
					tsBegin,
					tsEnd,
				)
				continue
			}
		}
		if serial < highestSerial {
			dlog.Debugf("[%v] Superseded by a more recent certificate", *serverName)
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
		if cryptoConstruction != XChacha20Poly1305 && cryptoConstruction != XSalsa20Poly1305 &&
			cryptoConstruction != XWingPQ {
			dlog.Noticef("[%v] Cryptographic construction %v not supported", *serverName, cryptoConstruction)
			continue
		}
		certInfo.ForwardSecurity = ttl <= 86400*7
		if isPQ {
			certInfo.PqPublicKey = append([]byte(nil), binCert[72:1288]...)
			certInfo.PqCertContext = pqCertContext(binCert)
			certInfo.ServerPk = [32]byte{}
			certInfo.SharedKey = [32]byte{}
			copy(certInfo.MagicQuery[:], binCert[1288:1296])
		} else {
			var serverPk [32]byte
			copy(serverPk[:], binCert[72:104])
			sharedKey := proxy.computeSharedKey(cryptoConstruction, &serverPk, &providerName)
			certInfo.SharedKey = sharedKey
			certInfo.PqPublicKey = nil
			certInfo.PqCertContext = nil
			copy(certInfo.ServerPk[:], serverPk[:])
			copy(certInfo.MagicQuery[:], binCert[104:112])
		}
		highestSerial = serial
		certInfo.CryptoConstruction = cryptoConstruction
		if isNew {
			dlog.Noticef("[%s] OK (DNSCrypt) - rtt: %dms%s", *serverName, rtt.Nanoseconds()/1000000, certCountStr)
		} else {
			dlog.Infof("[%s] OK (DNSCrypt) - rtt: %dms%s", *serverName, rtt.Nanoseconds()/1000000, certCountStr)
		}
		certCountStr = " - additional certificate"
	}
	if certInfo.CryptoConstruction == UndefinedConstruction {
		return certInfo, 0, fragmentsBlocked, errors.New("No usable certificate found")
	}
	return certInfo, int(rtt.Nanoseconds() / 1000000), fragmentsBlocked, nil
}
