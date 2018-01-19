package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/jedisct1/xsecretbox"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
)

type CertInfo struct {
	ServerPk           [32]byte
	SharedKey          [32]byte
	MagicQuery         [ClientMagicLen]byte
	CryptoConstruction CryptoConstruction
	ForwardSecurity    bool
}

func FetchCurrentCert(proxy *Proxy, serverName *string, proto string, pk ed25519.PublicKey, serverAddress string, providerName string) (CertInfo, int, error) {
	if len(pk) != ed25519.PublicKeySize {
		return CertInfo{}, 0, errors.New("Invalid public key length")
	}
	if !strings.HasSuffix(providerName, ".") {
		providerName = providerName + "."
	}
	query := new(dns.Msg)
	query.SetQuestion(providerName, dns.TypeTXT)
	client := dns.Client{Net: proto, UDPSize: uint16(MaxDNSUDPPacketSize)}
	in, rtt, err := client.Exchange(query, serverAddress)
	if err != nil {
		return CertInfo{}, 0, err
	}
	now := uint32(time.Now().Unix())
	certInfo := CertInfo{CryptoConstruction: UndefinedConstruction}
	highestSerial := uint32(0)
	for _, answerRr := range in.Answer {
		binCert, err := packTxtString(strings.Join(answerRr.(*dns.TXT).Txt, ""))
		if err != nil {
			dlog.Warnf("[%v] Unable to unpack the certificate", providerName)
			continue
		}
		if len(binCert) < 124 {
			dlog.Warnf("[%v] Certificate too short", providerName)
			continue
		}
		if !bytes.Equal(binCert[:4], CertMagic[:4]) {
			dlog.Warnf("[%v] Invalid cert magic", providerName)
			continue
		}
		cryptoConstruction := CryptoConstruction(0)
		switch esVersion := binary.BigEndian.Uint16(binCert[4:6]); esVersion {
		case 0x0001:
			cryptoConstruction = XSalsa20Poly1305
		case 0x0002:
			cryptoConstruction = XChacha20Poly1305
		default:
			dlog.Infof("[%v] Unsupported crypto construction", providerName)
			continue
		}
		signature := binCert[8:72]
		signed := binCert[72:]
		if !ed25519.Verify(pk, signed, signature) {
			dlog.Warnf("[%v] Incorrect signature", providerName)
			continue
		}
		serial := binary.BigEndian.Uint32(binCert[112:116])
		tsBegin := binary.BigEndian.Uint32(binCert[116:120])
		tsEnd := binary.BigEndian.Uint32(binCert[120:124])
		if tsBegin >= tsEnd {
			dlog.Warnf("[%v] certificate ends before it starts")
			continue
		}
		ttl := tsEnd - tsBegin
		if ttl > 86400*7 {
			dlog.Infof("[%v] the key validity period for this server is excessively long (%d days), significantly reducing reliability and forward security.", providerName, ttl/86400)
			certInfo.ForwardSecurity = false
		} else {
			certInfo.ForwardSecurity = true
		}
		if now > tsEnd || now < tsBegin {
			dlog.Debugf("[%v] Certificate not valid at the current date", providerName)
			continue
		}
		if serial < highestSerial {
			dlog.Debugf("[%v] Superseded by a previous certificate", providerName)
			continue
		}
		if serial == highestSerial {
			if cryptoConstruction < certInfo.CryptoConstruction {
				dlog.Debugf("[%v] Keeping the previous, preferred crypto construction", providerName)
				continue
			} else {
				dlog.Debugf("[%v] Upgrading the construction from %v to %v", providerName, certInfo.CryptoConstruction, cryptoConstruction)
			}
		}
		if cryptoConstruction != XChacha20Poly1305 && cryptoConstruction != XSalsa20Poly1305 {
			dlog.Warnf("[%v] Cryptographic construction %v not supported", providerName, cryptoConstruction)
			continue
		}
		var serverPk [32]byte
		copy(serverPk[:], binCert[72:104])
		var sharedKey [32]byte
		if cryptoConstruction == XChacha20Poly1305 {
			sharedKey, err = xsecretbox.SharedKey(proxy.proxySecretKey, serverPk)
			if err != nil {
				dlog.Errorf("[%v] Weak public key", providerName)
				continue
			}
		} else {
			box.Precompute(&sharedKey, &serverPk, &proxy.proxySecretKey)
		}
		certInfo.SharedKey = sharedKey
		highestSerial = serial
		certInfo.CryptoConstruction = cryptoConstruction
		copy(certInfo.ServerPk[:], serverPk[:])
		copy(certInfo.MagicQuery[:], binCert[104:112])
		if serverName == nil {
			serverName = &providerName
		}
		dlog.Noticef("[%s] OK (crypto v%d) - rtt: %dms", *serverName, cryptoConstruction, rtt.Nanoseconds()/1000000)
	}
	if certInfo.CryptoConstruction == UndefinedConstruction {
		return certInfo, 0, errors.New("No useable certificate found")
	}
	return certInfo, int(rtt.Nanoseconds() / 1000000), nil
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func dddToByte(s []byte) byte {
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

func packTxtString(s string) ([]byte, error) {
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
	return msg, nil
}
