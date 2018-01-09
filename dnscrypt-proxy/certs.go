package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/jedisct1/xsecretbox"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"
)

type CertInfo struct {
	ServerPk           [32]byte
	SharedKey          [32]byte
	MagicQuery         [8]byte
	CryptoConstruction CryptoConstruction
}

func FetchCurrentCert(proxy *Proxy, proto string, pk ed25519.PublicKey, serverAddress string, providerName string) (CertInfo, error) {
	if len(pk) != ed25519.PublicKeySize {
		return CertInfo{}, errors.New("Invalid public key length")
	}
	if !strings.HasSuffix(providerName, ".") {
		providerName = providerName + "."
	}
	query := new(dns.Msg)
	query.SetQuestion(providerName, dns.TypeTXT)
	client := dns.Client{Net: proto, UDPSize: uint16(MaxDNSUDPPacketSize)}
	in, _, err := client.Exchange(query, serverAddress)
	if err != nil {
		log.Fatal(err)
	}
	now := uint32(time.Now().Unix())
	certInfo := CertInfo{CryptoConstruction: UndefinedConstruction}
	highestSerial := uint32(0)
	for _, answerRr := range in.Answer {
		binCert, err := packTxtString(strings.Join(answerRr.(*dns.TXT).Txt, ""))
		if err != nil {
			return certInfo, err
		}
		if len(binCert) < 124 {
			return certInfo, errors.New("Certificate too short")
		}
		if !bytes.Equal(binCert[:4], CertMagic[:4]) {
			return certInfo, errors.New("Invalid cert magic")
		}
		cryptoConstruction := CryptoConstruction(0)
		switch esVersion := binary.BigEndian.Uint16(binCert[4:6]); esVersion {
		case 0x0001:
			cryptoConstruction = XSalsa20Poly1305
		case 0x0002:
			cryptoConstruction = XChacha20Poly1305
		default:
			return certInfo, errors.New("Unsupported crypto construction")
		}
		signature := binCert[8:72]
		signed := binCert[72:]
		if !ed25519.Verify(pk, signed, signature) {
			log.Fatal("Incorrect signature")
		}
		serial := binary.BigEndian.Uint32(binCert[112:116])
		tsBegin := binary.BigEndian.Uint32(binCert[116:120])
		tsEnd := binary.BigEndian.Uint32(binCert[120:124])
		if now > tsEnd || now < tsBegin {
			log.Print("Certificate not valid at the current date")
			continue
		}
		if serial < highestSerial {
			log.Print("Superseded by a previous certificate")
			continue
		}
		if serial == highestSerial && cryptoConstruction < certInfo.CryptoConstruction {
			log.Print("Keeping the previous, preferred crypto construction")
			continue
		}
		if cryptoConstruction != XChacha20Poly1305 {
			log.Printf("Cryptographic construction %v not supported\n", cryptoConstruction)
			continue
		}
		var serverPk [32]byte
		copy(serverPk[:], binCert[72:104])
		sharedKey, err := xsecretbox.SharedKey(proxy.proxySecretKey, serverPk)
		if err != nil {
			log.Print("Weak public key")
			continue
		}
		certInfo.SharedKey = sharedKey
		highestSerial = serial
		certInfo.CryptoConstruction = cryptoConstruction
		copy(certInfo.ServerPk[:], serverPk[:])
		copy(certInfo.MagicQuery[:], binCert[104:112])
		log.Printf("Valid cert found: %x\n", certInfo.ServerPk)
	}
	if certInfo.CryptoConstruction == UndefinedConstruction {
		return certInfo, errors.New("No useable certificate found")
	}
	return certInfo, nil
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
