package main

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/jedisct1/xsecretbox"
)

const (
	NonceSize     = xsecretbox.NonceSize
	HalfNonceSize = xsecretbox.NonceSize / 2
	TagSize       = xsecretbox.TagSize
)

func pad(packet []byte, minSize int) []byte {
	packet = append(packet, 0x80)
	for len(packet) < minSize {
		packet = append(packet, 0)
	}
	return packet
}

func unpad(packet []byte) ([]byte, error) {
	for i := len(packet); ; {
		if i == 0 {
			return nil, errors.New("Invalid padding (short packet)")
		}
		i--
		if packet[i] == 0x80 {
			return packet[:i], nil
		} else if packet[i] != 0x00 {
			return nil, errors.New("Invalid padding (delimiter not found)")
		}
	}
}

func (proxy *Proxy) Encrypt(serverInfo *ServerInfo, packet []byte, proto string) (encrypted []byte, clientNonce []byte, err error) {
	nonce, clientNonce := make([]byte, NonceSize), make([]byte, HalfNonceSize)
	rand.Read(clientNonce)
	copy(nonce, clientNonce)
	minQuestionSize := len(packet)
	if proto == "udp" {
		minQuestionSize = proxy.questionSizeEstimator.MinQuestionSize()
	} else {
		var xpad [1]byte
		rand.Read(xpad[:])
		minQuestionSize += int(xpad[0])
	}
	paddedLength := Min((minQuestionSize+63)&^63, MaxDNSUDPPacketSize-1)
	if paddedLength <= 0 || len(packet) >= paddedLength {
		err = errors.New("Question too large; cannot be padded")
		return
	}
	encrypted = append(serverInfo.MagicQuery[:], proxy.proxyPublicKey[:]...)
	encrypted = append(encrypted, nonce[:HalfNonceSize]...)
	encrypted = xsecretbox.Seal(encrypted, nonce, pad(packet, paddedLength), serverInfo.SharedKey[:])
	return
}

func (proxy *Proxy) Decrypt(serverInfo *ServerInfo, encrypted []byte, nonce []byte) ([]byte, error) {
	serverMagicLen := len(ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize
	if len(encrypted) < responseHeaderLen+TagSize+int(MinDNSPacketSize) ||
		!bytes.Equal(encrypted[:serverMagicLen], ServerMagic[:]) {
		return encrypted, errors.New("Short message")
	}
	serverNonce := encrypted[serverMagicLen:responseHeaderLen]
	if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
		return encrypted, errors.New("Unexpected nonce")
	}
	packet, err := xsecretbox.Open(nil, serverNonce, encrypted[responseHeaderLen:], serverInfo.SharedKey[:])
	if err != nil {
		return encrypted, errors.New("Incorrect tag")
	}
	packet, err = unpad(packet)
	if err != nil || len(packet) < MinDNSPacketSize {
		return encrypted, errors.New("Incorrect padding")
	}
	return packet, nil
}
