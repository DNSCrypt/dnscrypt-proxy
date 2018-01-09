package main

import (
	"errors"
	"time"
)

type CryptoConstruction uint16

const (
	UndefinedConstruction CryptoConstruction = iota
	XSalsa20Poly1305
	XChacha20Poly1305
)

var (
	CertMagic              = [4]byte{0x44, 0x4e, 0x53, 0x43}
	ServerMagic            = [8]byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
	MinDNSPacketSize       = uint(12)
	MaxDNSPacketSize       = uint(4096)
	InitialMinQuestionSize = uint(128)
	TimeoutMin             = 1 * time.Second
	TimeoutMax             = 5 * time.Second
)

func HasTCFlag(packet []byte) bool {
	return packet[2]&2 == 2
}

func Pad(packet []byte, minSize uint) []byte {
	packet = append(packet, 0x80)
	for uint(len(packet)) < minSize {
		packet = append(packet, 0)
	}
	return packet
}

func Unpad(packet []byte) ([]byte, error) {
	i := len(packet)
	for {
		if i == 0 {
			return nil, errors.New("Invalid padding (short packet)")
		}
		i--
		if packet[i] == 0x80 {
			break
		}
		if packet[i] != 0x00 {
			return nil, errors.New("Invalid padding (delimiter not found)")
		}
	}
	return packet[:i], nil
}
