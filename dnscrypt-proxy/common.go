package main

import (
	"encoding/binary"
	"errors"
	"net"
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
	MinDNSPacketSize       = 12
	MaxDNSPacketSize       = 4096
	MaxDNSUDPPacketSize    = 1252
	InitialMinQuestionSize = 256
	TimeoutMin             = 1 * time.Second
	TimeoutMax             = 5 * time.Second
	CertRefreshDelay       = 30 * time.Minute
)

func PrefixWithSize(packet []byte) ([]byte, error) {
	packet_len := len(packet)
	if packet_len > 0xffff {
		return packet, errors.New("Packet too large")
	}
	packet = append(append(packet, 0), 0)
	copy(packet[2:], packet[:len(packet)-2])
	binary.BigEndian.PutUint16(packet[0:2], uint16(len(packet)-2))
	return packet, nil
}

func ReadPrefixed(conn *net.TCPConn) ([]byte, error) {
	buf := make([]byte, 2+MaxDNSPacketSize)
	packetLength, pos := -1, 0
	for {
		readnb, err := (*conn).Read(buf[pos:])
		if err != nil {
			return buf, err
		}
		pos += readnb
		if pos >= 2 && packetLength < 0 {
			packetLength = int(binary.BigEndian.Uint16(buf[0:2]))
			if packetLength > MaxDNSPacketSize-1 {
				return buf, errors.New("Packet too large")
			}
		}
		if pos >= 2+packetLength {
			return buf[2:pos], nil
		}
	}
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
