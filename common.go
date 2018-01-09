package main

import (
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
	InitialMinQuestionSize = 128
	TimeoutMin             = 1 * time.Second
	TimeoutMax             = 5 * time.Second
)

type ServerInfo struct {
	MagicQuery         [8]byte
	ServerPk           [32]byte
	SharedKey          [32]byte
	CryptoConstruction CryptoConstruction
	Timeout            time.Duration
	UDPAddr            *net.UDPAddr
	TCPAddr            *net.TCPAddr
}

func HasTCFlag(packet []byte) bool {
	return packet[2]&2 == 2
}
