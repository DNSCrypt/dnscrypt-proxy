package protocol

import (
	"crypto/tls"
	"fmt"
)

// PacketNumberSpace is a QUIC packet number space.
type PacketNumberSpace uint8

const (
	PacketNumberSpaceInitial PacketNumberSpace = iota
	PacketNumberSpaceHandshake
	PacketNumberSpaceAppData
)

// EncryptionLevel is the encryption level
// Default value is Unencrypted
type EncryptionLevel uint8

const (
	// EncryptionInitial is the Initial encryption level
	EncryptionInitial EncryptionLevel = 1 + iota
	// EncryptionHandshake is the Handshake encryption level
	EncryptionHandshake
	// Encryption0RTT is the 0-RTT encryption level
	Encryption0RTT
	// Encryption1RTT is the 1-RTT encryption level
	Encryption1RTT
)

func (e EncryptionLevel) String() string {
	switch e {
	case EncryptionInitial:
		return "Initial"
	case EncryptionHandshake:
		return "Handshake"
	case Encryption0RTT:
		return "0-RTT"
	case Encryption1RTT:
		return "1-RTT"
	}
	return "unknown"
}

func (e EncryptionLevel) PacketNumberSpace() PacketNumberSpace {
	switch e {
	case EncryptionInitial:
		return PacketNumberSpaceInitial
	case EncryptionHandshake:
		return PacketNumberSpaceHandshake
	case Encryption0RTT, Encryption1RTT:
		return PacketNumberSpaceAppData
	default:
		panic("invalid encryption level")
	}
}

func (e EncryptionLevel) ToTLSEncryptionLevel() tls.QUICEncryptionLevel {
	switch e {
	case EncryptionInitial:
		return tls.QUICEncryptionLevelInitial
	case EncryptionHandshake:
		return tls.QUICEncryptionLevelHandshake
	case Encryption1RTT:
		return tls.QUICEncryptionLevelApplication
	case Encryption0RTT:
		return tls.QUICEncryptionLevelEarly
	default:
		panic(fmt.Sprintf("unexpected encryption level: %s", e))
	}
}

func FromTLSEncryptionLevel(e tls.QUICEncryptionLevel) EncryptionLevel {
	switch e {
	case tls.QUICEncryptionLevelInitial:
		return EncryptionInitial
	case tls.QUICEncryptionLevelHandshake:
		return EncryptionHandshake
	case tls.QUICEncryptionLevelApplication:
		return Encryption1RTT
	case tls.QUICEncryptionLevelEarly:
		return Encryption0RTT
	default:
		panic(fmt.Sprintf("unexpect encryption level: %s", e))
	}
}
