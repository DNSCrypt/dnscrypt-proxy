package logging

import (
	"github.com/quic-go/quic-go/internal/protocol"
)

// PacketTypeFromHeader determines the packet type from a *wire.Header.
func PacketTypeFromHeader(hdr *Header) PacketType {
	if hdr.Version == 0 {
		return PacketTypeVersionNegotiation
	}
	switch hdr.Type {
	case protocol.PacketTypeInitial:
		return PacketTypeInitial
	case protocol.PacketTypeHandshake:
		return PacketTypeHandshake
	case protocol.PacketType0RTT:
		return PacketType0RTT
	case protocol.PacketTypeRetry:
		return PacketTypeRetry
	default:
		return PacketTypeNotDetermined
	}
}
