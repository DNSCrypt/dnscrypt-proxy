package wire

import (
	"errors"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

func ParseShortHeader(data []byte, connIDLen int) (length int, _ protocol.PacketNumber, _ protocol.PacketNumberLen, _ protocol.KeyPhaseBit, _ error) {
	if len(data) == 0 {
		return 0, 0, 0, 0, io.EOF
	}
	if data[0]&0x80 > 0 {
		return 0, 0, 0, 0, errors.New("not a short header packet")
	}
	if data[0]&0x40 == 0 {
		return 0, 0, 0, 0, errors.New("not a QUIC packet")
	}
	pnLen := protocol.PacketNumberLen(data[0]&0b11) + 1
	if len(data) < 1+int(pnLen)+connIDLen {
		return 0, 0, 0, 0, io.EOF
	}

	pos := 1 + connIDLen
	var pn protocol.PacketNumber
	switch pnLen {
	case protocol.PacketNumberLen1:
		pn = protocol.PacketNumber(data[pos])
	case protocol.PacketNumberLen2:
		pn = protocol.PacketNumber(utils.BigEndian.Uint16(data[pos : pos+2]))
	case protocol.PacketNumberLen3:
		pn = protocol.PacketNumber(utils.BigEndian.Uint24(data[pos : pos+3]))
	case protocol.PacketNumberLen4:
		pn = protocol.PacketNumber(utils.BigEndian.Uint32(data[pos : pos+4]))
	default:
		return 0, 0, 0, 0, fmt.Errorf("invalid packet number length: %d", pnLen)
	}
	kp := protocol.KeyPhaseZero
	if data[0]&0b100 > 0 {
		kp = protocol.KeyPhaseOne
	}

	var err error
	if data[0]&0x18 != 0 {
		err = ErrInvalidReservedBits
	}
	return 1 + connIDLen + int(pnLen), pn, pnLen, kp, err
}

func LogShortHeader(logger utils.Logger, dest protocol.ConnectionID, pn protocol.PacketNumber, pnLen protocol.PacketNumberLen, kp protocol.KeyPhaseBit) {
	logger.Debugf("\tShort Header{DestConnectionID: %s, PacketNumber: %d, PacketNumberLen: %d, KeyPhase: %s}", dest, pn, pnLen, kp)
}
