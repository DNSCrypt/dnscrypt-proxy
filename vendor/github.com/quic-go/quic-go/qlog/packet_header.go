package qlog

import (
	"encoding/hex"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

type Token struct {
	Raw []byte
}

func (t Token) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("raw"))
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("data"))
	h.WriteToken(jsontext.String(hex.EncodeToString(t.Raw)))
	h.WriteToken(jsontext.EndObject)
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// PacketHeader is a QUIC packet header.
// Connection IDs are only logged if they are valid.
type PacketHeader struct {
	PacketType       PacketType
	KeyPhaseBit      KeyPhaseBit
	PacketNumber     PacketNumber
	Version          Version
	SrcConnectionID  ConnectionID
	DestConnectionID ConnectionID
	Token            *Token
}

func (h PacketHeader) encode(enc *jsontext.Encoder) error {
	helper := encoderHelper{enc: enc}
	helper.WriteToken(jsontext.BeginObject)
	helper.WriteToken(jsontext.String("packet_type"))
	packetType := h.PacketType
	if packetType == "" {
		packetType = PacketTypeUnknown
	}
	helper.WriteToken(jsontext.String(string(packetType)))
	//nolint:exhaustive // Only these packet types carry packet numbers.
	switch packetType {
	case PacketTypeInitial, PacketTypeHandshake, PacketType0RTT, PacketType1RTT:
		if h.PacketNumber != protocol.InvalidPacketNumber {
			helper.WriteToken(jsontext.String("packet_number"))
			helper.WriteToken(jsontext.Int(int64(h.PacketNumber)))
		}
	}
	if h.Version != 0 {
		helper.WriteToken(jsontext.String("version"))
		helper.WriteToken(jsontext.String(version(h.Version).String()))
	}
	if h.PacketType != PacketType1RTT && h.SrcConnectionID.Valid() {
		helper.WriteToken(jsontext.String("scid"))
		helper.WriteToken(jsontext.String(hex.EncodeToString(h.SrcConnectionID.Bytes())))
	}
	if h.DestConnectionID.Valid() {
		helper.WriteToken(jsontext.String("dcid"))
		helper.WriteToken(jsontext.String(hex.EncodeToString(h.DestConnectionID.Bytes())))
	}
	if h.KeyPhaseBit == KeyPhaseZero || h.KeyPhaseBit == KeyPhaseOne {
		helper.WriteToken(jsontext.String("key_phase_bit"))
		helper.WriteToken(jsontext.Bool(h.KeyPhaseBit == KeyPhaseOne))
	}
	if h.Token != nil {
		helper.WriteToken(jsontext.String("token"))
		if err := h.Token.encode(enc); err != nil {
			return err
		}
	}
	helper.WriteToken(jsontext.EndObject)
	return helper.err
}

type PacketHeaderVersionNegotiation struct {
	SrcConnectionID  ArbitraryLenConnectionID
	DestConnectionID ArbitraryLenConnectionID
}

func (h PacketHeaderVersionNegotiation) encode(enc *jsontext.Encoder) error {
	helper := encoderHelper{enc: enc}
	helper.WriteToken(jsontext.BeginObject)
	helper.WriteToken(jsontext.String("packet_type"))
	helper.WriteToken(jsontext.String("version_negotiation"))
	helper.WriteToken(jsontext.String("scid"))
	helper.WriteToken(jsontext.String(hex.EncodeToString(h.SrcConnectionID.Bytes())))
	helper.WriteToken(jsontext.String("dcid"))
	helper.WriteToken(jsontext.String(hex.EncodeToString(h.DestConnectionID.Bytes())))
	helper.WriteToken(jsontext.EndObject)
	return helper.err
}
