package congestion

import (
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// A SendAlgorithm performs congestion control
type SendAlgorithm interface {
	TimeUntilSend() monotime.Time
	HasPacingBudget(now monotime.Time) bool
	OnPacketSent(sentTime monotime.Time, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool)
	CanSend(bytesInFlight protocol.ByteCount) bool
	GetCongestionWindow() protocol.ByteCount
	MaybeExitSlowStart()
	OnPacketAcked(number protocol.PacketNumber, priorInFlight protocol.ByteCount)
	OnCongestionEvent(number protocol.PacketNumber)
	OnSpuriousLoss(number protocol.PacketNumber)
	SetMaxDatagramSize(protocol.ByteCount)
}
