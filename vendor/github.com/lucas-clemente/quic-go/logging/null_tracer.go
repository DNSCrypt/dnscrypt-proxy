package logging

import (
	"context"
	"net"
	"time"
)

// The NullTracer is a Tracer that does nothing.
// It is useful for embedding.
type NullTracer struct{}

func (n NullTracer) TracerForConnection(context.Context, Perspective, ConnectionID) ConnectionTracer {
	return NullConnectionTracer{}
}
func (n NullTracer) SentPacket(net.Addr, *Header, ByteCount, []Frame)                {}
func (n NullTracer) DroppedPacket(net.Addr, PacketType, ByteCount, PacketDropReason) {}

// The NullConnectionTracer is a ConnectionTracer that does nothing.
// It is useful for embedding.
type NullConnectionTracer struct{}

func (n NullConnectionTracer) StartedConnection(local, remote net.Addr, srcConnID, destConnID ConnectionID) {
}

func (n NullConnectionTracer) NegotiatedVersion(chosen VersionNumber, clientVersions, serverVersions []VersionNumber) {
}
func (n NullConnectionTracer) ClosedConnection(err error)                                         {}
func (n NullConnectionTracer) SentTransportParameters(*TransportParameters)                       {}
func (n NullConnectionTracer) ReceivedTransportParameters(*TransportParameters)                   {}
func (n NullConnectionTracer) RestoredTransportParameters(*TransportParameters)                   {}
func (n NullConnectionTracer) SentPacket(*ExtendedHeader, ByteCount, *AckFrame, []Frame)          {}
func (n NullConnectionTracer) ReceivedVersionNegotiationPacket(*Header, []VersionNumber)          {}
func (n NullConnectionTracer) ReceivedRetry(*Header)                                              {}
func (n NullConnectionTracer) ReceivedPacket(hdr *ExtendedHeader, size ByteCount, frames []Frame) {}
func (n NullConnectionTracer) BufferedPacket(PacketType)                                          {}
func (n NullConnectionTracer) DroppedPacket(PacketType, ByteCount, PacketDropReason)              {}
func (n NullConnectionTracer) UpdatedMetrics(rttStats *RTTStats, cwnd, bytesInFlight ByteCount, packetsInFlight int) {
}
func (n NullConnectionTracer) AcknowledgedPacket(EncryptionLevel, PacketNumber)            {}
func (n NullConnectionTracer) LostPacket(EncryptionLevel, PacketNumber, PacketLossReason)  {}
func (n NullConnectionTracer) UpdatedCongestionState(CongestionState)                      {}
func (n NullConnectionTracer) UpdatedPTOCount(uint32)                                      {}
func (n NullConnectionTracer) UpdatedKeyFromTLS(EncryptionLevel, Perspective)              {}
func (n NullConnectionTracer) UpdatedKey(keyPhase KeyPhase, remote bool)                   {}
func (n NullConnectionTracer) DroppedEncryptionLevel(EncryptionLevel)                      {}
func (n NullConnectionTracer) DroppedKey(KeyPhase)                                         {}
func (n NullConnectionTracer) SetLossTimer(TimerType, EncryptionLevel, time.Time)          {}
func (n NullConnectionTracer) LossTimerExpired(timerType TimerType, level EncryptionLevel) {}
func (n NullConnectionTracer) LossTimerCanceled()                                          {}
func (n NullConnectionTracer) Close()                                                      {}
func (n NullConnectionTracer) Debug(name, msg string)                                      {}
