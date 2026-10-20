package protocol

import "time"

// InitialPacketSize is the initial (before Path MTU discovery) maximum packet size used.
const InitialPacketSize = 1280

// MaxCongestionWindowPackets is the maximum congestion window in packet.
const MaxCongestionWindowPackets = 10000

// MaxUndecryptablePackets limits the number of undecryptable packets that are queued in the connection.
const MaxUndecryptablePackets = 32

// ConnectionFlowControlMultiplier determines how much larger the connection flow control windows needs to be relative to any stream's flow control window
// This is the value that Chromium is using
const ConnectionFlowControlMultiplier = 1.5

// DefaultInitialMaxStreamData is the default initial stream-level flow control window for receiving data
const DefaultInitialMaxStreamData = (1 << 10) * 512 // 512 kb

// DefaultInitialMaxData is the connection-level flow control window for receiving data
const DefaultInitialMaxData = ConnectionFlowControlMultiplier * DefaultInitialMaxStreamData

// DefaultMaxReceiveStreamFlowControlWindow is the default maximum stream-level flow control window for receiving data
const DefaultMaxReceiveStreamFlowControlWindow = 6 * (1 << 20) // 6 MB

// DefaultMaxReceiveConnectionFlowControlWindow is the default connection-level flow control window for receiving data
const DefaultMaxReceiveConnectionFlowControlWindow = 15 * (1 << 20) // 15 MB

// WindowUpdateThreshold is the fraction of the receive window that has to be consumed before an higher offset is advertised to the client
const WindowUpdateThreshold = 0.25

// DefaultMaxIncomingStreams is the maximum number of streams that a peer may open
const DefaultMaxIncomingStreams = 100

// DefaultMaxIncomingUniStreams is the maximum number of unidirectional streams that a peer may open
const DefaultMaxIncomingUniStreams = 100

// MaxServerUnprocessedPackets is the max number of packets stored in the server that are not yet processed.
const MaxServerUnprocessedPackets = 1024

// MaxConnUnprocessedPackets is the max number of packets stored in each connection that are not yet processed.
const MaxConnUnprocessedPackets = 256

// MaxAcceptQueueSize is the maximum number of connections that the server queues for accepting.
// If the queue is full, new connection attempts will be rejected.
const MaxAcceptQueueSize = 32

// TokenValidity is the duration that a (non-retry) token is considered valid
const TokenValidity = 24 * time.Hour

// MaxOutstandingSentPackets is maximum number of packets saved for retransmission.
// When reached, it imposes a soft limit on sending new packets:
// Sending ACKs and retransmission is still allowed, but now new regular packets can be sent.
const MaxOutstandingSentPackets = 2 * MaxCongestionWindowPackets

// MaxTrackedSentPackets is maximum number of sent packets saved for retransmission.
// When reached, no more packets will be sent.
// This value *must* be larger than MaxOutstandingSentPackets.
const MaxTrackedSentPackets = MaxOutstandingSentPackets * 5 / 4

// MaxNonAckElicitingAcks is the maximum number of packets containing an ACK,
// but no ack-eliciting frames, that we send in a row
const MaxNonAckElicitingAcks = 19

// MaxStreamFrameSorterGaps is the maximum number of gaps between received StreamFrames
// prevents DoS attacks against the streamFrameSorter
const MaxStreamFrameSorterGaps = 1000

// MinStreamFrameBufferSize is the minimum data length of a received STREAM frame
// that we use the buffer for. This protects against a DoS where an attacker would send us
// very small STREAM frames to consume a lot of memory.
const MinStreamFrameBufferSize = 128

// MinCoalescedPacketSize is the minimum size of a coalesced packet that we pack.
// If a packet has less than this number of bytes, we won't coalesce any more packets onto it.
const MinCoalescedPacketSize = 128

// MaxCryptoStreamOffset is the maximum offset allowed on any of the crypto streams.
// This limits the size of the ClientHello and Certificates that can be received.
const MaxCryptoStreamOffset = 16 * (1 << 10)

// MinRemoteIdleTimeout is the minimum value that we accept for the remote idle timeout
const MinRemoteIdleTimeout = 5 * time.Second

// DefaultIdleTimeout is the default idle timeout
const DefaultIdleTimeout = 30 * time.Second

// DefaultHandshakeIdleTimeout is the default idle timeout used before handshake completion.
const DefaultHandshakeIdleTimeout = 5 * time.Second

// MinStreamFrameSize is the minimum size that has to be left in a packet, so that we add another STREAM frame.
// This avoids splitting up STREAM frames into small pieces, which has 2 advantages:
// 1. it reduces the framing overhead
// 2. it reduces the head-of-line blocking, when a packet is lost
const MinStreamFrameSize ByteCount = 128

// MaxNumAckRanges is the maximum number of ACK ranges that we send in an ACK frame.
// It also serves as a limit for the packet history.
// If at any point we keep track of more ranges, old ranges are discarded.
//
// This value also guarantees that ACK Range Count value in the ACK frame can be encoded
// in a single byte varint.
const MaxNumAckRanges = 64

// DefaultConnectionIDLength is the connection ID length that is used for multiplexed connections
// if no other value is configured.
const DefaultConnectionIDLength = 4

// MaxActiveConnectionIDs is the number of connection IDs that we're storing.
const MaxActiveConnectionIDs = 4

// MaxIssuedConnectionIDs is the maximum number of connection IDs that we're issuing at the same time.
const MaxIssuedConnectionIDs = 6

// PacketsPerConnectionID is the number of packets we send using one connection ID.
// If the peer provices us with enough new connection IDs, we switch to a new connection ID.
const PacketsPerConnectionID = 10000

// AckDelayExponent is the ack delay exponent used when sending ACKs.
const AckDelayExponent = 3

// Estimated timer granularity.
// The loss detection timer will not be set to a value smaller than granularity.
const TimerGranularity = time.Millisecond
