package qlog

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

func milliseconds(dur time.Duration) float64 { return float64(dur.Nanoseconds()) / 1e6 }

type encoderHelper struct {
	enc *jsontext.Encoder
	err error
}

func (h *encoderHelper) WriteToken(t jsontext.Token) {
	if h.err != nil {
		return
	}
	h.err = h.enc.WriteToken(t)
}

func (h *encoderHelper) WriteIPAddressPort(addr netip.AddrPort) {
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("ip"))
	h.WriteToken(jsontext.String(addr.Addr().String()))
	h.WriteToken(jsontext.String("port"))
	h.WriteToken(jsontext.Uint(uint64(addr.Port())))
	h.WriteToken(jsontext.EndObject)
}

type versions []Version

func (v versions) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginArray)
	for _, e := range v {
		h.WriteToken(jsontext.String(fmt.Sprintf("%x", uint32(e))))
	}
	h.WriteToken(jsontext.EndArray)
	return h.err
}

// OmitLength indicates that a length should not be logged.
const OmitLength = -1

// RawInfo contains packet or datagram lengths. Zero lengths are logged.
// Set a field to OmitLength to omit it.
type RawInfo struct {
	Length        int // full packet length, including header and AEAD authentication tag
	PayloadLength int // length of the packet payload, excluding AEAD tag
}

func (i RawInfo) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if i.Length != OmitLength {
		h.WriteToken(jsontext.String("length"))
		h.WriteToken(jsontext.Uint(uint64(i.Length)))
	}
	if i.PayloadLength != OmitLength {
		h.WriteToken(jsontext.String("payload_length"))
		h.WriteToken(jsontext.Uint(uint64(i.PayloadLength)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type TupleEndpointInfo struct {
	IPv4 netip.AddrPort
	IPv6 netip.AddrPort
}

func (p TupleEndpointInfo) encode(enc *jsontext.Encoder, redacted *string) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if redacted != nil {
		if p.IPv4.IsValid() {
			h.WriteToken(jsontext.String("address_v4"))
		} else {
			h.WriteToken(jsontext.String("address_v6"))
		}
		h.WriteToken(jsontext.String(*redacted))
		h.WriteToken(jsontext.EndObject)
		return h.err
	}
	if p.IPv4.IsValid() {
		h.WriteToken(jsontext.String("address_v4"))
		h.WriteIPAddressPort(p.IPv4)
	}
	if p.IPv6.IsValid() {
		h.WriteToken(jsontext.String("address_v6"))
		h.WriteIPAddressPort(p.IPv6)
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type StartedConnection struct {
	Local  TupleEndpointInfo
	Remote TupleEndpointInfo

	// Non-nil redacted values replace the corresponding IP and port in qlog output.
	RedactedLocal, RedactedRemote *string
}

func (e StartedConnection) Name() string { return "transport:connection_started" }

func (e StartedConnection) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("local"))
	if err := e.Local.encode(enc, e.RedactedLocal); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("remote"))
	if err := e.Remote.encode(enc, e.RedactedRemote); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// TupleAssigned associates a TupleID with the endpoints of a network tuple.
type TupleAssigned struct {
	TupleID string
	Local   TupleEndpointInfo
	Remote  TupleEndpointInfo

	// non-nil redacted values replace the corresponding IP and port in qlog output
	RedactedLocal, RedactedRemote *string
}

func (e TupleAssigned) Name() string { return "transport:tuple_assigned" }

func (e TupleAssigned) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("tuple_id"))
	h.WriteToken(jsontext.String(e.TupleID))
	h.WriteToken(jsontext.String("tuple_local"))
	if err := e.Local.encode(enc, e.RedactedLocal); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("tuple_remote"))
	if err := e.Remote.encode(enc, e.RedactedRemote); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type VersionInformation struct {
	ClientVersions, ServerVersions []Version
	ChosenVersion                  Version
}

func (e VersionInformation) Name() string { return "transport:version_information" }

func (e VersionInformation) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if len(e.ClientVersions) > 0 {
		h.WriteToken(jsontext.String("client_versions"))
		if err := versions(e.ClientVersions).encode(enc); err != nil {
			return err
		}
	}
	if len(e.ServerVersions) > 0 {
		h.WriteToken(jsontext.String("server_versions"))
		if err := versions(e.ServerVersions).encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.String("chosen_version"))
	h.WriteToken(jsontext.String(fmt.Sprintf("%x", uint32(e.ChosenVersion))))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type ConnectionClosed struct {
	Initiator Initiator

	ConnectionError  *TransportErrorCode
	ApplicationError *ApplicationErrorCode

	Reason string

	Trigger ConnectionCloseTrigger
}

func (e ConnectionClosed) Name() string { return "transport:connection_closed" }

func (e ConnectionClosed) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("initiator"))
	h.WriteToken(jsontext.String(string(e.Initiator)))
	if e.ConnectionError != nil {
		h.WriteToken(jsontext.String("connection_error"))
		if name := transportError(*e.ConnectionError).String(); name != "" {
			h.WriteToken(jsontext.String(name))
		} else {
			h.WriteToken(jsontext.String("unknown"))
			h.WriteToken(jsontext.String("error_code"))
			h.WriteToken(jsontext.Uint(uint64(*e.ConnectionError)))
		}
	}
	if e.ApplicationError != nil {
		h.WriteToken(jsontext.String("application_error"))
		h.WriteToken(jsontext.String("unknown"))
		h.WriteToken(jsontext.String("error_code"))
		h.WriteToken(jsontext.Uint(uint64(*e.ApplicationError)))
	}
	if e.ConnectionError != nil || e.ApplicationError != nil {
		h.WriteToken(jsontext.String("reason"))
		h.WriteToken(jsontext.String(e.Reason))
	}
	if e.Trigger != "" {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(string(e.Trigger)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type ConnectionStateUpdated struct {
	State ConnectionState
}

func (e ConnectionStateUpdated) Name() string { return "quic:connection_state_updated" }

func (e ConnectionStateUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("new"))
	h.WriteToken(jsontext.String(string(e.State)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type PacketSent struct {
	Header                  PacketHeader
	Raw                     RawInfo
	DatagramPayloadChecksum DatagramPayloadChecksum
	Frames                  []Frame
	ECN                     ECN
	Trigger                 string
	SupportedVersions       []Version
	IsMTUProbePacket        bool
	// Tuple is the TupleID of the network tuple that the packet was sent on.
	// It is empty for the tuple that the TupleID "" is assigned to.
	Tuple string
}

func (e PacketSent) Name() string { return "transport:packet_sent" }

func (e PacketSent) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("raw"))
	if err := e.Raw.encode(enc); err != nil {
		return err
	}
	if e.DatagramPayloadChecksum != 0 {
		h.WriteToken(jsontext.String("datagram_payload_checksum"))
		h.WriteToken(jsontext.Uint(uint64(e.DatagramPayloadChecksum)))
	}
	if len(e.Frames) > 0 {
		h.WriteToken(jsontext.String("frames"))
		if err := frames(e.Frames).encode(enc); err != nil {
			return err
		}
	}
	if e.ECN != ECNUnsupported {
		h.WriteToken(jsontext.String("ecn"))
		h.WriteToken(jsontext.String(string(e.ECN)))
	}
	if e.Trigger != "" {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(e.Trigger))
	}
	if e.IsMTUProbePacket {
		h.WriteToken(jsontext.String("is_mtu_probe_packet"))
		h.WriteToken(jsontext.True)
	}
	if e.Tuple != "" {
		h.WriteToken(jsontext.String("tuple"))
		h.WriteToken(jsontext.String(e.Tuple))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type PacketReceived struct {
	Header                  PacketHeader
	Raw                     RawInfo
	DatagramPayloadChecksum DatagramPayloadChecksum
	Frames                  []Frame
	ECN                     ECN
	Trigger                 string
	// Tuple is the TupleID of the network tuple that the packet was received on.
	// It is empty for the tuple that the TupleID "" is assigned to.
	Tuple string
}

func (e PacketReceived) Name() string { return "transport:packet_received" }

func (e PacketReceived) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("raw"))
	if err := e.Raw.encode(enc); err != nil {
		return err
	}
	if e.DatagramPayloadChecksum != 0 {
		h.WriteToken(jsontext.String("datagram_payload_checksum"))
		h.WriteToken(jsontext.Uint(uint64(e.DatagramPayloadChecksum)))
	}
	if len(e.Frames) > 0 {
		h.WriteToken(jsontext.String("frames"))
		if err := frames(e.Frames).encode(enc); err != nil {
			return err
		}
	}
	if e.ECN != ECNUnsupported {
		h.WriteToken(jsontext.String("ecn"))
		h.WriteToken(jsontext.String(string(e.ECN)))
	}
	if e.Trigger != "" {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(e.Trigger))
	}
	if e.Tuple != "" {
		h.WriteToken(jsontext.String("tuple"))
		h.WriteToken(jsontext.String(e.Tuple))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type VersionNegotiationReceived struct {
	Header            PacketHeaderVersionNegotiation
	SupportedVersions []Version
}

func (e VersionNegotiationReceived) Name() string { return "transport:packet_received" }

func (e VersionNegotiationReceived) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("supported_versions"))
	if err := versions(e.SupportedVersions).encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type VersionNegotiationSent struct {
	Header            PacketHeaderVersionNegotiation
	SupportedVersions []Version
}

func (e VersionNegotiationSent) Name() string { return "transport:packet_sent" }

func (e VersionNegotiationSent) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("supported_versions"))
	if err := versions(e.SupportedVersions).encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type PacketBuffered struct {
	Header                  PacketHeader
	Raw                     RawInfo
	DatagramPayloadChecksum DatagramPayloadChecksum
}

func (e PacketBuffered) Name() string { return "transport:packet_buffered" }

func (e PacketBuffered) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("raw"))
	if err := e.Raw.encode(enc); err != nil {
		return err
	}
	if e.DatagramPayloadChecksum != 0 {
		h.WriteToken(jsontext.String("datagram_payload_checksum"))
		h.WriteToken(jsontext.Uint(uint64(e.DatagramPayloadChecksum)))
	}
	h.WriteToken(jsontext.String("trigger"))
	h.WriteToken(jsontext.String("keys_unavailable"))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// PacketDropped is the transport:packet_dropped event.
type PacketDropped struct {
	Header                  PacketHeader
	Raw                     RawInfo
	DatagramPayloadChecksum DatagramPayloadChecksum
	Trigger                 PacketDropReason
}

func (e PacketDropped) Name() string { return "transport:packet_dropped" }

func (e PacketDropped) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("raw"))
	if err := e.Raw.encode(enc); err != nil {
		return err
	}
	if e.DatagramPayloadChecksum != 0 {
		h.WriteToken(jsontext.String("datagram_payload_checksum"))
		h.WriteToken(jsontext.Uint(uint64(e.DatagramPayloadChecksum)))
	}
	trigger := e.Trigger.trigger()
	h.WriteToken(jsontext.String("trigger"))
	h.WriteToken(jsontext.String(trigger))
	// preserve the more specific reason
	if trigger != string(e.Trigger) {
		h.WriteToken(jsontext.String("details"))
		h.WriteToken(jsontext.BeginObject)
		h.WriteToken(jsontext.String("reason"))
		h.WriteToken(jsontext.String(string(e.Trigger)))
		h.WriteToken(jsontext.EndObject)
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// DatagramDropped is the quic:datagram_dropped event.
type DatagramDropped struct {
	Direction Direction
	Raw       RawInfo
	Trigger   string
}

var _ qlogwriter.Event = DatagramDropped{}

func (e DatagramDropped) Name() string { return "quic:datagram_dropped" }

func (e DatagramDropped) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if e.Direction != "" {
		h.WriteToken(jsontext.String("direction"))
		h.WriteToken(jsontext.String(string(e.Direction)))
	}
	h.WriteToken(jsontext.String("raw"))
	if err := e.Raw.encode(enc); err != nil {
		return err
	}
	if e.Trigger != "" {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(e.Trigger))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// StreamPriorityUpdated closely follows the http3:priority_updated event from
// draft-ietf-quic-qlog-h3-events.
type StreamPriorityUpdated struct {
	StreamID    StreamID
	Urgency     int8
	Incremental bool
}

func (e StreamPriorityUpdated) Name() string { return "transport:priority_updated" }

func (e StreamPriorityUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("stream_id"))
	h.WriteToken(jsontext.Int(int64(e.StreamID)))
	h.WriteToken(jsontext.String("new"))
	newPriority := fmt.Sprintf("u=%d", e.Urgency)
	if e.Incremental {
		newPriority += ", i"
	}
	h.WriteToken(jsontext.String(newPriority))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type MTUUpdated struct {
	Value int
	Done  bool
}

func (e MTUUpdated) Name() string { return "recovery:mtu_updated" }

func (e MTUUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("new"))
	h.WriteToken(jsontext.Uint(uint64(e.Value)))
	h.WriteToken(jsontext.String("done"))
	h.WriteToken(jsontext.Bool(e.Done))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// RecoveryParametersSet is the quic:recovery_parameters_set event.
type RecoveryParametersSet struct {
	ReorderingThreshold     uint16
	PacketThresholdDisabled bool
	TimeThreshold           float64 // RTT multiplier.
	TimerGranularity        time.Duration
	InitialCongestionWindow protocol.ByteCount
	InitialRTT              time.Duration
}

var _ qlogwriter.Event = RecoveryParametersSet{}

func (e RecoveryParametersSet) Name() string { return "quic:recovery_parameters_set" }

func (e RecoveryParametersSet) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("reordering_threshold"))
	if e.PacketThresholdDisabled {
		h.WriteToken(jsontext.String("disabled"))
	} else {
		h.WriteToken(jsontext.Uint(uint64(e.ReorderingThreshold)))
	}
	h.WriteToken(jsontext.String("time_threshold"))
	h.WriteToken(jsontext.Float(e.TimeThreshold))
	h.WriteToken(jsontext.String("timer_granularity"))
	h.WriteToken(jsontext.Uint(uint64(e.TimerGranularity / time.Millisecond)))
	if e.InitialCongestionWindow != 0 {
		h.WriteToken(jsontext.String("initial_congestion_window"))
		h.WriteToken(jsontext.Uint(uint64(e.InitialCongestionWindow)))
	}
	if e.InitialRTT != 0 {
		h.WriteToken(jsontext.String("initial_rtt"))
		h.WriteToken(jsontext.Float(milliseconds(e.InitialRTT)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// MetricsUpdated logs a snapshot of RTT and congestion metrics as defined in the
// recovery:metrics_updated event.
// The PTO count is logged via [PTOCountUpdated].
type MetricsUpdated struct {
	MinRTT           time.Duration
	SmoothedRTT      time.Duration
	LatestRTT        time.Duration
	RTTVariance      time.Duration
	CongestionWindow int
	BytesInFlight    int
	PacketsInFlight  int
}

func (e MetricsUpdated) Name() string { return "recovery:metrics_updated" }

func (e MetricsUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if e.MinRTT != 0 {
		h.WriteToken(jsontext.String("min_rtt"))
		h.WriteToken(jsontext.Float(milliseconds(e.MinRTT)))
	}
	if e.SmoothedRTT != 0 {
		h.WriteToken(jsontext.String("smoothed_rtt"))
		h.WriteToken(jsontext.Float(milliseconds(e.SmoothedRTT)))
	}
	if e.LatestRTT != 0 {
		h.WriteToken(jsontext.String("latest_rtt"))
		h.WriteToken(jsontext.Float(milliseconds(e.LatestRTT)))
	}
	if e.RTTVariance != 0 || e.SmoothedRTT != 0 {
		h.WriteToken(jsontext.String("rtt_variance"))
		h.WriteToken(jsontext.Float(milliseconds(e.RTTVariance)))
	}
	h.WriteToken(jsontext.String("congestion_window"))
	h.WriteToken(jsontext.Uint(uint64(e.CongestionWindow)))
	h.WriteToken(jsontext.String("bytes_in_flight"))
	h.WriteToken(jsontext.Uint(uint64(e.BytesInFlight)))
	h.WriteToken(jsontext.String("packets_in_flight"))
	h.WriteToken(jsontext.Uint(uint64(e.PacketsInFlight)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// PTOCountUpdated logs the pto_count value of the
// recovery:metrics_updated event.
type PTOCountUpdated struct {
	PTOCount uint32
}

func (e PTOCountUpdated) Name() string { return "recovery:metrics_updated" }

func (e PTOCountUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("pto_count"))
	h.WriteToken(jsontext.Uint(uint64(e.PTOCount)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type PacketLost struct {
	Header           PacketHeader
	IsMTUProbePacket bool
	Trigger          PacketLossReason
}

func (e PacketLost) Name() string { return "recovery:packet_lost" }

func (e PacketLost) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	if e.IsMTUProbePacket {
		h.WriteToken(jsontext.String("is_mtu_probe_packet"))
		h.WriteToken(jsontext.True)
	}
	h.WriteToken(jsontext.String("trigger"))
	h.WriteToken(jsontext.String(string(e.Trigger)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type SpuriousLoss struct {
	EncryptionLevel protocol.EncryptionLevel
	PacketNumber    protocol.PacketNumber
	// PacketReordering is the distance to the ACK's largest acknowledged packet,
	// adjusted for known skipped packet numbers. Reordered ACKs can yield zero.
	PacketReordering uint64
	TimeReordering   time.Duration
}

func (e SpuriousLoss) Name() string { return "recovery:spurious_loss" }

func (e SpuriousLoss) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("packet_number_space"))
	h.WriteToken(jsontext.String(encLevelToPacketNumberSpace(e.EncryptionLevel)))
	h.WriteToken(jsontext.String("packet_number"))
	h.WriteToken(jsontext.Uint(uint64(e.PacketNumber)))
	h.WriteToken(jsontext.String("reordering_packets"))
	h.WriteToken(jsontext.Uint(e.PacketReordering))
	h.WriteToken(jsontext.String("reordering_time"))
	h.WriteToken(jsontext.Float(milliseconds(e.TimeReordering)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type KeyUpdated struct {
	Trigger  KeyUpdateTrigger
	KeyType  KeyType
	KeyPhase KeyPhase // only set for 1-RTT keys
	// we don't log the keys here, so we don't need `old` and `new`.
}

func (e KeyUpdated) Name() string { return "security:key_updated" }

func (e KeyUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("trigger"))
	h.WriteToken(jsontext.String(string(e.Trigger)))
	h.WriteToken(jsontext.String("key_type"))
	h.WriteToken(jsontext.String(string(e.KeyType)))
	if e.KeyType == KeyTypeClient1RTT || e.KeyType == KeyTypeServer1RTT {
		h.WriteToken(jsontext.String("key_phase"))
		h.WriteToken(jsontext.Uint(uint64(e.KeyPhase)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type KeyDiscarded struct {
	KeyType  KeyType
	KeyPhase KeyPhase // only set for 1-RTT keys
}

func (e KeyDiscarded) Name() string { return "security:key_discarded" }

func (e KeyDiscarded) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if e.KeyType != KeyTypeClient1RTT && e.KeyType != KeyTypeServer1RTT {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String("tls"))
	}
	h.WriteToken(jsontext.String("key_type"))
	h.WriteToken(jsontext.String(string(e.KeyType)))
	if e.KeyType == KeyTypeClient1RTT || e.KeyType == KeyTypeServer1RTT {
		h.WriteToken(jsontext.String("key_phase"))
		h.WriteToken(jsontext.Uint(uint64(e.KeyPhase)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type ParametersSet struct {
	Initiator                       Initiator
	SentBy                          protocol.Perspective
	OriginalDestinationConnectionID protocol.ConnectionID
	InitialSourceConnectionID       protocol.ConnectionID
	RetrySourceConnectionID         protocol.ConnectionID
	StatelessResetToken             *protocol.StatelessResetToken
	DisableActiveMigration          bool
	MaxIdleTimeout                  time.Duration
	MaxUDPPayloadSize               protocol.ByteCount
	AckDelayExponent                uint8
	MaxAckDelay                     time.Duration
	ActiveConnectionIDLimit         uint64
	InitialMaxData                  protocol.ByteCount
	InitialMaxStreamDataBidiLocal   protocol.ByteCount
	InitialMaxStreamDataBidiRemote  protocol.ByteCount
	InitialMaxStreamDataUni         protocol.ByteCount
	InitialMaxStreamsBidi           int64
	InitialMaxStreamsUni            int64
	PreferredAddress                *PreferredAddress
	MaxDatagramFrameSize            protocol.ByteCount
	EnableResetStreamAt             bool
}

func (e ParametersSet) Name() string { return "transport:parameters_set" }

func (e ParametersSet) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("initiator"))
	h.WriteToken(jsontext.String(string(e.Initiator)))
	if e.SentBy == protocol.PerspectiveServer {
		h.WriteToken(jsontext.String("original_destination_connection_id"))
		h.WriteToken(jsontext.String(fmt.Sprintf("%x", e.OriginalDestinationConnectionID.Bytes())))
		if e.StatelessResetToken != nil {
			h.WriteToken(jsontext.String("stateless_reset_token"))
			h.WriteToken(jsontext.String(fmt.Sprintf("%x", e.StatelessResetToken[:])))
		}
		if e.RetrySourceConnectionID.Valid() {
			h.WriteToken(jsontext.String("retry_source_connection_id"))
			h.WriteToken(jsontext.String(fmt.Sprintf("%x", e.RetrySourceConnectionID.Bytes())))
		}
	}
	h.WriteToken(jsontext.String("initial_source_connection_id"))
	h.WriteToken(jsontext.String(fmt.Sprintf("%x", e.InitialSourceConnectionID.Bytes())))
	h.WriteToken(jsontext.String("disable_active_migration"))
	h.WriteToken(jsontext.Bool(e.DisableActiveMigration))
	if e.MaxIdleTimeout != 0 {
		h.WriteToken(jsontext.String("max_idle_timeout"))
		h.WriteToken(jsontext.Uint(uint64(e.MaxIdleTimeout.Milliseconds())))
	}
	if e.MaxUDPPayloadSize != 0 {
		h.WriteToken(jsontext.String("max_udp_payload_size"))
		h.WriteToken(jsontext.Int(int64(e.MaxUDPPayloadSize)))
	}
	h.WriteToken(jsontext.String("ack_delay_exponent"))
	h.WriteToken(jsontext.Uint(uint64(e.AckDelayExponent)))
	if e.MaxAckDelay != 0 {
		h.WriteToken(jsontext.String("max_ack_delay"))
		h.WriteToken(jsontext.Uint(uint64(e.MaxAckDelay.Milliseconds())))
	}
	if e.ActiveConnectionIDLimit != 0 {
		h.WriteToken(jsontext.String("active_connection_id_limit"))
		h.WriteToken(jsontext.Uint(e.ActiveConnectionIDLimit))
	}
	if e.InitialMaxData != 0 {
		h.WriteToken(jsontext.String("initial_max_data"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxData)))
	}
	if e.InitialMaxStreamDataBidiLocal != 0 {
		h.WriteToken(jsontext.String("initial_max_stream_data_bidi_local"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataBidiLocal)))
	}
	if e.InitialMaxStreamDataBidiRemote != 0 {
		h.WriteToken(jsontext.String("initial_max_stream_data_bidi_remote"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataBidiRemote)))
	}
	if e.InitialMaxStreamDataUni != 0 {
		h.WriteToken(jsontext.String("initial_max_stream_data_uni"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataUni)))
	}
	if e.InitialMaxStreamsBidi != 0 {
		h.WriteToken(jsontext.String("initial_max_streams_bidi"))
		h.WriteToken(jsontext.Int(e.InitialMaxStreamsBidi))
	}
	if e.InitialMaxStreamsUni != 0 {
		h.WriteToken(jsontext.String("initial_max_streams_uni"))
		h.WriteToken(jsontext.Int(e.InitialMaxStreamsUni))
	}
	if e.PreferredAddress != nil {
		h.WriteToken(jsontext.String("preferred_address"))
		if err := e.PreferredAddress.encode(enc); err != nil {
			return err
		}
	}
	if e.MaxDatagramFrameSize != protocol.InvalidByteCount {
		h.WriteToken(jsontext.String("max_datagram_frame_size"))
		h.WriteToken(jsontext.Int(int64(e.MaxDatagramFrameSize)))
	}
	if e.EnableResetStreamAt {
		h.WriteToken(jsontext.String("reset_stream_at"))
		h.WriteToken(jsontext.True)
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type ParametersRestored struct {
	ActiveConnectionIDLimit        uint64
	InitialMaxData                 protocol.ByteCount
	InitialMaxStreamDataBidiLocal  protocol.ByteCount
	InitialMaxStreamDataBidiRemote protocol.ByteCount
	InitialMaxStreamDataUni        protocol.ByteCount
	InitialMaxStreamsBidi          int64
	InitialMaxStreamsUni           int64
	MaxDatagramFrameSize           protocol.ByteCount
	EnableResetStreamAt            bool
}

func (e ParametersRestored) Name() string { return "transport:parameters_restored" }

func (e ParametersRestored) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if e.ActiveConnectionIDLimit != 0 {
		h.WriteToken(jsontext.String("active_connection_id_limit"))
		h.WriteToken(jsontext.Uint(e.ActiveConnectionIDLimit))
	}
	if e.InitialMaxData != 0 {
		h.WriteToken(jsontext.String("initial_max_data"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxData)))
	}
	if e.InitialMaxStreamDataBidiLocal != 0 {
		h.WriteToken(jsontext.String("initial_max_stream_data_bidi_local"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataBidiLocal)))
	}
	if e.InitialMaxStreamDataBidiRemote != 0 {
		h.WriteToken(jsontext.String("initial_max_stream_data_bidi_remote"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataBidiRemote)))
	}
	if e.InitialMaxStreamDataUni != 0 {
		h.WriteToken(jsontext.String("initial_max_stream_data_uni"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataUni)))
	}
	if e.InitialMaxStreamsBidi != 0 {
		h.WriteToken(jsontext.String("initial_max_streams_bidi"))
		h.WriteToken(jsontext.Int(e.InitialMaxStreamsBidi))
	}
	if e.InitialMaxStreamsUni != 0 {
		h.WriteToken(jsontext.String("initial_max_streams_uni"))
		h.WriteToken(jsontext.Int(e.InitialMaxStreamsUni))
	}
	if e.MaxDatagramFrameSize != protocol.InvalidByteCount {
		h.WriteToken(jsontext.String("max_datagram_frame_size"))
		h.WriteToken(jsontext.Int(int64(e.MaxDatagramFrameSize)))
	}
	if e.EnableResetStreamAt {
		h.WriteToken(jsontext.String("reset_stream_at"))
		h.WriteToken(jsontext.True)
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type PreferredAddress struct {
	IPv4, IPv6          netip.AddrPort
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken

	// Non-nil redacted values replace the corresponding IP and port in qlog output.
	RedactedIPv4, RedactedIPv6 *string
}

func (a PreferredAddress) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if a.RedactedIPv4 != nil {
		h.WriteToken(jsontext.String("address_v4"))
		h.WriteToken(jsontext.String(*a.RedactedIPv4))
	} else if a.IPv4.IsValid() {
		h.WriteToken(jsontext.String("address_v4"))
		h.WriteIPAddressPort(a.IPv4)
	}
	if a.RedactedIPv6 != nil {
		h.WriteToken(jsontext.String("address_v6"))
		h.WriteToken(jsontext.String(*a.RedactedIPv6))
	} else if a.IPv6.IsValid() {
		h.WriteToken(jsontext.String("address_v6"))
		h.WriteIPAddressPort(a.IPv6)
	}
	h.WriteToken(jsontext.String("connection_id"))
	h.WriteToken(jsontext.String(fmt.Sprintf("%x", a.ConnectionID.Bytes())))
	h.WriteToken(jsontext.String("stateless_reset_token"))
	h.WriteToken(jsontext.String(fmt.Sprintf("%x", a.StatelessResetToken)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type TimerUpdated struct {
	Type      TimerEventType
	TimerType TimerType
	EncLevel  EncryptionLevel
	Time      time.Time
}

func (e TimerUpdated) Name() string { return "recovery:loss_timer_updated" }

func (e TimerUpdated) Encode(enc *jsontext.Encoder, t time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("event_type"))
	h.WriteToken(jsontext.String(string(e.Type)))
	if e.TimerType != "" {
		h.WriteToken(jsontext.String("timer_type"))
		h.WriteToken(jsontext.String(string(e.TimerType)))
	}
	if e.EncLevel != 0 {
		h.WriteToken(jsontext.String("packet_number_space"))
		h.WriteToken(jsontext.String(encLevelToPacketNumberSpace(e.EncLevel)))
	}
	if e.Type == TimerEventTypeSet {
		h.WriteToken(jsontext.String("delta"))
		h.WriteToken(jsontext.Float(milliseconds(e.Time.Sub(t))))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type CongestionStateUpdated struct {
	State CongestionState
}

func (e CongestionStateUpdated) Name() string { return "recovery:congestion_state_updated" }

func (e CongestionStateUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("new"))
	h.WriteToken(jsontext.String(e.State.String()))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type ECNStateUpdated struct {
	State   ECNState
	Trigger string
}

func (e ECNStateUpdated) Name() string { return "recovery:ecn_state_updated" }

func (e ECNStateUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("new"))
	h.WriteToken(jsontext.String(string(e.State)))
	if e.Trigger != "" {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(e.Trigger))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type ALPNInformation struct {
	ChosenALPN string
}

func (e ALPNInformation) Name() string { return "transport:alpn_information" }

func (e ALPNInformation) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("chosen_alpn"))
	h.WriteToken(jsontext.BeginObject)
	if utf8.ValidString(e.ChosenALPN) {
		h.WriteToken(jsontext.String("string_value"))
		h.WriteToken(jsontext.String(e.ChosenALPN))
	} else {
		h.WriteToken(jsontext.String("byte_value"))
		h.WriteToken(jsontext.String(hex.EncodeToString([]byte(e.ChosenALPN))))
	}
	h.WriteToken(jsontext.EndObject)
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// DebugEvent is a generic event that can be used to log arbitrary messages.
type DebugEvent struct {
	EventName string
	Message   string
}

func (e DebugEvent) Name() string {
	if e.EventName == "" {
		return "transport:debug"
	}
	return fmt.Sprintf("transport:%s", e.EventName)
}

func (e DebugEvent) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("message"))
	h.WriteToken(jsontext.String(e.Message))
	h.WriteToken(jsontext.EndObject)
	return h.err
}
