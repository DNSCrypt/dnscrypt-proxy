package ackhandler

import (
	"errors"
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

const (
	// Extra RTT allowance for time-threshold loss detection, in eighths of an RTT.
	defaultTimeThresholdEighths = 1
	maxTimeThresholdEighths     = 8
	// Maximum reordering in packets before packet threshold loss detection considers a packet lost.
	packetThreshold = 3
	// Before validating the client's address, the server won't send more than 3x bytes than it received.
	amplificationFactor = 3
	// We use Retry packets to derive an RTT estimate. Make sure we don't set the RTT to a super low value yet.
	minRTTAfterRetry = 5 * time.Millisecond
	// The PTO duration uses exponential backoff, but is truncated to a maximum value, as allowed by RFC 8961, section 4.4.
	maxPTODuration = 60 * time.Second
)

// Path probe packets are declared lost after this time.
const pathProbePacketLossTimeout = time.Second

type packetNumberSpace struct {
	numOutstanding int

	lossTime                   monotime.Time
	lastAckElicitingPacketTime monotime.Time

	largestAcked protocol.PacketNumber
	largestSent  protocol.PacketNumber
}

func newPacketNumberSpace() *packetNumberSpace {
	return &packetNumberSpace{
		largestSent:  protocol.InvalidPacketNumber,
		largestAcked: protocol.InvalidPacketNumber,
	}
}

type alarmTimer struct {
	Time            monotime.Time
	TimerType       qlog.TimerType
	EncryptionLevel protocol.EncryptionLevel
}

type handshakePacketNumbers struct {
	Initial   []protocol.PacketNumber
	Handshake []protocol.PacketNumber
}

func (p *handshakePacketNumbers) Highest() protocol.PacketNumber {
	switch {
	case len(p.Initial) == 0 && len(p.Handshake) == 0:
		return protocol.InvalidPacketNumber
	case len(p.Initial) == 0:
		return p.Handshake[len(p.Handshake)-1]
	case len(p.Handshake) == 0:
		return p.Initial[len(p.Initial)-1]
	default:
		return max(p.Initial[len(p.Initial)-1], p.Handshake[len(p.Handshake)-1])
	}
}

type sentPacketHandler struct {
	// Packet numbers and their history are shared across encryption levels.
	// ACK processing and loss detection still use the state for each space.
	pns  *packetNumberGenerator
	hist sentPacketHistory

	handshakePNs *handshakePacketNumbers

	initialPackets   *packetNumberSpace
	handshakePackets *packetNumberSpace
	appDataPackets   *packetNumberSpace
	lostPackets      lostPacketTracker // only for application-data packet number space
	// send time of the largest acknowledged packet, across all packet number spaces
	largestAckedTime monotime.Time

	// In the application-data packet number space, packet threshold loss detection is
	// disabled when spurious losses are detected.
	packetThresholdDisabled bool
	timeThresholdEighths    uint8
	// Only packets sent after a time-threshold increase can trigger another one.
	minPNToRelaxReordering protocol.PacketNumber

	// Do we know that the peer completed address validation yet?
	// Always true for the server.
	peerCompletedAddressValidation bool
	bytesReceived                  protocol.ByteCount
	bytesSent                      protocol.ByteCount
	// Have we validated the peer's address yet?
	// Always true for the client.
	peerAddressValidated bool

	handshakeConfirmed bool

	ignorePacketsBelow func(protocol.PacketNumber)

	ackedPackets []packetWithPacketNumber // to avoid allocations in detectAndRemoveAckedPackets

	bytesInFlight protocol.ByteCount

	congestion congestion.SendAlgorithmWithDebugInfos
	rttStats   *utils.RTTStats
	connStats  *utils.ConnectionStats

	// The number of times a PTO has been sent without receiving an ack.
	ptoCount uint32
	ptoMode  SendMode
	// The number of PTO probe packets that should be sent.
	// Only applies to the application-data packet number space.
	numProbesToSend int

	// The alarm timeout
	alarm alarmTimer

	enableECN  bool
	ecnTracker ecnHandler

	perspective protocol.Perspective

	qlogger     qlogwriter.Recorder
	lastMetrics qlog.MetricsUpdated
	logger      utils.Logger
}

var _ SentPacketHandler = &sentPacketHandler{}

// clientAddressValidated indicates whether the address was validated beforehand by an address validation token.
// If the address was validated, the amplification limit doesn't apply. It has no effect for a client.
func NewSentPacketHandler(
	initialPN protocol.PacketNumber,
	initialMaxDatagramSize protocol.ByteCount,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	clientAddressValidated bool,
	enableECN bool,
	ignorePacketsBelow func(protocol.PacketNumber),
	pers protocol.Perspective,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
) SentPacketHandler {
	congestion := congestion.NewCubicSender(
		congestion.DefaultClock{},
		rttStats,
		connStats,
		initialMaxDatagramSize,
		true, // use Reno
		qlogger,
	)

	h := &sentPacketHandler{
		peerCompletedAddressValidation: pers == protocol.PerspectiveServer,
		peerAddressValidated:           pers == protocol.PerspectiveClient || clientAddressValidated,
		pns:                            newPacketNumberGenerator(initialPN, skipPacketInitialPeriod, skipPacketMaxPeriod),
		hist:                           *newSentPacketHistory(),
		timeThresholdEighths:           defaultTimeThresholdEighths,
		minPNToRelaxReordering:         protocol.InvalidPacketNumber,
		handshakePNs: &handshakePacketNumbers{
			Initial:   make([]protocol.PacketNumber, 0, 4),
			Handshake: make([]protocol.PacketNumber, 0, 8),
		},
		initialPackets:     newPacketNumberSpace(),
		handshakePackets:   newPacketNumberSpace(),
		appDataPackets:     newPacketNumberSpace(),
		lostPackets:        *newLostPacketTracker(),
		rttStats:           rttStats,
		connStats:          connStats,
		congestion:         congestion,
		ignorePacketsBelow: ignorePacketsBelow,
		perspective:        pers,
		qlogger:            qlogger,
		logger:             logger,
	}
	if enableECN {
		h.enableECN = true
		h.ecnTracker = newECNTracker(logger, qlogger)
	}
	h.qlogRecoveryParametersSet(true)
	return h
}

func (h *sentPacketHandler) qlogRecoveryParametersSet(initial bool) {
	if h.qlogger == nil {
		return
	}
	ev := qlog.RecoveryParametersSet{
		EncryptionLevel:         protocol.Encryption1RTT,
		ReorderingThreshold:     packetThreshold,
		PacketThresholdDisabled: h.packetThresholdDisabled,
		TimeThreshold:           float64(8+h.timeThresholdEighths) / 8,
		TimerGranularity:        protocol.TimerGranularity,
	}
	if initial {
		ev.InitialCongestionWindow = h.congestion.GetCongestionWindow()
		ev.InitialRTT = h.rttStats.SmoothedRTT()
	}
	h.qlogger.RecordEvent(ev)
}

func (h *sentPacketHandler) removeFromBytesInFlight(p *packet) {
	if p.includedInBytesInFlight {
		if p.Length > h.bytesInFlight {
			panic("negative bytes_in_flight")
		}
		h.bytesInFlight -= p.Length
		if p.Outstanding() {
			h.getPacketNumberSpace(p.EncryptionLevel.PacketNumberSpace()).numOutstanding--
		}
		p.includedInBytesInFlight = false
	}
}

func (h *sentPacketHandler) DropPackets(encLevel protocol.EncryptionLevel, now monotime.Time) {
	if encLevel == protocol.Encryption1RTT {
		panic(fmt.Sprintf("Cannot drop keys for encryption level %s", encLevel))
	}
	// The server won't await address validation after the handshake is confirmed.
	// This applies even if we didn't receive an ACK for a Handshake packet.
	if h.perspective == protocol.PerspectiveClient && encLevel == protocol.EncryptionHandshake {
		h.peerCompletedAddressValidation = true
	}
	// remove packets from the history and bytes_in_flight
	pnSpace := h.getPacketNumberSpace(encLevel.PacketNumberSpace())
	// We might already have dropped this packet number space.
	if pnSpace == nil {
		return
	}
	for pn, p := range h.hist.Packets() {
		if pn > pnSpace.largestSent {
			break
		}
		// no 0-RTT packets are sent after the first 1-RTT packet
		if encLevel == protocol.Encryption0RTT && p.EncryptionLevel == protocol.Encryption1RTT {
			break
		}
		if p.EncryptionLevel != encLevel {
			continue
		}
		h.removeFromBytesInFlight(p)
		h.hist.Remove(pn)
	}
	// drop the packet number space
	//nolint:exhaustive // Not every packet number space can be dropped.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.initialPackets = nil
	case protocol.EncryptionHandshake:
		// Dropping the handshake packet number space means that the handshake is confirmed,
		// see section 4.9.2 of RFC 9001.
		h.handshakeConfirmed = true
		h.handshakePackets = nil
	case protocol.Encryption0RTT:
		// This function is only called when 0-RTT is rejected,
		// and not when the client drops 0-RTT keys when the handshake completes.
	}
	if h.qlogger != nil && h.ptoCount != 0 {
		h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
	}
	h.ptoCount = 0
	h.numProbesToSend = 0
	h.ptoMode = SendNone
	h.setLossDetectionTimer(now)
}

func (h *sentPacketHandler) ReceivedBytes(n protocol.ByteCount, t monotime.Time) {
	h.connStats.BytesReceived.Add(uint64(n))
	wasAmplificationLimit := h.isAmplificationLimited()
	h.bytesReceived += n
	if wasAmplificationLimit && !h.isAmplificationLimited() {
		h.setLossDetectionTimer(t)
	}
}

func (h *sentPacketHandler) ReceivedPacket(l protocol.EncryptionLevel, t monotime.Time) {
	h.connStats.PacketsReceived.Add(1)
	if h.perspective == protocol.PerspectiveServer && l == protocol.EncryptionHandshake && !h.peerAddressValidated {
		h.peerAddressValidated = true
		h.setLossDetectionTimer(t)
	}
}

func (h *sentPacketHandler) SentPacket(
	t monotime.Time,
	pn, largestAcked protocol.PacketNumber,
	streamFrames []StreamFrame,
	frames []Frame,
	encLevel protocol.EncryptionLevel,
	ecn protocol.ECN,
	size protocol.ByteCount,
	isPathMTUProbePacket bool,
	isPathProbePacket bool,
) {
	h.bytesSent += size
	h.connStats.BytesSent.Add(uint64(size))
	h.connStats.PacketsSent.Add(1)

	pnSpace := h.getPacketNumberSpace(encLevel.PacketNumberSpace())
	pnSpace.largestSent = pn
	if encLevel.PacketNumberSpace() == protocol.PacketNumberSpaceAppData &&
		h.minPNToRelaxReordering == protocol.InvalidPacketNumber {
		h.minPNToRelaxReordering = pn
	}
	//nolint:exhaustive // Only Initial and Handshake packet numbers are stored separately.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.handshakePNs.Initial = append(h.handshakePNs.Initial, pn)
	case protocol.EncryptionHandshake:
		h.handshakePNs.Handshake = append(h.handshakePNs.Handshake, pn)
	}

	p := getPacket()
	p.SendTime = t
	p.EncryptionLevel = encLevel
	p.Length = size
	p.Frames = frames
	p.LargestAcked = largestAcked
	p.StreamFrames = streamFrames
	p.IsPathMTUProbePacket = isPathMTUProbePacket
	p.isPathProbePacket = isPathProbePacket
	isAckEliciting := p.IsAckEliciting()

	if isPathProbePacket {
		h.hist.SentPathProbePacket(pn, p)
		h.setLossDetectionTimer(t)
		return
	}
	if isAckEliciting {
		pnSpace.lastAckElicitingPacketTime = t
		h.bytesInFlight += size
		p.includedInBytesInFlight = true
		if h.numProbesToSend > 0 {
			h.numProbesToSend--
		}
	}
	h.congestion.OnPacketSent(t, h.bytesInFlight, pn, size, isAckEliciting)

	if encLevel == protocol.Encryption1RTT && h.ecnTracker != nil {
		h.ecnTracker.SentPacket(pn, ecn)
	}

	if p.Outstanding() {
		pnSpace.numOutstanding++
	}
	h.hist.SentPacket(pn, p)
	if !isAckEliciting {
		if !h.peerCompletedAddressValidation {
			h.setLossDetectionTimer(t)
		}
		return
	}
	if h.qlogger != nil {
		h.qlogMetricsUpdated()
	}
	h.setLossDetectionTimer(t)
}

func (h *sentPacketHandler) qlogMetricsUpdated() {
	var metricsUpdatedEvent qlog.MetricsUpdated
	var updated bool
	if h.rttStats.HasMeasurement() {
		if h.lastMetrics.MinRTT != h.rttStats.MinRTT() {
			metricsUpdatedEvent.MinRTT = h.rttStats.MinRTT()
			h.lastMetrics.MinRTT = metricsUpdatedEvent.MinRTT
			updated = true
		}
		if h.lastMetrics.SmoothedRTT != h.rttStats.SmoothedRTT() {
			metricsUpdatedEvent.SmoothedRTT = h.rttStats.SmoothedRTT()
			h.lastMetrics.SmoothedRTT = metricsUpdatedEvent.SmoothedRTT
			updated = true
		}
		if h.lastMetrics.LatestRTT != h.rttStats.LatestRTT() {
			metricsUpdatedEvent.LatestRTT = h.rttStats.LatestRTT()
			h.lastMetrics.LatestRTT = metricsUpdatedEvent.LatestRTT
			updated = true
		}
		if h.lastMetrics.RTTVariance != h.rttStats.MeanDeviation() {
			metricsUpdatedEvent.RTTVariance = h.rttStats.MeanDeviation()
			h.lastMetrics.RTTVariance = metricsUpdatedEvent.RTTVariance
			updated = true
		}
	}
	if cwnd := h.congestion.GetCongestionWindow(); h.lastMetrics.CongestionWindow != int(cwnd) {
		metricsUpdatedEvent.CongestionWindow = int(cwnd)
		h.lastMetrics.CongestionWindow = metricsUpdatedEvent.CongestionWindow
		updated = true
	}
	if h.lastMetrics.BytesInFlight != int(h.bytesInFlight) {
		metricsUpdatedEvent.BytesInFlight = int(h.bytesInFlight)
		h.lastMetrics.BytesInFlight = metricsUpdatedEvent.BytesInFlight
		updated = true
	}
	packetsInFlight := h.hist.NumOutstanding()
	if h.lastMetrics.PacketsInFlight != packetsInFlight {
		metricsUpdatedEvent.PacketsInFlight = packetsInFlight
		h.lastMetrics.PacketsInFlight = metricsUpdatedEvent.PacketsInFlight
		updated = true
	}
	if updated {
		h.qlogger.RecordEvent(metricsUpdatedEvent)
	}
}

func (h *sentPacketHandler) getPacketNumberSpace(space protocol.PacketNumberSpace) *packetNumberSpace {
	switch space {
	case protocol.PacketNumberSpaceInitial:
		return h.initialPackets
	case protocol.PacketNumberSpaceHandshake:
		return h.handshakePackets
	case protocol.PacketNumberSpaceAppData:
		return h.appDataPackets
	default:
		panic("invalid packet number space")
	}
}

func (h *sentPacketHandler) ReceivedAck(ack *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) (bool /* contained 1-RTT packet */, error) {
	pnSpace := h.getPacketNumberSpace(encLevel.PacketNumberSpace())

	largestAcked := ack.LargestAcked()
	if largestAcked > pnSpace.largestSent {
		return false, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received ACK for an unsent packet",
		}
	}

	// Servers complete address validation when a protected packet is received.
	if h.perspective == protocol.PerspectiveClient && !h.peerCompletedAddressValidation &&
		(encLevel == protocol.EncryptionHandshake || encLevel == protocol.Encryption1RTT) {
		h.peerCompletedAddressValidation = true
		h.logger.Debugf("Peer doesn't await address validation any longer.")
		// Make sure that the timer is reset, even if this ACK doesn't acknowledge any (ack-eliciting) packets.
		h.setLossDetectionTimer(rcvTime)
	}

	priorInFlight := h.bytesInFlight
	ackedPackets, hasAckEliciting, err := h.detectAndRemoveAckedPackets(ack, encLevel)
	if err != nil {
		return false, err
	}
	// update the RTT, if:
	// * the largest acked is newly acknowledged, AND
	// * at least one new ack-eliciting packet was acknowledged
	if len(ackedPackets) > 0 {
		if p := ackedPackets[len(ackedPackets)-1]; p.PacketNumber == ack.LargestAcked() && !p.isPathProbePacket && hasAckEliciting {
			// don't use the ack delay for Initial and Handshake packets
			var ackDelay time.Duration
			if encLevel == protocol.Encryption1RTT {
				ackDelay = min(ack.DelayTime, h.rttStats.MaxAckDelay())
			}
			if h.largestAckedTime.IsZero() || !p.SendTime.Before(h.largestAckedTime) {
				h.rttStats.UpdateRTT(rcvTime.Sub(p.SendTime), ackDelay)
				if h.logger.Debug() {
					h.logger.Debugf("\tupdated RTT: %s (σ: %s)", h.rttStats.SmoothedRTT(), h.rttStats.MeanDeviation())
				}
				h.largestAckedTime = p.SendTime
			}
			h.congestion.MaybeExitSlowStart()
		}
	}

	// Detect spurious losses even if no outstanding packets were newly acknowledged.
	var spuriousLosses []protocol.PacketNumber
	var timeThresholdIncreased bool
	if encLevel == protocol.Encryption1RTT {
		spuriousLosses, timeThresholdIncreased = h.detectSpuriousLosses(
			ack,
			rcvTime.Add(-min(ack.DelayTime, h.rttStats.MaxAckDelay())),
		)
		// clean up lost packet history
		h.lostPackets.DeleteBefore(rcvTime.Add(-3 * h.rttStats.PTO(false)))
	}
	if len(ackedPackets) > 0 {
		// Only inform the ECN tracker about new 1-RTT ACKs if the ACK increases the largest acked.
		if encLevel == protocol.Encryption1RTT && h.ecnTracker != nil && largestAcked > pnSpace.largestAcked {
			congested := h.ecnTracker.HandleNewlyAcked(ackedPackets, int64(ack.ECT0), int64(ack.ECT1), int64(ack.ECNCE))
			if congested {
				h.congestion.OnCongestionEvent(largestAcked, 0, priorInFlight)
			}
		}

		pnSpace.largestAcked = max(pnSpace.largestAcked, largestAcked)
	}
	// new acked packets can advance largestAcked or update the RTT,
	// and a larger time threshold moves the loss deadline
	if len(ackedPackets) > 0 || timeThresholdIncreased {
		h.detectLostPackets(rcvTime, encLevel)
		if encLevel == protocol.Encryption1RTT {
			h.detectLostPathProbes(rcvTime)
		}
	}
	// report spurious losses after any new congestion events from this ACK
	for _, pn := range spuriousLosses {
		h.congestion.OnSpuriousLoss(pn)
	}
	if len(ackedPackets) == 0 {
		if len(spuriousLosses) > 0 && h.qlogger != nil {
			h.qlogMetricsUpdated()
		}
		if timeThresholdIncreased {
			h.setLossDetectionTimer(rcvTime)
		}
		return false, nil
	}

	var acked1RTTPacket bool
	for _, p := range ackedPackets {
		if p.includedInBytesInFlight {
			h.congestion.OnPacketAcked(p.PacketNumber, p.Length, priorInFlight, rcvTime)
		}
		if p.EncryptionLevel == protocol.Encryption1RTT {
			acked1RTTPacket = true
		}
		h.removeFromBytesInFlight(p.packet)
		if !p.isPathProbePacket {
			putPacket(p.packet)
		}
	}

	// After this point, we must not use ackedPackets any longer!
	// We've already returned the buffers.
	ackedPackets = nil    //nolint:ineffassign // This is just to be on the safe side.
	clear(h.ackedPackets) // make sure the memory is released
	h.ackedPackets = h.ackedPackets[:0]

	// Reset the pto_count unless the client is unsure if the server has validated the client's address.
	if h.peerCompletedAddressValidation {
		if h.qlogger != nil && h.ptoCount != 0 {
			h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
		}
		h.ptoCount = 0
	}
	h.numProbesToSend = 0

	if h.qlogger != nil {
		h.qlogMetricsUpdated()
	}

	h.setLossDetectionTimer(rcvTime)
	return acked1RTTPacket, nil
}

func (h *sentPacketHandler) detectSpuriousLosses(ack *wire.AckFrame, ackTime monotime.Time) (_ []protocol.PacketNumber, timeThresholdIncreased bool) {
	var maxPacketReordering protocol.PacketNumber
	var maxTimeReordering time.Duration
	var packetThresholdChanged bool
	ackRangeIdx := len(ack.AckRanges) - 1
	var spuriousLosses []protocol.PacketNumber
	for pn, sendTime := range h.lostPackets.All() {
		ackRange := ack.AckRanges[ackRangeIdx]
		for pn > ackRange.Largest && ackRangeIdx > 0 {
			ackRangeIdx--
			ackRange = ack.AckRanges[ackRangeIdx]
		}
		if pn < ackRange.Smallest {
			continue
		}
		if pn <= ackRange.Largest {
			if !h.packetThresholdDisabled {
				h.packetThresholdDisabled = true
				packetThresholdChanged = true
			}
			packetReordering := h.hist.Difference(ack.LargestAcked(), pn)
			timeReordering := ackTime.Sub(sendTime)
			maxPacketReordering = max(maxPacketReordering, packetReordering)
			if h.minPNToRelaxReordering != protocol.InvalidPacketNumber && pn >= h.minPNToRelaxReordering {
				maxTimeReordering = max(maxTimeReordering, timeReordering)
			}

			if h.qlogger != nil {
				h.qlogger.RecordEvent(qlog.SpuriousLoss{
					EncryptionLevel:  protocol.Encryption1RTT,
					PacketNumber:     pn,
					PacketReordering: uint64(packetReordering),
					TimeReordering:   timeReordering,
				})
			}
			spuriousLosses = append(spuriousLosses, pn)
		}
	}
	for _, pn := range spuriousLosses {
		h.lostPackets.Delete(pn)
	}
	lossDelay := max(
		max(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT())*time.Duration(8+h.timeThresholdEighths)/8,
		protocol.TimerGranularity,
	)
	if maxTimeReordering > lossDelay && h.timeThresholdEighths < maxTimeThresholdEighths {
		h.timeThresholdEighths = min(2*h.timeThresholdEighths, maxTimeThresholdEighths)
		h.minPNToRelaxReordering = protocol.InvalidPacketNumber
		timeThresholdIncreased = true
	}
	if packetThresholdChanged || timeThresholdIncreased {
		h.qlogRecoveryParametersSet(false)
	}
	return spuriousLosses, timeThresholdIncreased
}

// Packets are returned in ascending packet number order.
func (h *sentPacketHandler) detectAndRemoveAckedPackets(
	ack *wire.AckFrame,
	encLevel protocol.EncryptionLevel,
) (_ []packetWithPacketNumber, hasAckEliciting bool, _ error) {
	if len(h.ackedPackets) > 0 {
		return nil, false, errors.New("ackhandler BUG: ackedPackets slice not empty")
	}

	if encLevel == protocol.Encryption1RTT {
		for p := range h.hist.SkippedPackets() {
			if ack.AcksPacket(p) {
				return nil, false, &qerr.TransportError{
					ErrorCode:    qerr.ProtocolViolation,
					ErrorMessage: fmt.Sprintf("received an ACK for skipped packet number: %d (%s)", p, encLevel),
				}
			}
		}
	}

	var ackRangeIndex int
	lowestAcked := ack.LowestAcked()
	largestAcked := ack.LargestAcked()
	for pn, p := range h.hist.Packets() {
		// ignore packets below the lowest acked
		if pn < lowestAcked {
			continue
		}
		if pn > largestAcked {
			break
		}
		if p.EncryptionLevel.PacketNumberSpace() != encLevel.PacketNumberSpace() {
			continue
		}

		if ack.HasMissingRanges() {
			ackRange := ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]

			for pn > ackRange.Largest && ackRangeIndex < len(ack.AckRanges)-1 {
				ackRangeIndex++
				ackRange = ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]
			}

			if pn < ackRange.Smallest { // packet not contained in ACK range
				continue
			}
			if pn > ackRange.Largest {
				return nil, false, fmt.Errorf("BUG: ackhandler would have acked wrong packet %d, while evaluating range %d -> %d", pn, ackRange.Smallest, ackRange.Largest)
			}
		}
		if p.isPathProbePacket {
			probePacket := h.hist.RemovePathProbe(pn)
			// the probe packet might already have been declared lost
			if probePacket != nil {
				h.ackedPackets = append(h.ackedPackets, packetWithPacketNumber{PacketNumber: pn, packet: probePacket})
			}
			continue
		}
		if p.IsAckEliciting() {
			hasAckEliciting = true
		}
		h.ackedPackets = append(h.ackedPackets, packetWithPacketNumber{PacketNumber: pn, packet: p})
	}
	if h.logger.Debug() && len(h.ackedPackets) > 0 {
		pns := make([]protocol.PacketNumber, len(h.ackedPackets))
		for i, p := range h.ackedPackets {
			pns[i] = p.PacketNumber
		}
		h.logger.Debugf("\tnewly acked packets (%d): %d", len(pns), pns)
	}

	for _, p := range h.ackedPackets {
		if p.LargestAcked != protocol.InvalidPacketNumber && encLevel == protocol.Encryption1RTT && h.ignorePacketsBelow != nil {
			h.ignorePacketsBelow(p.LargestAcked + 1)
		}

		for _, f := range p.Frames {
			if f.Handler != nil {
				f.Handler.OnAcked(f.Frame)
			}
		}
		for _, f := range p.StreamFrames {
			if f.Handler != nil {
				f.Handler.OnAcked(f.Frame)
			}
		}
		if err := h.hist.Remove(p.PacketNumber); err != nil {
			return nil, false, err
		}
	}
	// TODO: add support for the transport:packets_acked qlog event
	return h.ackedPackets, hasAckEliciting, nil
}

func (h *sentPacketHandler) getLossTimeAndSpace() (monotime.Time, protocol.EncryptionLevel) {
	var encLevel protocol.EncryptionLevel
	var lossTime monotime.Time

	if h.initialPackets != nil {
		lossTime = h.initialPackets.lossTime
		encLevel = protocol.EncryptionInitial
	}
	if h.handshakePackets != nil && (lossTime.IsZero() || (!h.handshakePackets.lossTime.IsZero() && h.handshakePackets.lossTime.Before(lossTime))) {
		lossTime = h.handshakePackets.lossTime
		encLevel = protocol.EncryptionHandshake
	}
	if lossTime.IsZero() || (!h.appDataPackets.lossTime.IsZero() && h.appDataPackets.lossTime.Before(lossTime)) {
		lossTime = h.appDataPackets.lossTime
		encLevel = protocol.Encryption1RTT
	}
	return lossTime, encLevel
}

func (h *sentPacketHandler) getScaledPTO(includeMaxAckDelay bool) time.Duration {
	pto := h.rttStats.PTO(includeMaxAckDelay) << h.ptoCount
	if pto > maxPTODuration || pto <= 0 {
		return maxPTODuration
	}
	return pto
}

// same logic as getLossTimeAndSpace, but for lastAckElicitingPacketTime instead of lossTime
func (h *sentPacketHandler) getPTOTimeAndSpace(now monotime.Time) (pto monotime.Time, encLevel protocol.EncryptionLevel) {
	// We only send application data probe packets once the handshake is confirmed,
	// because before that, we don't have the keys to decrypt ACKs sent in 1-RTT packets.
	if !h.handshakeConfirmed && !h.hasOutstandingCryptoPackets() {
		if h.peerCompletedAddressValidation {
			return
		}
		t := now.Add(h.getScaledPTO(false))
		if h.initialPackets != nil {
			return t, protocol.EncryptionInitial
		}
		return t, protocol.EncryptionHandshake
	}

	if h.initialPackets != nil && h.initialPackets.numOutstanding > 0 &&
		!h.initialPackets.lastAckElicitingPacketTime.IsZero() {
		encLevel = protocol.EncryptionInitial
		if t := h.initialPackets.lastAckElicitingPacketTime; !t.IsZero() {
			pto = t.Add(h.getScaledPTO(false))
		}
	}
	if h.handshakePackets != nil && h.handshakePackets.numOutstanding > 0 &&
		!h.handshakePackets.lastAckElicitingPacketTime.IsZero() {
		t := h.handshakePackets.lastAckElicitingPacketTime.Add(h.getScaledPTO(false))
		if pto.IsZero() || (!t.IsZero() && t.Before(pto)) {
			pto = t
			encLevel = protocol.EncryptionHandshake
		}
	}
	if h.handshakeConfirmed && h.appDataPackets.numOutstanding > 0 &&
		!h.appDataPackets.lastAckElicitingPacketTime.IsZero() {
		t := h.appDataPackets.lastAckElicitingPacketTime.Add(h.getScaledPTO(true))
		if pto.IsZero() || (!t.IsZero() && t.Before(pto)) {
			pto = t
			encLevel = protocol.Encryption1RTT
		}
	}
	return pto, encLevel
}

func (h *sentPacketHandler) hasOutstandingCryptoPackets() bool {
	if h.initialPackets != nil && h.initialPackets.numOutstanding > 0 {
		return true
	}
	if h.handshakePackets != nil && h.handshakePackets.numOutstanding > 0 {
		return true
	}
	return false
}

func (h *sentPacketHandler) setLossDetectionTimer(now monotime.Time) {
	oldAlarm := h.alarm // only needed in case tracing is enabled
	newAlarm := h.lossDetectionTime(now)
	h.alarm = newAlarm

	hasAlarm := !newAlarm.Time.IsZero()
	if !hasAlarm && !oldAlarm.Time.IsZero() {
		h.logger.Debugf("Canceling loss detection timer.")
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.LossTimerUpdated{
				Type: qlog.LossTimerUpdateTypeCancelled,
			})
		}
	}

	if h.qlogger != nil && hasAlarm && newAlarm != oldAlarm {
		h.qlogger.RecordEvent(qlog.LossTimerUpdated{
			Type:      qlog.LossTimerUpdateTypeSet,
			TimerType: newAlarm.TimerType,
			EncLevel:  newAlarm.EncryptionLevel,
			Time:      newAlarm.Time.ToTime(),
		})
	}
}

func (h *sentPacketHandler) lossDetectionTime(now monotime.Time) alarmTimer {
	// cancel the alarm if no packets are outstanding
	if h.peerCompletedAddressValidation && !h.hist.HasOutstandingPackets() && !h.hist.HasOutstandingPathProbes() {
		return alarmTimer{}
	}

	// cancel the alarm if amplification limited
	if h.isAmplificationLimited() {
		return alarmTimer{}
	}

	var pathProbeLossTime monotime.Time
	if h.hist.HasOutstandingPathProbes() {
		if _, p := h.hist.FirstOutstandingPathProbe(); p != nil {
			pathProbeLossTime = p.SendTime.Add(pathProbePacketLossTimeout)
		}
	}

	// early retransmit timer or time loss detection
	lossTime, encLevel := h.getLossTimeAndSpace()
	if !lossTime.IsZero() && (pathProbeLossTime.IsZero() || lossTime.Before(pathProbeLossTime)) {
		return alarmTimer{
			Time:            lossTime,
			TimerType:       qlog.TimerTypeACK,
			EncryptionLevel: encLevel,
		}
	}
	ptoTime, encLevel := h.getPTOTimeAndSpace(now)
	if !ptoTime.IsZero() && (pathProbeLossTime.IsZero() || ptoTime.Before(pathProbeLossTime)) {
		return alarmTimer{
			Time:            ptoTime,
			TimerType:       qlog.TimerTypePTO,
			EncryptionLevel: encLevel,
		}
	}
	if !pathProbeLossTime.IsZero() {
		return alarmTimer{
			Time:            pathProbeLossTime,
			TimerType:       qlog.TimerTypePathProbe,
			EncryptionLevel: protocol.Encryption1RTT,
		}
	}
	return alarmTimer{}
}

func (h *sentPacketHandler) detectLostPathProbes(now monotime.Time) {
	if !h.hist.HasOutstandingPathProbes() {
		return
	}
	lossTime := now.Add(-pathProbePacketLossTimeout)
	// RemovePathProbe cannot be called while iterating.
	var lostPathProbes []packetWithPacketNumber
	for pn, p := range h.hist.PathProbes() {
		if !p.SendTime.After(lossTime) {
			lostPathProbes = append(lostPathProbes, packetWithPacketNumber{PacketNumber: pn, packet: p})
		}
	}
	for _, p := range lostPathProbes {
		for _, f := range p.Frames {
			f.Handler.OnLost(f.Frame)
		}
		h.hist.RemovePathProbe(p.PacketNumber)
	}
}

func countPacketNumbers(pns []protocol.PacketNumber, lower, upper protocol.PacketNumber) protocol.PacketNumber {
	if len(pns) == 0 || pns[len(pns)-1] <= lower {
		return 0
	}
	var count protocol.PacketNumber
	for _, pn := range pns {
		if pn > lower && pn <= upper {
			count++
		}
	}
	return count
}

func (h *sentPacketHandler) detectLostPackets(now monotime.Time, encLevel protocol.EncryptionLevel) {
	pnSpace := h.getPacketNumberSpace(encLevel.PacketNumberSpace())
	pnSpace.lossTime = 0
	space := encLevel.PacketNumberSpace()
	usePacketThreshold := space != protocol.PacketNumberSpaceAppData || !h.packetThresholdDisabled
	timeThresholdEighths := uint8(defaultTimeThresholdEighths)
	if space == protocol.PacketNumberSpaceAppData {
		timeThresholdEighths = h.timeThresholdEighths
	}

	lossDelay := max(
		max(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT())*time.Duration(8+timeThresholdEighths)/8,
		protocol.TimerGranularity,
	)

	// Packets sent before this time are deemed lost.
	lostSendTime := now.Add(-lossDelay)

	priorInFlight := h.bytesInFlight
	for pn, p := range h.hist.Packets() {
		if pn > pnSpace.largestAcked {
			break
		}
		if p.EncryptionLevel.PacketNumberSpace() != space {
			continue
		}

		var distance protocol.PacketNumber
		switch space {
		case protocol.PacketNumberSpaceInitial:
			distance = countPacketNumbers(h.handshakePNs.Initial, pn, pnSpace.largestAcked)
		case protocol.PacketNumberSpaceHandshake:
			distance = countPacketNumbers(h.handshakePNs.Handshake, pn, pnSpace.largestAcked)
		case protocol.PacketNumberSpaceAppData:
			distance = h.hist.Difference(pnSpace.largestAcked, pn)
			if h.handshakePNs != nil {
				distance -= countPacketNumbers(h.handshakePNs.Initial, pn, pnSpace.largestAcked)
				distance -= countPacketNumbers(h.handshakePNs.Handshake, pn, pnSpace.largestAcked)
			}
		}
		var packetLost bool
		if !p.SendTime.After(lostSendTime) {
			packetLost = true
			if !p.isPathProbePacket && p.IsAckEliciting() {
				if h.logger.Debug() {
					h.logger.Debugf("\tlost packet %d (time threshold)", pn)
				}
				if h.qlogger != nil {
					h.qlogger.RecordEvent(qlog.PacketLost{
						Header: qlog.PacketHeader{
							PacketType:   qlog.EncryptionLevelToPacketType(p.EncryptionLevel),
							PacketNumber: pn,
						},
						Trigger: qlog.PacketLossTimeThreshold,
					})
				}
			}
		} else if usePacketThreshold && distance >= packetThreshold {
			packetLost = true
			if !p.isPathProbePacket && p.IsAckEliciting() {
				if h.logger.Debug() {
					h.logger.Debugf("\tlost packet %d (reordering threshold)", pn)
				}
				if h.qlogger != nil {
					h.qlogger.RecordEvent(qlog.PacketLost{
						Header: qlog.PacketHeader{
							PacketType:   qlog.EncryptionLevelToPacketType(p.EncryptionLevel),
							PacketNumber: pn,
						},
						Trigger: qlog.PacketLossReorderingThreshold,
					})
				}
			}
		} else if pnSpace.lossTime.IsZero() {
			// Note: This conditional is only entered once per call
			lossTime := p.SendTime.Add(lossDelay)
			if h.logger.Debug() {
				h.logger.Debugf("\tsetting loss timer for packet %d (%s) to %s (in %s)", pn, encLevel, lossDelay, lossTime)
			}
			pnSpace.lossTime = lossTime
		}
		if packetLost {
			if p.Outstanding() && space == protocol.PacketNumberSpaceAppData {
				h.lostPackets.Add(pn, p.SendTime)
			}
			h.hist.DeclareLost(pn)
			if !p.isPathProbePacket && p.IsAckEliciting() {
				// the bytes in flight need to be reduced no matter if the frames in this packet will be retransmitted
				h.removeFromBytesInFlight(p)
				h.queueFramesForRetransmission(p)
				if !p.IsPathMTUProbePacket {
					h.congestion.OnCongestionEvent(pn, p.Length, priorInFlight)
				}
				if encLevel == protocol.Encryption1RTT && h.ecnTracker != nil {
					h.ecnTracker.LostPacket(pn)
				}
			}
		}
	}
	if h.handshakeConfirmed && h.handshakePNs != nil {
		firstPN := h.hist.FirstPacketNumber()
		highestPN := h.handshakePNs.Highest()
		if firstPN == protocol.InvalidPacketNumber || highestPN == protocol.InvalidPacketNumber || firstPN > highestPN {
			h.handshakePNs = nil
		}
	}
}

func (h *sentPacketHandler) OnLossDetectionTimeout(now monotime.Time) error {
	defer h.setLossDetectionTimer(now)

	if h.handshakeConfirmed {
		h.detectLostPathProbes(now)
	}

	earliestLossTime, encLevel := h.getLossTimeAndSpace()
	if !earliestLossTime.IsZero() {
		if h.logger.Debug() {
			h.logger.Debugf("Loss detection alarm fired in loss timer mode. Loss time: %s", earliestLossTime)
		}
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.LossTimerUpdated{
				Type:      qlog.LossTimerUpdateTypeExpired,
				TimerType: qlog.TimerTypeACK,
				EncLevel:  encLevel,
			})
		}
		// Early retransmit or time loss detection
		h.detectLostPackets(now, encLevel)
		return nil
	}

	// PTO
	// When all outstanding are acknowledged, the alarm is canceled in setLossDetectionTimer.
	// However, there's no way to reset the timer in the connection.
	// When OnLossDetectionTimeout is called, we therefore need to make sure that there are
	// actually packets outstanding.
	if h.bytesInFlight == 0 && !h.peerCompletedAddressValidation {
		h.ptoCount++
		h.numProbesToSend++
		if h.initialPackets != nil {
			h.ptoMode = SendPTOInitial
		} else if h.handshakePackets != nil {
			h.ptoMode = SendPTOHandshake
		} else {
			return errors.New("sentPacketHandler BUG: PTO fired, but bytes_in_flight is 0 and Initial and Handshake already dropped")
		}
		return nil
	}

	ptoTime, encLevel := h.getPTOTimeAndSpace(now)
	if ptoTime.IsZero() {
		return nil
	}
	ps := h.getPacketNumberSpace(encLevel.PacketNumberSpace())
	if ps.numOutstanding == 0 && (encLevel != protocol.Encryption1RTT || !h.hist.HasOutstandingPathProbes()) && !h.peerCompletedAddressValidation {
		return nil
	}
	h.ptoCount++
	if h.logger.Debug() {
		h.logger.Debugf("Loss detection alarm for %s fired in PTO mode. PTO count: %d", encLevel, h.ptoCount)
	}
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.LossTimerUpdated{
			Type:      qlog.LossTimerUpdateTypeExpired,
			TimerType: qlog.TimerTypePTO,
			EncLevel:  encLevel,
		})
		h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: h.ptoCount})
	}
	h.numProbesToSend += 2
	//nolint:exhaustive // We never arm a PTO timer for 0-RTT packets.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.ptoMode = SendPTOInitial
	case protocol.EncryptionHandshake:
		h.ptoMode = SendPTOHandshake
	case protocol.Encryption1RTT:
		// skip a packet number in order to elicit an immediate ACK
		pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
		h.hist.SkippedPacket(pn)
		h.ptoMode = SendPTOAppData
	default:
		return fmt.Errorf("PTO timer in unexpected encryption level: %s", encLevel)
	}
	return nil
}

func (h *sentPacketHandler) GetLossDetectionTimeout() monotime.Time {
	return h.alarm.Time
}

func (h *sentPacketHandler) ECNMode(isShortHeaderPacket bool) protocol.ECN {
	if !h.enableECN {
		return protocol.ECNUnsupported
	}
	if !isShortHeaderPacket {
		return protocol.ECNNon
	}
	return h.ecnTracker.Mode()
}

func (h *sentPacketHandler) PeekPacketNumber(space protocol.PacketNumberSpace) (protocol.PacketNumber, protocol.PacketNumberLen) {
	pnSpace := h.getPacketNumberSpace(space)
	pn := h.pns.Peek(space == protocol.PacketNumberSpaceAppData)
	// See section 17.1 of RFC 9000.
	return pn, protocol.PacketNumberLengthForHeader(pn, pnSpace.largestAcked)
}

func (h *sentPacketHandler) PopPacketNumber(space protocol.PacketNumberSpace) protocol.PacketNumber {
	skipped, pn := h.pns.Pop(space == protocol.PacketNumberSpaceAppData)
	if skipped {
		skippedPN := pn - 1
		h.hist.SkippedPacket(skippedPN)
		if h.logger.Debug() {
			h.logger.Debugf("Skipping packet number %d", skippedPN)
		}
	}
	return pn
}

func (h *sentPacketHandler) SendMode(now monotime.Time) SendMode {
	numTrackedPackets := h.hist.Len()

	if h.isAmplificationLimited() {
		h.logger.Debugf("Amplification window limited. Received %d bytes, already sent out %d bytes", h.bytesReceived, h.bytesSent)
		return SendNone
	}
	// Don't send any packets if we're keeping track of the maximum number of packets.
	// Note that since MaxOutstandingSentPackets is smaller than MaxTrackedSentPackets,
	// we will stop sending out new data when reaching MaxOutstandingSentPackets,
	// but still allow sending of retransmissions and ACKs.
	if numTrackedPackets >= protocol.MaxTrackedSentPackets {
		if h.logger.Debug() {
			h.logger.Debugf("Limited by the number of tracked packets: tracking %d packets, maximum %d", numTrackedPackets, protocol.MaxTrackedSentPackets)
		}
		return SendNone
	}
	if h.numProbesToSend > 0 {
		return h.ptoMode
	}
	// Only send ACKs if we're congestion limited.
	if !h.congestion.CanSend(h.bytesInFlight) {
		if h.logger.Debug() {
			h.logger.Debugf("Congestion limited: bytes in flight %d, window %d", h.bytesInFlight, h.congestion.GetCongestionWindow())
		}
		return SendAck
	}
	if numTrackedPackets >= protocol.MaxOutstandingSentPackets {
		if h.logger.Debug() {
			h.logger.Debugf("Max outstanding limited: tracking %d packets, maximum: %d", numTrackedPackets, protocol.MaxOutstandingSentPackets)
		}
		return SendAck
	}
	if !h.congestion.HasPacingBudget(now) {
		return SendPacingLimited
	}
	return SendAny
}

func (h *sentPacketHandler) TimeUntilSend() monotime.Time {
	return h.congestion.TimeUntilSend(h.bytesInFlight)
}

func (h *sentPacketHandler) SetMaxDatagramSize(s protocol.ByteCount) {
	h.congestion.SetMaxDatagramSize(s)
}

func (h *sentPacketHandler) isAmplificationLimited() bool {
	if h.peerAddressValidated {
		return false
	}
	return h.bytesSent >= amplificationFactor*h.bytesReceived
}

func (h *sentPacketHandler) QueueProbePacket(space protocol.PacketNumberSpace) bool {
	pn, p := h.hist.FirstOutstanding(space)
	if p == nil {
		return false
	}
	// TODO: don't declare the packet lost here.
	// Keep track of acknowledged frames instead.
	// Call DeclareLost before queueFramesForRetransmission, which clears the packet's frames.
	h.hist.DeclareLost(pn)
	h.removeFromBytesInFlight(p)
	h.queueFramesForRetransmission(p)
	return true
}

func (h *sentPacketHandler) queueFramesForRetransmission(p *packet) {
	if len(p.Frames) == 0 && len(p.StreamFrames) == 0 {
		panic("no frames")
	}
	for _, f := range p.Frames {
		if f.Handler != nil {
			f.Handler.OnLost(f.Frame)
		}
	}
	for _, f := range p.StreamFrames {
		if f.Handler != nil {
			f.Handler.OnLost(f.Frame)
		}
	}
	p.StreamFrames = nil
	p.Frames = nil
}

func (h *sentPacketHandler) ResetForRetry(now monotime.Time) {
	h.bytesInFlight = 0
	var firstPacketSendTime monotime.Time
	// Only Initial and 0-RTT packets can have been sent before a Retry.
	for _, p := range h.hist.Packets() {
		if p.EncryptionLevel == protocol.EncryptionInitial && firstPacketSendTime.IsZero() {
			firstPacketSendTime = p.SendTime
		}
		if p.IsAckEliciting() {
			h.queueFramesForRetransmission(p)
		}
	}

	// Only use the Retry to estimate the RTT if we didn't send any retransmission for the Initial.
	// Otherwise, we don't know which Initial the Retry was sent in response to.
	if h.ptoCount == 0 {
		// Don't set the RTT to a value lower than 5ms here.
		h.rttStats.UpdateRTT(max(minRTTAfterRetry, now.Sub(firstPacketSendTime)), 0)
		if h.logger.Debug() {
			h.logger.Debugf("\tupdated RTT: %s (σ: %s)", h.rttStats.SmoothedRTT(), h.rttStats.MeanDeviation())
		}
		if h.qlogger != nil {
			h.qlogMetricsUpdated()
		}
	}
	h.hist = *newSentPacketHistory()
	h.handshakePNs.Initial = h.handshakePNs.Initial[:0]
	h.handshakePNs.Handshake = h.handshakePNs.Handshake[:0]
	h.initialPackets = newPacketNumberSpace()
	h.appDataPackets = newPacketNumberSpace()
	oldAlarm := h.alarm
	h.alarm = alarmTimer{}
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
		if !oldAlarm.Time.IsZero() {
			h.qlogger.RecordEvent(qlog.LossTimerUpdated{
				Type: qlog.LossTimerUpdateTypeCancelled,
			})
		}
	}
	h.ptoCount = 0
}

func (h *sentPacketHandler) MigratedPath(now monotime.Time, initialMaxDatagramSize protocol.ByteCount) {
	h.rttStats.ResetForPathMigration()
	h.packetThresholdDisabled = false
	h.timeThresholdEighths = defaultTimeThresholdEighths
	h.minPNToRelaxReordering = protocol.InvalidPacketNumber
	h.lostPackets.Reset()
	for pn, p := range h.hist.Packets() {
		if p.EncryptionLevel.PacketNumberSpace() != protocol.PacketNumberSpaceAppData {
			continue
		}
		h.hist.DeclareLost(pn)
		if !p.isPathProbePacket {
			h.removeFromBytesInFlight(p)
			if p.IsAckEliciting() {
				h.queueFramesForRetransmission(p)
			}
		}
	}
	for pn := range h.hist.PathProbes() {
		h.hist.RemovePathProbe(pn)
	}
	h.congestion = congestion.NewCubicSender(
		congestion.DefaultClock{},
		h.rttStats,
		h.connStats,
		initialMaxDatagramSize,
		true, // use Reno
		h.qlogger,
	)
	h.qlogRecoveryParametersSet(true)
	h.setLossDetectionTimer(now)
}
