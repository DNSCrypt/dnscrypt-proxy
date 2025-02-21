package ackhandler

import (
	"errors"
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
)

const (
	// Maximum reordering in time space before time based loss detection considers a packet lost.
	// Specified as an RTT multiplier.
	timeThreshold = 9.0 / 8
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
	history sentPacketHistory
	pns     packetNumberGenerator

	lossTime                   time.Time
	lastAckElicitingPacketTime time.Time

	largestAcked protocol.PacketNumber
	largestSent  protocol.PacketNumber
}

func newPacketNumberSpace(initialPN protocol.PacketNumber, isAppData bool) *packetNumberSpace {
	var pns packetNumberGenerator
	if isAppData {
		pns = newSkippingPacketNumberGenerator(initialPN, protocol.SkipPacketInitialPeriod, protocol.SkipPacketMaxPeriod)
	} else {
		pns = newSequentialPacketNumberGenerator(initialPN)
	}
	return &packetNumberSpace{
		history:      *newSentPacketHistory(isAppData),
		pns:          pns,
		largestSent:  protocol.InvalidPacketNumber,
		largestAcked: protocol.InvalidPacketNumber,
	}
}

type alarmTimer struct {
	Time            time.Time
	TimerType       logging.TimerType
	EncryptionLevel protocol.EncryptionLevel
}

type sentPacketHandler struct {
	initialPackets   *packetNumberSpace
	handshakePackets *packetNumberSpace
	appDataPackets   *packetNumberSpace

	// Do we know that the peer completed address validation yet?
	// Always true for the server.
	peerCompletedAddressValidation bool
	bytesReceived                  protocol.ByteCount
	bytesSent                      protocol.ByteCount
	// Have we validated the peer's address yet?
	// Always true for the client.
	peerAddressValidated bool

	handshakeConfirmed bool

	// lowestNotConfirmedAcked is the lowest packet number that we sent an ACK for, but haven't received confirmation, that this ACK actually arrived
	// example: we send an ACK for packets 90-100 with packet number 20
	// once we receive an ACK from the peer for packet 20, the lowestNotConfirmedAcked is 101
	// Only applies to the application-data packet number space.
	lowestNotConfirmedAcked protocol.PacketNumber

	ackedPackets []*packet // to avoid allocations in detectAndRemoveAckedPackets

	bytesInFlight protocol.ByteCount

	congestion congestion.SendAlgorithmWithDebugInfos
	rttStats   *utils.RTTStats

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

	tracer *logging.ConnectionTracer
	logger utils.Logger
}

var (
	_ SentPacketHandler = &sentPacketHandler{}
	_ sentPacketTracker = &sentPacketHandler{}
)

// clientAddressValidated indicates whether the address was validated beforehand by an address validation token.
// If the address was validated, the amplification limit doesn't apply. It has no effect for a client.
func newSentPacketHandler(
	initialPN protocol.PacketNumber,
	initialMaxDatagramSize protocol.ByteCount,
	rttStats *utils.RTTStats,
	clientAddressValidated bool,
	enableECN bool,
	pers protocol.Perspective,
	tracer *logging.ConnectionTracer,
	logger utils.Logger,
) *sentPacketHandler {
	congestion := congestion.NewCubicSender(
		congestion.DefaultClock{},
		rttStats,
		initialMaxDatagramSize,
		true, // use Reno
		tracer,
	)

	h := &sentPacketHandler{
		peerCompletedAddressValidation: pers == protocol.PerspectiveServer,
		peerAddressValidated:           pers == protocol.PerspectiveClient || clientAddressValidated,
		initialPackets:                 newPacketNumberSpace(initialPN, false),
		handshakePackets:               newPacketNumberSpace(0, false),
		appDataPackets:                 newPacketNumberSpace(0, true),
		rttStats:                       rttStats,
		congestion:                     congestion,
		perspective:                    pers,
		tracer:                         tracer,
		logger:                         logger,
	}
	if enableECN {
		h.enableECN = true
		h.ecnTracker = newECNTracker(logger, tracer)
	}
	return h
}

func (h *sentPacketHandler) removeFromBytesInFlight(p *packet) {
	if p.includedInBytesInFlight {
		if p.Length > h.bytesInFlight {
			panic("negative bytes_in_flight")
		}
		h.bytesInFlight -= p.Length
		p.includedInBytesInFlight = false
	}
}

func (h *sentPacketHandler) DropPackets(encLevel protocol.EncryptionLevel, now time.Time) {
	// The server won't await address validation after the handshake is confirmed.
	// This applies even if we didn't receive an ACK for a Handshake packet.
	if h.perspective == protocol.PerspectiveClient && encLevel == protocol.EncryptionHandshake {
		h.peerCompletedAddressValidation = true
	}
	// remove outstanding packets from bytes_in_flight
	if encLevel == protocol.EncryptionInitial || encLevel == protocol.EncryptionHandshake {
		pnSpace := h.getPacketNumberSpace(encLevel)
		// We might already have dropped this packet number space.
		if pnSpace == nil {
			return
		}
		for p := range pnSpace.history.Packets() {
			h.removeFromBytesInFlight(p)
		}
	}
	// drop the packet history
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
		// When 0-RTT is rejected, all application data sent so far becomes invalid.
		// Delete the packets from the history and remove them from bytes_in_flight.
		for p := range h.appDataPackets.history.Packets() {
			if p.EncryptionLevel != protocol.Encryption0RTT && !p.skippedPacket {
				break
			}
			h.removeFromBytesInFlight(p)
			h.appDataPackets.history.Remove(p.PacketNumber)
		}
	default:
		panic(fmt.Sprintf("Cannot drop keys for encryption level %s", encLevel))
	}
	if h.tracer != nil && h.tracer.UpdatedPTOCount != nil && h.ptoCount != 0 {
		h.tracer.UpdatedPTOCount(0)
	}
	h.ptoCount = 0
	h.numProbesToSend = 0
	h.ptoMode = SendNone
	h.setLossDetectionTimer(now)
}

func (h *sentPacketHandler) ReceivedBytes(n protocol.ByteCount, t time.Time) {
	wasAmplificationLimit := h.isAmplificationLimited()
	h.bytesReceived += n
	if wasAmplificationLimit && !h.isAmplificationLimited() {
		h.setLossDetectionTimer(t)
	}
}

func (h *sentPacketHandler) ReceivedPacket(l protocol.EncryptionLevel, t time.Time) {
	if h.perspective == protocol.PerspectiveServer && l == protocol.EncryptionHandshake && !h.peerAddressValidated {
		h.peerAddressValidated = true
		h.setLossDetectionTimer(t)
	}
}

func (h *sentPacketHandler) packetsInFlight() int {
	packetsInFlight := h.appDataPackets.history.Len()
	if h.handshakePackets != nil {
		packetsInFlight += h.handshakePackets.history.Len()
	}
	if h.initialPackets != nil {
		packetsInFlight += h.initialPackets.history.Len()
	}
	return packetsInFlight
}

func (h *sentPacketHandler) SentPacket(
	t time.Time,
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

	pnSpace := h.getPacketNumberSpace(encLevel)
	if h.logger.Debug() && (pnSpace.history.HasOutstandingPackets() || pnSpace.history.HasOutstandingPathProbes()) {
		for p := max(0, pnSpace.largestSent+1); p < pn; p++ {
			h.logger.Debugf("Skipping packet number %d", p)
		}
	}

	pnSpace.largestSent = pn
	isAckEliciting := len(streamFrames) > 0 || len(frames) > 0

	if isPathProbePacket {
		p := getPacket()
		p.SendTime = t
		p.PacketNumber = pn
		p.EncryptionLevel = encLevel
		p.Length = size
		p.Frames = frames
		p.isPathProbePacket = true
		pnSpace.history.SentPathProbePacket(p)
		h.setLossDetectionTimer(t)
		return
	}
	if isAckEliciting {
		pnSpace.lastAckElicitingPacketTime = t
		h.bytesInFlight += size
		if h.numProbesToSend > 0 {
			h.numProbesToSend--
		}
	}
	h.congestion.OnPacketSent(t, h.bytesInFlight, pn, size, isAckEliciting)

	if encLevel == protocol.Encryption1RTT && h.ecnTracker != nil {
		h.ecnTracker.SentPacket(pn, ecn)
	}

	if !isAckEliciting {
		pnSpace.history.SentNonAckElicitingPacket(pn)
		if !h.peerCompletedAddressValidation {
			h.setLossDetectionTimer(t)
		}
		return
	}

	p := getPacket()
	p.SendTime = t
	p.PacketNumber = pn
	p.EncryptionLevel = encLevel
	p.Length = size
	p.LargestAcked = largestAcked
	p.StreamFrames = streamFrames
	p.Frames = frames
	p.IsPathMTUProbePacket = isPathMTUProbePacket
	p.includedInBytesInFlight = true

	pnSpace.history.SentAckElicitingPacket(p)
	if h.tracer != nil && h.tracer.UpdatedMetrics != nil {
		h.tracer.UpdatedMetrics(h.rttStats, h.congestion.GetCongestionWindow(), h.bytesInFlight, h.packetsInFlight())
	}
	h.setLossDetectionTimer(t)
}

func (h *sentPacketHandler) getPacketNumberSpace(encLevel protocol.EncryptionLevel) *packetNumberSpace {
	switch encLevel {
	case protocol.EncryptionInitial:
		return h.initialPackets
	case protocol.EncryptionHandshake:
		return h.handshakePackets
	case protocol.Encryption0RTT, protocol.Encryption1RTT:
		return h.appDataPackets
	default:
		panic("invalid packet number space")
	}
}

func (h *sentPacketHandler) ReceivedAck(ack *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime time.Time) (bool /* contained 1-RTT packet */, error) {
	pnSpace := h.getPacketNumberSpace(encLevel)

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
	ackedPackets, err := h.detectAndRemoveAckedPackets(ack, encLevel)
	if err != nil || len(ackedPackets) == 0 {
		return false, err
	}
	// update the RTT, if the largest acked is newly acknowledged
	if len(ackedPackets) > 0 {
		if p := ackedPackets[len(ackedPackets)-1]; p.PacketNumber == ack.LargestAcked() && !p.isPathProbePacket {
			// don't use the ack delay for Initial and Handshake packets
			var ackDelay time.Duration
			if encLevel == protocol.Encryption1RTT {
				ackDelay = min(ack.DelayTime, h.rttStats.MaxAckDelay())
			}
			h.rttStats.UpdateRTT(rcvTime.Sub(p.SendTime), ackDelay)
			if h.logger.Debug() {
				h.logger.Debugf("\tupdated RTT: %s (σ: %s)", h.rttStats.SmoothedRTT(), h.rttStats.MeanDeviation())
			}
			h.congestion.MaybeExitSlowStart()
		}
	}

	// Only inform the ECN tracker about new 1-RTT ACKs if the ACK increases the largest acked.
	if encLevel == protocol.Encryption1RTT && h.ecnTracker != nil && largestAcked > pnSpace.largestAcked {
		congested := h.ecnTracker.HandleNewlyAcked(ackedPackets, int64(ack.ECT0), int64(ack.ECT1), int64(ack.ECNCE))
		if congested {
			h.congestion.OnCongestionEvent(largestAcked, 0, priorInFlight)
		}
	}

	pnSpace.largestAcked = max(pnSpace.largestAcked, largestAcked)

	h.detectLostPackets(rcvTime, encLevel)
	if encLevel == protocol.Encryption1RTT {
		h.detectLostPathProbes(rcvTime)
	}
	var acked1RTTPacket bool
	for _, p := range ackedPackets {
		if p.includedInBytesInFlight && !p.declaredLost {
			h.congestion.OnPacketAcked(p.PacketNumber, p.Length, priorInFlight, rcvTime)
		}
		if p.EncryptionLevel == protocol.Encryption1RTT {
			acked1RTTPacket = true
		}
		h.removeFromBytesInFlight(p)
		if !p.isPathProbePacket {
			putPacket(p)
		}
	}
	// After this point, we must not use ackedPackets any longer!
	// We've already returned the buffers.
	ackedPackets = nil //nolint:ineffassign // This is just to be on the safe side.

	// Reset the pto_count unless the client is unsure if the server has validated the client's address.
	if h.peerCompletedAddressValidation {
		if h.tracer != nil && h.tracer.UpdatedPTOCount != nil && h.ptoCount != 0 {
			h.tracer.UpdatedPTOCount(0)
		}
		h.ptoCount = 0
	}
	h.numProbesToSend = 0

	if h.tracer != nil && h.tracer.UpdatedMetrics != nil {
		h.tracer.UpdatedMetrics(h.rttStats, h.congestion.GetCongestionWindow(), h.bytesInFlight, h.packetsInFlight())
	}

	h.setLossDetectionTimer(rcvTime)
	return acked1RTTPacket, nil
}

func (h *sentPacketHandler) GetLowestPacketNotConfirmedAcked() protocol.PacketNumber {
	return h.lowestNotConfirmedAcked
}

// Packets are returned in ascending packet number order.
func (h *sentPacketHandler) detectAndRemoveAckedPackets(ack *wire.AckFrame, encLevel protocol.EncryptionLevel) ([]*packet, error) {
	pnSpace := h.getPacketNumberSpace(encLevel)
	h.ackedPackets = h.ackedPackets[:0]
	ackRangeIndex := 0
	lowestAcked := ack.LowestAcked()
	largestAcked := ack.LargestAcked()
	for p := range pnSpace.history.Packets() {
		// ignore packets below the lowest acked
		if p.PacketNumber < lowestAcked {
			continue
		}
		if p.PacketNumber > largestAcked {
			break
		}

		if ack.HasMissingRanges() {
			ackRange := ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]

			for p.PacketNumber > ackRange.Largest && ackRangeIndex < len(ack.AckRanges)-1 {
				ackRangeIndex++
				ackRange = ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]
			}

			if p.PacketNumber < ackRange.Smallest { // packet not contained in ACK range
				continue
			}
			if p.PacketNumber > ackRange.Largest {
				return nil, fmt.Errorf("BUG: ackhandler would have acked wrong packet %d, while evaluating range %d -> %d", p.PacketNumber, ackRange.Smallest, ackRange.Largest)
			}
		}
		if p.skippedPacket {
			return nil, &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				ErrorMessage: fmt.Sprintf("received an ACK for skipped packet number: %d (%s)", p.PacketNumber, encLevel),
			}
		}
		if p.isPathProbePacket {
			probePacket := pnSpace.history.RemovePathProbe(p.PacketNumber)
			if probePacket == nil {
				panic(fmt.Sprintf("path probe doesn't exist: %d", p.PacketNumber))
			}
			h.ackedPackets = append(h.ackedPackets, probePacket)
			continue
		}
		h.ackedPackets = append(h.ackedPackets, p)
	}
	if h.logger.Debug() && len(h.ackedPackets) > 0 {
		pns := make([]protocol.PacketNumber, len(h.ackedPackets))
		for i, p := range h.ackedPackets {
			pns[i] = p.PacketNumber
		}
		h.logger.Debugf("\tnewly acked packets (%d): %d", len(pns), pns)
	}

	for _, p := range h.ackedPackets {
		if p.LargestAcked != protocol.InvalidPacketNumber && encLevel == protocol.Encryption1RTT {
			h.lowestNotConfirmedAcked = max(h.lowestNotConfirmedAcked, p.LargestAcked+1)
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
		if err := pnSpace.history.Remove(p.PacketNumber); err != nil {
			return nil, err
		}
		if h.tracer != nil && h.tracer.AcknowledgedPacket != nil {
			h.tracer.AcknowledgedPacket(encLevel, p.PacketNumber)
		}
	}
	return h.ackedPackets, nil
}

func (h *sentPacketHandler) getLossTimeAndSpace() (time.Time, protocol.EncryptionLevel) {
	var encLevel protocol.EncryptionLevel
	var lossTime time.Time

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
func (h *sentPacketHandler) getPTOTimeAndSpace(now time.Time) (pto time.Time, encLevel protocol.EncryptionLevel) {
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

	if h.initialPackets != nil && h.initialPackets.history.HasOutstandingPackets() &&
		!h.initialPackets.lastAckElicitingPacketTime.IsZero() {
		encLevel = protocol.EncryptionInitial
		if t := h.initialPackets.lastAckElicitingPacketTime; !t.IsZero() {
			pto = t.Add(h.getScaledPTO(false))
		}
	}
	if h.handshakePackets != nil && h.handshakePackets.history.HasOutstandingPackets() &&
		!h.handshakePackets.lastAckElicitingPacketTime.IsZero() {
		t := h.handshakePackets.lastAckElicitingPacketTime.Add(h.getScaledPTO(false))
		if pto.IsZero() || (!t.IsZero() && t.Before(pto)) {
			pto = t
			encLevel = protocol.EncryptionHandshake
		}
	}
	if h.handshakeConfirmed && h.appDataPackets.history.HasOutstandingPackets() &&
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
	if h.initialPackets != nil && h.initialPackets.history.HasOutstandingPackets() {
		return true
	}
	if h.handshakePackets != nil && h.handshakePackets.history.HasOutstandingPackets() {
		return true
	}
	return false
}

func (h *sentPacketHandler) setLossDetectionTimer(now time.Time) {
	oldAlarm := h.alarm // only needed in case tracing is enabled
	newAlarm := h.lossDetectionTime(now)
	h.alarm = newAlarm

	if newAlarm.Time.IsZero() && !oldAlarm.Time.IsZero() {
		h.logger.Debugf("Canceling loss detection timer.")
		if h.tracer != nil && h.tracer.LossTimerCanceled != nil {
			h.tracer.LossTimerCanceled()
		}
	}

	if h.tracer != nil && h.tracer.SetLossTimer != nil && newAlarm != oldAlarm {
		h.tracer.SetLossTimer(newAlarm.TimerType, newAlarm.EncryptionLevel, newAlarm.Time)
	}
}

func (h *sentPacketHandler) lossDetectionTime(now time.Time) alarmTimer {
	// cancel the alarm if no packets are outstanding
	if h.peerCompletedAddressValidation && !h.hasOutstandingCryptoPackets() &&
		!h.appDataPackets.history.HasOutstandingPackets() && !h.appDataPackets.history.HasOutstandingPathProbes() {
		return alarmTimer{}
	}

	// cancel the alarm if amplification limited
	if h.isAmplificationLimited() {
		return alarmTimer{}
	}

	var pathProbeLossTime time.Time
	if h.appDataPackets.history.HasOutstandingPathProbes() {
		if p := h.appDataPackets.history.FirstOutstandingPathProbe(); p != nil {
			pathProbeLossTime = p.SendTime.Add(pathProbePacketLossTimeout)
		}
	}

	// early retransmit timer or time loss detection
	lossTime, encLevel := h.getLossTimeAndSpace()
	if !lossTime.IsZero() && (pathProbeLossTime.IsZero() || lossTime.Before(pathProbeLossTime)) {
		return alarmTimer{
			Time:            lossTime,
			TimerType:       logging.TimerTypeACK,
			EncryptionLevel: encLevel,
		}
	}
	ptoTime, encLevel := h.getPTOTimeAndSpace(now)
	if !ptoTime.IsZero() && (pathProbeLossTime.IsZero() || ptoTime.Before(pathProbeLossTime)) {
		return alarmTimer{
			Time:            ptoTime,
			TimerType:       logging.TimerTypePTO,
			EncryptionLevel: encLevel,
		}
	}
	if !pathProbeLossTime.IsZero() {
		return alarmTimer{
			Time:            pathProbeLossTime,
			TimerType:       logging.TimerTypePathProbe,
			EncryptionLevel: encLevel,
		}
	}
	return alarmTimer{}
}

func (h *sentPacketHandler) detectLostPathProbes(now time.Time) {
	if !h.appDataPackets.history.HasOutstandingPathProbes() {
		return
	}
	lossTime := now.Add(-pathProbePacketLossTimeout)
	// RemovePathProbe cannot be called while iterating.
	var lostPathProbes []*packet
	for p := range h.appDataPackets.history.PathProbes() {
		if !p.SendTime.After(lossTime) {
			lostPathProbes = append(lostPathProbes, p)
		}
	}
	for _, p := range lostPathProbes {
		for _, f := range p.Frames {
			f.Handler.OnLost(f.Frame)
		}
		h.appDataPackets.history.Remove(p.PacketNumber)
		h.appDataPackets.history.RemovePathProbe(p.PacketNumber)
	}
}

func (h *sentPacketHandler) detectLostPackets(now time.Time, encLevel protocol.EncryptionLevel) {
	pnSpace := h.getPacketNumberSpace(encLevel)
	pnSpace.lossTime = time.Time{}

	maxRTT := float64(max(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT()))
	lossDelay := time.Duration(timeThreshold * maxRTT)

	// Minimum time of granularity before packets are deemed lost.
	lossDelay = max(lossDelay, protocol.TimerGranularity)

	// Packets sent before this time are deemed lost.
	lostSendTime := now.Add(-lossDelay)

	priorInFlight := h.bytesInFlight
	for p := range pnSpace.history.Packets() {
		if p.PacketNumber > pnSpace.largestAcked {
			break
		}

		isRegularPacket := !p.skippedPacket && !p.isPathProbePacket
		var packetLost bool
		if !p.SendTime.After(lostSendTime) {
			packetLost = true
			if isRegularPacket {
				if h.logger.Debug() {
					h.logger.Debugf("\tlost packet %d (time threshold)", p.PacketNumber)
				}
				if h.tracer != nil && h.tracer.LostPacket != nil {
					h.tracer.LostPacket(p.EncryptionLevel, p.PacketNumber, logging.PacketLossTimeThreshold)
				}
			}
		} else if pnSpace.largestAcked >= p.PacketNumber+packetThreshold {
			packetLost = true
			if isRegularPacket {
				if h.logger.Debug() {
					h.logger.Debugf("\tlost packet %d (reordering threshold)", p.PacketNumber)
				}
				if h.tracer != nil && h.tracer.LostPacket != nil {
					h.tracer.LostPacket(p.EncryptionLevel, p.PacketNumber, logging.PacketLossReorderingThreshold)
				}
			}
		} else if pnSpace.lossTime.IsZero() {
			// Note: This conditional is only entered once per call
			lossTime := p.SendTime.Add(lossDelay)
			if h.logger.Debug() {
				h.logger.Debugf("\tsetting loss timer for packet %d (%s) to %s (in %s)", p.PacketNumber, encLevel, lossDelay, lossTime)
			}
			pnSpace.lossTime = lossTime
		}
		if packetLost {
			pnSpace.history.DeclareLost(p.PacketNumber)
			if isRegularPacket {
				// the bytes in flight need to be reduced no matter if the frames in this packet will be retransmitted
				h.removeFromBytesInFlight(p)
				h.queueFramesForRetransmission(p)
				if !p.IsPathMTUProbePacket {
					h.congestion.OnCongestionEvent(p.PacketNumber, p.Length, priorInFlight)
				}
				if encLevel == protocol.Encryption1RTT && h.ecnTracker != nil {
					h.ecnTracker.LostPacket(p.PacketNumber)
				}
			}
		}
	}
}

func (h *sentPacketHandler) OnLossDetectionTimeout(now time.Time) error {
	defer h.setLossDetectionTimer(now)

	if h.handshakeConfirmed {
		h.detectLostPathProbes(now)
	}

	earliestLossTime, encLevel := h.getLossTimeAndSpace()
	if !earliestLossTime.IsZero() {
		if h.logger.Debug() {
			h.logger.Debugf("Loss detection alarm fired in loss timer mode. Loss time: %s", earliestLossTime)
		}
		if h.tracer != nil && h.tracer.LossTimerExpired != nil {
			h.tracer.LossTimerExpired(logging.TimerTypeACK, encLevel)
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
	ps := h.getPacketNumberSpace(encLevel)
	if !ps.history.HasOutstandingPackets() && !ps.history.HasOutstandingPathProbes() && !h.peerCompletedAddressValidation {
		return nil
	}
	h.ptoCount++
	if h.logger.Debug() {
		h.logger.Debugf("Loss detection alarm for %s fired in PTO mode. PTO count: %d", encLevel, h.ptoCount)
	}
	if h.tracer != nil {
		if h.tracer.LossTimerExpired != nil {
			h.tracer.LossTimerExpired(logging.TimerTypePTO, encLevel)
		}
		if h.tracer.UpdatedPTOCount != nil {
			h.tracer.UpdatedPTOCount(h.ptoCount)
		}
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
		pn := h.PopPacketNumber(protocol.Encryption1RTT)
		h.getPacketNumberSpace(protocol.Encryption1RTT).history.SkippedPacket(pn)
		h.ptoMode = SendPTOAppData
	default:
		return fmt.Errorf("PTO timer in unexpected encryption level: %s", encLevel)
	}
	return nil
}

func (h *sentPacketHandler) GetLossDetectionTimeout() time.Time {
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

func (h *sentPacketHandler) PeekPacketNumber(encLevel protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	pnSpace := h.getPacketNumberSpace(encLevel)
	pn := pnSpace.pns.Peek()
	// See section 17.1 of RFC 9000.
	return pn, protocol.PacketNumberLengthForHeader(pn, pnSpace.largestAcked)
}

func (h *sentPacketHandler) PopPacketNumber(encLevel protocol.EncryptionLevel) protocol.PacketNumber {
	pnSpace := h.getPacketNumberSpace(encLevel)
	skipped, pn := pnSpace.pns.Pop()
	if skipped {
		skippedPN := pn - 1
		pnSpace.history.SkippedPacket(skippedPN)
		if h.logger.Debug() {
			h.logger.Debugf("Skipping packet number %d", skippedPN)
		}
	}
	return pn
}

func (h *sentPacketHandler) SendMode(now time.Time) SendMode {
	numTrackedPackets := h.appDataPackets.history.Len()
	if h.initialPackets != nil {
		numTrackedPackets += h.initialPackets.history.Len()
	}
	if h.handshakePackets != nil {
		numTrackedPackets += h.handshakePackets.history.Len()
	}

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

func (h *sentPacketHandler) TimeUntilSend() time.Time {
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

func (h *sentPacketHandler) QueueProbePacket(encLevel protocol.EncryptionLevel) bool {
	pnSpace := h.getPacketNumberSpace(encLevel)
	p := pnSpace.history.FirstOutstanding()
	if p == nil {
		return false
	}
	h.queueFramesForRetransmission(p)
	// TODO: don't declare the packet lost here.
	// Keep track of acknowledged frames instead.
	h.removeFromBytesInFlight(p)
	pnSpace.history.DeclareLost(p.PacketNumber)
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

func (h *sentPacketHandler) ResetForRetry(now time.Time) {
	h.bytesInFlight = 0
	var firstPacketSendTime time.Time
	for p := range h.initialPackets.history.Packets() {
		if firstPacketSendTime.IsZero() {
			firstPacketSendTime = p.SendTime
		}
		if !p.declaredLost && !p.skippedPacket {
			h.queueFramesForRetransmission(p)
		}
	}
	// All application data packets sent at this point are 0-RTT packets.
	// In the case of a Retry, we can assume that the server dropped all of them.
	for p := range h.appDataPackets.history.Packets() {
		if !p.declaredLost && !p.skippedPacket {
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
		if h.tracer != nil && h.tracer.UpdatedMetrics != nil {
			h.tracer.UpdatedMetrics(h.rttStats, h.congestion.GetCongestionWindow(), h.bytesInFlight, h.packetsInFlight())
		}
	}
	h.initialPackets = newPacketNumberSpace(h.initialPackets.pns.Peek(), false)
	h.appDataPackets = newPacketNumberSpace(h.appDataPackets.pns.Peek(), true)
	oldAlarm := h.alarm
	h.alarm = alarmTimer{}
	if h.tracer != nil {
		if h.tracer.UpdatedPTOCount != nil {
			h.tracer.UpdatedPTOCount(0)
		}
		if !oldAlarm.Time.IsZero() && h.tracer.LossTimerCanceled != nil {
			h.tracer.LossTimerCanceled()
		}
	}
	h.ptoCount = 0
}

func (h *sentPacketHandler) MigratedPath(now time.Time, initialMaxDatagramSize protocol.ByteCount) {
	h.rttStats.ResetForPathMigration()
	for p := range h.appDataPackets.history.Packets() {
		h.appDataPackets.history.DeclareLost(p.PacketNumber)
		if !p.skippedPacket && !p.isPathProbePacket {
			h.removeFromBytesInFlight(p)
			h.queueFramesForRetransmission(p)
		}
	}
	for p := range h.appDataPackets.history.PathProbes() {
		h.appDataPackets.history.RemovePathProbe(p.PacketNumber)
	}
	h.congestion = congestion.NewCubicSender(
		congestion.DefaultClock{},
		h.rttStats,
		initialMaxDatagramSize,
		true, // use Reno
		h.tracer,
	)
	h.setLossDetectionTimer(now)
}
