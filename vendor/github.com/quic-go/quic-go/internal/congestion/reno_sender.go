package congestion

import (
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

const (
	// maxDatagramSize is the default maximum packet size used in the Linux TCP implementation.
	// Used in QUIC for congestion window computations in bytes.
	initialMaxDatagramSize     = protocol.ByteCount(protocol.InitialPacketSize)
	maxBurstPackets            = 3
	renoBeta                   = 0.7 // Reno backoff factor.
	minCongestionWindowPackets = 2
	initialCongestionWindow    = 32
)

// renoUndoState saves Reno's state before the latest cutback.
type renoUndoState struct {
	congestionWindow   protocol.ByteCount
	slowStartThreshold protocol.ByteCount
	numAckedPackets    uint64
	// Previous cutback's boundary; renoSender holds the current boundary.
	largestSentAtLastCutback protocol.PacketNumber
	// Includes ECN events, which cannot be undone by spurious-loss reports.
	numCongestionEvents uint64
}

func (s *renoUndoState) IsActive() bool {
	return s.numCongestionEvents > 0
}

func (s *renoUndoState) Reset() {
	*s = renoUndoState{}
}

type renoSender struct {
	hybridSlowStart hybridSlowStart
	rttStats        *utils.RTTStats
	pacer           *pacer

	// Track the largest packet that has been sent.
	largestSentPacketNumber protocol.PacketNumber

	// Track the largest packet that has been acked.
	largestAckedPacketNumber protocol.PacketNumber

	// Largest packet number sent when the latest CWND cutback occurred.
	largestSentAtLastCutback protocol.PacketNumber

	// Congestion window in bytes.
	congestionWindow protocol.ByteCount

	// Slow start congestion window in bytes, aka ssthresh.
	slowStartThreshold protocol.ByteCount

	// ACK counter for the Reno implementation.
	numAckedPackets uint64

	// Retained after recovery, since spurious losses can be reported later.
	undoState renoUndoState

	maxDatagramSize protocol.ByteCount

	lastState qlog.CongestionState
	qlogger   qlogwriter.Recorder
}

var _ SendAlgorithm = &renoSender{}

// NewRenoSender makes a new Reno sender
func NewRenoSender(
	rttStats *utils.RTTStats,
	initialMaxDatagramSize protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) *renoSender {
	return newRenoSender(
		rttStats,
		initialMaxDatagramSize,
		initialCongestionWindow*initialMaxDatagramSize,
		qlogger,
	)
}

func newRenoSender(
	rttStats *utils.RTTStats,
	initialMaxDatagramSize,
	initialCongestionWindow protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) *renoSender {
	c := &renoSender{
		rttStats:                 rttStats,
		largestSentPacketNumber:  protocol.InvalidPacketNumber,
		largestAckedPacketNumber: protocol.InvalidPacketNumber,
		largestSentAtLastCutback: protocol.InvalidPacketNumber,
		congestionWindow:         initialCongestionWindow,
		slowStartThreshold:       protocol.MaxByteCount,
		pacer:                    newPacer(initialMaxDatagramSize),
		qlogger:                  qlogger,
		maxDatagramSize:          initialMaxDatagramSize,
	}
	if c.qlogger != nil {
		c.lastState = qlog.CongestionStateSlowStart
		c.qlogger.RecordEvent(qlog.CongestionStateUpdated{
			State: qlog.CongestionStateSlowStart,
		})
	}
	return c
}

// TimeUntilSend returns when the next packet should be sent.
func (c *renoSender) TimeUntilSend() monotime.Time {
	return c.pacer.TimeUntilSend(c.pacingRate())
}

func (c *renoSender) HasPacingBudget(now monotime.Time) bool {
	return c.pacer.Budget(now, c.pacingRate()) >= c.maxDatagramSize
}

func (c *renoSender) maxCongestionWindow() protocol.ByteCount {
	return c.maxDatagramSize * protocol.MaxCongestionWindowPackets
}

func (c *renoSender) minCongestionWindow() protocol.ByteCount {
	return c.maxDatagramSize * minCongestionWindowPackets
}

func (c *renoSender) OnPacketSent(
	sentTime monotime.Time,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	c.pacer.SentPacket(sentTime, bytes, c.pacingRate())
	if !isRetransmittable {
		return
	}
	c.largestSentPacketNumber = packetNumber
	c.hybridSlowStart.OnPacketSent(packetNumber)
}

func (c *renoSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < c.congestionWindow
}

func (c *renoSender) inRecovery() bool {
	return c.largestAckedPacketNumber != protocol.InvalidPacketNumber && c.largestAckedPacketNumber <= c.largestSentAtLastCutback
}

func (c *renoSender) inSlowStart() bool {
	return c.congestionWindow < c.slowStartThreshold
}

func (c *renoSender) GetCongestionWindow() protocol.ByteCount {
	return c.congestionWindow
}

func (c *renoSender) MaybeExitSlowStart() {
	if c.inSlowStart() &&
		c.hybridSlowStart.ShouldExitSlowStart(c.rttStats.LatestRTT(), c.rttStats.MinRTT(), c.congestionWindow/c.maxDatagramSize) {
		// exit slow start
		c.slowStartThreshold = c.congestionWindow
		c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
	}
}

func (c *renoSender) OnPacketAcked(ackedPacketNumber protocol.PacketNumber, priorInFlight protocol.ByteCount) {
	c.largestAckedPacketNumber = max(ackedPacketNumber, c.largestAckedPacketNumber)
	if c.inRecovery() {
		return
	}
	c.maybeIncreaseCwnd(priorInFlight)
	if c.inSlowStart() {
		c.hybridSlowStart.OnPacketAcked(ackedPacketNumber)
	}
}

func (c *renoSender) OnCongestionEvent(packetNumber protocol.PacketNumber) {
	// TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
	// already sent should be treated as a single loss event, since it's expected.
	if packetNumber <= c.largestSentAtLastCutback {
		// Older events are already accounted for in the saved congestion window.
		if c.undoState.IsActive() && packetNumber > c.undoState.largestSentAtLastCutback {
			c.undoState.numCongestionEvents++
		}
		return
	}
	c.undoState = renoUndoState{
		congestionWindow:         c.congestionWindow,
		slowStartThreshold:       c.slowStartThreshold,
		numAckedPackets:          c.numAckedPackets,
		largestSentAtLastCutback: c.largestSentAtLastCutback,
		numCongestionEvents:      1,
	}

	c.maybeQlogStateChange(qlog.CongestionStateRecovery)

	c.congestionWindow = protocol.ByteCount(float64(c.congestionWindow) * renoBeta)
	if minCwnd := c.minCongestionWindow(); c.congestionWindow < minCwnd {
		c.congestionWindow = minCwnd
	}
	c.slowStartThreshold = c.congestionWindow
	c.largestSentAtLastCutback = c.largestSentPacketNumber
	// reset packet count from congestion avoidance mode. We start
	// counting again when we're out of recovery.
	c.numAckedPackets = 0
}

func (c *renoSender) OnSpuriousLoss(packetNumber protocol.PacketNumber) {
	if !c.undoState.IsActive() {
		return
	}
	// only losses counted for this cutback can undo it
	if packetNumber <= c.undoState.largestSentAtLastCutback || packetNumber > c.largestSentAtLastCutback {
		return
	}
	c.undoState.numCongestionEvents--
	if c.undoState.numCongestionEvents > 0 {
		return
	}

	state := c.undoState
	c.undoState.Reset()
	// Regaining the old window usually takes multiple RTTs, making a spurious-loss report this late unlikely.
	if c.congestionWindow > state.congestionWindow {
		return
	}
	c.congestionWindow = state.congestionWindow
	c.slowStartThreshold = state.slowStartThreshold
	c.numAckedPackets = state.numAckedPackets
	c.largestSentAtLastCutback = state.largestSentAtLastCutback
	switch {
	case c.inRecovery():
		c.maybeQlogStateChange(qlog.CongestionStateRecovery)
	case c.inSlowStart():
		c.maybeQlogStateChange(qlog.CongestionStateSlowStart)
	default:
		c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
	}
}

// Called when we receive an ack. Normal TCP tracks how many packets one ack
// represents, but quic has a separate ack for each packet.
func (c *renoSender) maybeIncreaseCwnd(priorInFlight protocol.ByteCount) {
	// Do not increase the congestion window unless the sender is close to using
	// the current window.
	if !c.isCwndLimited(priorInFlight) {
		c.maybeQlogStateChange(qlog.CongestionStateApplicationLimited)
		return
	}
	if c.congestionWindow >= c.maxCongestionWindow() {
		return
	}
	if c.inSlowStart() {
		// TCP slow start, exponential growth, increase by one for each ACK.
		c.congestionWindow += c.maxDatagramSize
		c.maybeQlogStateChange(qlog.CongestionStateSlowStart)
		return
	}
	// Congestion avoidance
	c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
	c.numAckedPackets++
	if c.numAckedPackets >= uint64(c.congestionWindow/c.maxDatagramSize) {
		c.congestionWindow += c.maxDatagramSize
		c.numAckedPackets = 0
	}
}

func (c *renoSender) isCwndLimited(bytesInFlight protocol.ByteCount) bool {
	if bytesInFlight >= c.congestionWindow {
		return true
	}
	availableBytes := c.congestionWindow - bytesInFlight
	slowStartLimited := c.inSlowStart() && bytesInFlight > c.congestionWindow/2
	return slowStartLimited || availableBytes <= maxBurstPackets*c.maxDatagramSize
}

// bandwidthEstimate returns the current bandwidth estimate
func (c *renoSender) bandwidthEstimate() bandwidth {
	srtt := c.rttStats.SmoothedRTT()
	if srtt == 0 {
		// This should never happen, but if it does, avoid division by zero.
		srtt = protocol.TimerGranularity
	}
	return bandwidthFromDelta(c.congestionWindow, srtt)
}

func (c *renoSender) pacingRate() bandwidth {
	if c.inSlowStart() {
		// Allow slow start to double the sending rate every RTT.
		return 2 * c.bandwidthEstimate()
	}
	// Allow for RTT variations when filling the congestion window.
	return c.bandwidthEstimate() * 5 / 4
}

func (c *renoSender) maybeQlogStateChange(new qlog.CongestionState) {
	if c.qlogger == nil || new == c.lastState {
		return
	}
	c.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: new})
	c.lastState = new
}

func (c *renoSender) SetMaxDatagramSize(s protocol.ByteCount) {
	cwndIsMinCwnd := c.congestionWindow == c.minCongestionWindow()
	c.maxDatagramSize = s
	if cwndIsMinCwnd {
		c.congestionWindow = c.minCongestionWindow()
	}
	c.pacer.SetMaxDatagramSize(s)
}
