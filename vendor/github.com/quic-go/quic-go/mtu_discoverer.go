package quic

import (
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
)

type mtuDiscoverer interface {
	// Start starts the MTU discovery process.
	// It's unnecessary to call ShouldSendProbe before that.
	Start()
	ShouldSendProbe(now time.Time) bool
	CurrentSize() protocol.ByteCount
	GetPing() (ping ackhandler.Frame, datagramSize protocol.ByteCount)
}

const (
	// At some point, we have to stop searching for a higher MTU.
	// We're happy to send a packet that's 10 bytes smaller than the actual MTU.
	maxMTUDiff = 20
	// send a probe packet every mtuProbeDelay RTTs
	mtuProbeDelay = 5
)

type mtuFinder struct {
	lastProbeTime time.Time
	mtuIncreased  func(protocol.ByteCount)

	rttStats *utils.RTTStats
	inFlight protocol.ByteCount // the size of the probe packet currently in flight. InvalidByteCount if none is in flight
	current  protocol.ByteCount
	max      protocol.ByteCount // the maximum value, as advertised by the peer (or our maximum size buffer)

	tracer *logging.ConnectionTracer
}

var _ mtuDiscoverer = &mtuFinder{}

func newMTUDiscoverer(
	rttStats *utils.RTTStats,
	start, max protocol.ByteCount,
	mtuIncreased func(protocol.ByteCount),
	tracer *logging.ConnectionTracer,
) *mtuFinder {
	return &mtuFinder{
		inFlight:     protocol.InvalidByteCount,
		current:      start,
		max:          max,
		rttStats:     rttStats,
		mtuIncreased: mtuIncreased,
		tracer:       tracer,
	}
}

func (f *mtuFinder) done() bool {
	return f.max-f.current <= maxMTUDiff+1
}

func (f *mtuFinder) SetMax(max protocol.ByteCount) {
	f.max = max
}

func (f *mtuFinder) Start() {
	if f.max == protocol.InvalidByteCount {
		panic("invalid")
	}
	f.lastProbeTime = time.Now() // makes sure the first probe packet is not sent immediately
}

func (f *mtuFinder) ShouldSendProbe(now time.Time) bool {
	if f.max == 0 || f.lastProbeTime.IsZero() {
		return false
	}
	if f.inFlight != protocol.InvalidByteCount || f.done() {
		return false
	}
	return !now.Before(f.lastProbeTime.Add(mtuProbeDelay * f.rttStats.SmoothedRTT()))
}

func (f *mtuFinder) GetPing() (ackhandler.Frame, protocol.ByteCount) {
	size := (f.max + f.current) / 2
	f.lastProbeTime = time.Now()
	f.inFlight = size
	return ackhandler.Frame{
		Frame:   &wire.PingFrame{},
		Handler: &mtuFinderAckHandler{f},
	}, size
}

func (f *mtuFinder) CurrentSize() protocol.ByteCount {
	return f.current
}

type mtuFinderAckHandler struct {
	*mtuFinder
}

var _ ackhandler.FrameHandler = &mtuFinderAckHandler{}

func (h *mtuFinderAckHandler) OnAcked(wire.Frame) {
	size := h.inFlight
	if size == protocol.InvalidByteCount {
		panic("OnAcked callback called although there's no MTU probe packet in flight")
	}
	h.inFlight = protocol.InvalidByteCount
	h.current = size
	if h.tracer != nil && h.tracer.UpdatedMTU != nil {
		h.tracer.UpdatedMTU(size, h.done())
	}
	h.mtuIncreased(size)
}

func (h *mtuFinderAckHandler) OnLost(wire.Frame) {
	size := h.inFlight
	if size == protocol.InvalidByteCount {
		panic("OnLost callback called although there's no MTU probe packet in flight")
	}
	h.max = size
	h.inFlight = protocol.InvalidByteCount
}
