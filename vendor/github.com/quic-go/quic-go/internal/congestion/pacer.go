package congestion

import (
	"math"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

const maxBurstSizePackets = 10

// minPacingDelay is the minimum duration that is used for packet pacing
// If the packet packing frequency is higher, multiple packets might be sent at once.
// Example: For a packet pacing delay of 200μs, we would send 5 packets at once, wait for 1ms, and so forth.
const minPacingDelay = time.Millisecond

// The pacer implements a token bucket pacing algorithm.
type pacer struct {
	budgetAtLastSent protocol.ByteCount
	maxDatagramSize  protocol.ByteCount
	lastSentTime     monotime.Time
}

func newPacer() *pacer {
	return &pacer{
		maxDatagramSize: protocol.InitialPacketSize,
	}
}

func (p *pacer) SentPacket(sendTime monotime.Time, size protocol.ByteCount, rate Bandwidth) {
	budget := p.Budget(sendTime, rate)
	if size >= budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

func (p *pacer) Budget(now monotime.Time, rate Bandwidth) protocol.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize(rate)
	}
	delta := now.Sub(p.lastSentTime)
	var added protocol.ByteCount
	if delta > 0 {
		added = p.timeScaledBandwidth(delta, rate)
	}
	budget := p.budgetAtLastSent + added
	if added > 0 && budget < p.budgetAtLastSent {
		budget = protocol.MaxByteCount
	}
	return min(p.maxBurstSize(rate), budget)
}

func (p *pacer) maxBurstSize(rate Bandwidth) protocol.ByteCount {
	return max(
		p.timeScaledBandwidth(minPacingDelay+protocol.TimerGranularity, rate),
		maxBurstSizePackets*p.maxDatagramSize,
	)
}

// timeScaledBandwidth calculates the number of bytes that may be sent within
// a given duration, based on the current pacing rate.
// It caps the scaled value to the maximum allowed burst and handles overflows.
func (p *pacer) timeScaledBandwidth(d time.Duration, rate Bandwidth) protocol.ByteCount {
	bw := uint64(rate / BytesPerSecond)
	if bw == 0 {
		return 0
	}
	const nsPerSecond = 1e9
	ns := uint64(d)
	maxBurst := maxBurstSizePackets * p.maxDatagramSize
	var scaled protocol.ByteCount
	if ns > math.MaxUint64/bw {
		scaled = maxBurst
	} else {
		scaled = protocol.ByteCount(bw * ns / nsPerSecond)
	}
	return scaled
}

// TimeUntilSend returns when the next packet should be sent.
// It returns zero if a packet can be sent immediately.
func (p *pacer) TimeUntilSend(rate Bandwidth) monotime.Time {
	if p.lastSentTime.IsZero() || p.budgetAtLastSent >= p.maxDatagramSize {
		return 0
	}
	diff := 1e9 * uint64(p.maxDatagramSize-p.budgetAtLastSent)
	bw := uint64(rate / BytesPerSecond)
	// We might need to round up this value.
	// Otherwise, we might have a budget (slightly) smaller than the datagram size when the timer expires.
	d := diff / bw
	// this is effectively a math.Ceil, but using only integer math
	if diff%bw > 0 {
		d++
	}
	return p.lastSentTime.Add(max(minPacingDelay, time.Duration(d)*time.Nanosecond))
}

func (p *pacer) SetMaxDatagramSize(s protocol.ByteCount) {
	p.maxDatagramSize = s
}
