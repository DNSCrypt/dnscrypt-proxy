package ackhandler

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

const (
	// skipPacketInitialPeriod is the initial period length used for packet number skipping
	// to prevent an Optimistic ACK attack.
	// Every time a packet number is skipped, the period is doubled, up to skipPacketMaxPeriod.
	skipPacketInitialPeriod = 256

	// skipPacketMaxPeriod is the maximum period length used for packet number skipping.
	skipPacketMaxPeriod = 128 * 1024
)

// The packetNumberGenerator generates the packet number for the next packet
// it randomly skips a packet number every averagePeriod packets (on average).
// It is guaranteed to never skip two consecutive packet numbers.
type packetNumberGenerator struct {
	next protocol.PacketNumber

	period           uint32
	maxPeriod        uint32
	packetsUntilSkip uint32

	rng utils.Rand
}

func newPacketNumberGenerator(initial protocol.PacketNumber, initialPeriod, maxPeriod uint32) *packetNumberGenerator {
	g := &packetNumberGenerator{
		next:      initial,
		period:    initialPeriod,
		maxPeriod: maxPeriod,
	}
	g.generateNewSkip()
	return g
}

func (p *packetNumberGenerator) Peek(allowSkip bool) protocol.PacketNumber {
	if allowSkip && p.packetsUntilSkip == 0 {
		return p.next + 1
	}
	return p.next
}

// Pop reports whether the packet number before the returned number was skipped.
func (p *packetNumberGenerator) Pop(allowSkip bool) (bool, protocol.PacketNumber) {
	next := p.next
	if allowSkip && p.packetsUntilSkip == 0 {
		next++
		p.next += 2
		p.generateNewSkip()
		return true, next
	}
	if allowSkip {
		p.packetsUntilSkip--
	}
	p.next++ // generate a new packet number for the next packet
	return false, next
}

func (p *packetNumberGenerator) generateNewSkip() {
	// make sure that there are never two consecutive packet numbers that are skipped
	p.packetsUntilSkip = 3 + p.rng.Uint32N(2*p.period)
	p.period = min(2*p.period, p.maxPeriod)
}
