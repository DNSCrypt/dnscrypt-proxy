package ackhandler

import (
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	list "github.com/lucas-clemente/quic-go/internal/utils/linkedlist"
)

type sentPacketHistory struct {
	rttStats              *utils.RTTStats
	outstandingPacketList *list.List[Packet]
	etcPacketList         *list.List[Packet]
	packetMap             map[protocol.PacketNumber]*list.Element[Packet]
	highestSent           protocol.PacketNumber
}

func newSentPacketHistory(rttStats *utils.RTTStats) *sentPacketHistory {
	return &sentPacketHistory{
		rttStats:              rttStats,
		outstandingPacketList: list.New[Packet](),
		etcPacketList:         list.New[Packet](),
		packetMap:             make(map[protocol.PacketNumber]*list.Element[Packet]),
		highestSent:           protocol.InvalidPacketNumber,
	}
}

func (h *sentPacketHistory) SentPacket(p *Packet, isAckEliciting bool) {
	if p.PacketNumber <= h.highestSent {
		panic("non-sequential packet number use")
	}
	// Skipped packet numbers.
	for pn := h.highestSent + 1; pn < p.PacketNumber; pn++ {
		el := h.etcPacketList.PushBack(Packet{
			PacketNumber:    pn,
			EncryptionLevel: p.EncryptionLevel,
			SendTime:        p.SendTime,
			skippedPacket:   true,
		})
		h.packetMap[pn] = el
	}
	h.highestSent = p.PacketNumber

	if isAckEliciting {
		var el *list.Element[Packet]
		if p.outstanding() {
			el = h.outstandingPacketList.PushBack(*p)
		} else {
			el = h.etcPacketList.PushBack(*p)
		}
		h.packetMap[p.PacketNumber] = el
	}
}

// Iterate iterates through all packets.
func (h *sentPacketHistory) Iterate(cb func(*Packet) (cont bool, err error)) error {
	cont := true
	outstandingEl := h.outstandingPacketList.Front()
	etcEl := h.etcPacketList.Front()
	var el *list.Element[Packet]
	// whichever has the next packet number is returned first
	for cont {
		if outstandingEl == nil || (etcEl != nil && etcEl.Value.PacketNumber < outstandingEl.Value.PacketNumber) {
			el = etcEl
		} else {
			el = outstandingEl
		}
		if el == nil {
			return nil
		}
		if el == outstandingEl {
			outstandingEl = outstandingEl.Next()
		} else {
			etcEl = etcEl.Next()
		}
		var err error
		cont, err = cb(&el.Value)
		if err != nil {
			return err
		}
	}
	return nil
}

// FirstOutstanding returns the first outstanding packet.
func (h *sentPacketHistory) FirstOutstanding() *Packet {
	el := h.outstandingPacketList.Front()
	if el == nil {
		return nil
	}
	return &el.Value
}

func (h *sentPacketHistory) Len() int {
	return len(h.packetMap)
}

func (h *sentPacketHistory) Remove(p protocol.PacketNumber) error {
	el, ok := h.packetMap[p]
	if !ok {
		return fmt.Errorf("packet %d not found in sent packet history", p)
	}
	h.outstandingPacketList.Remove(el)
	h.etcPacketList.Remove(el)
	delete(h.packetMap, p)
	return nil
}

func (h *sentPacketHistory) HasOutstandingPackets() bool {
	return h.outstandingPacketList.Len() > 0
}

func (h *sentPacketHistory) DeleteOldPackets(now time.Time) {
	maxAge := 3 * h.rttStats.PTO(false)
	var nextEl *list.Element[Packet]
	// we don't iterate outstandingPacketList, as we should not delete outstanding packets.
	// being outstanding for more than 3*PTO should only happen in the case of drastic RTT changes.
	for el := h.etcPacketList.Front(); el != nil; el = nextEl {
		nextEl = el.Next()
		p := el.Value
		if p.SendTime.After(now.Add(-maxAge)) {
			break
		}
		delete(h.packetMap, p.PacketNumber)
		h.etcPacketList.Remove(el)
	}
}

func (h *sentPacketHistory) DeclareLost(p *Packet) *Packet {
	el, ok := h.packetMap[p.PacketNumber]
	if !ok {
		return nil
	}
	// try to remove it from both lists, as we don't know which one it currently belongs to.
	// Remove is a no-op for elements that are not in the list.
	h.outstandingPacketList.Remove(el)
	h.etcPacketList.Remove(el)
	p.declaredLost = true
	// move it to the correct position in the etc list (based on the packet number)
	for el = h.etcPacketList.Back(); el != nil; el = el.Prev() {
		if el.Value.PacketNumber < p.PacketNumber {
			break
		}
	}
	if el == nil {
		el = h.etcPacketList.PushFront(*p)
	} else {
		el = h.etcPacketList.InsertAfter(*p, el)
	}
	h.packetMap[p.PacketNumber] = el
	return &el.Value
}
