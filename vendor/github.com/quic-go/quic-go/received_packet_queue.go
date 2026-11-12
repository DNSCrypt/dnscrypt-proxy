package quic

import (
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
)

// A sidePacket is a packet received on a Transport other than the one of the active path.
type sidePacket struct {
	receivedPacket
	source *pathReceiver
}

// The receivedPacketQueue queues received packets until they are processed by the connection's run loop.
// Packets are identified by the pathReceiver that the Transport passed them to, i.e. by the Transport they were received on.
// Packets received on the Transport of the active path are queued in the main queue.
// Packets received on any other Transport are queued in the side queue.
// The side queue is only used by clients that probe or migrate to new paths.
type receivedPacketQueue struct {
	mx     sync.Mutex
	active *pathReceiver
	main   ringbuffer.RingBuffer[receivedPacket]
	side   ringbuffer.RingBuffer[sidePacket] // only allocated once a packet is received on a different Transport
}

// Init initializes the queue.
// The active pathReceiver is the one of the Transport that the connection was created on.
func (q *receivedPacketQueue) Init(active *pathReceiver) {
	q.main.Init(8)
	q.active = active
}

// Push queues a packet received by the pathReceiver source.
// It returns false if the packet was dropped because too many packets are queued.
func (q *receivedPacketQueue) Push(p receivedPacket, source *pathReceiver) bool {
	q.mx.Lock()
	defer q.mx.Unlock()

	if source == q.active {
		if q.main.Len() >= protocol.MaxConnUnprocessedPackets {
			return false
		}
		q.main.PushBack(p)
		return true
	}

	if q.side.Len() >= protocol.MaxConnUnprocessedPackets {
		return false
	}
	q.side.PushBack(sidePacket{receivedPacket: p, source: source})
	return true
}

// activePathID is returned by Pop for packets received on the active path.
// Like the qlog TupleID "", it refers to whichever path is currently active.
const activePathID pathID = -2

// Pop returns the next packet, and the ID of the path it was received on.
// The ID is activePathID for packets received on the active path.
// Packets in the side queue are returned first:
// When switching paths, the packets received on the old path are moved to the side queue.
func (q *receivedPacketQueue) Pop() (_ receivedPacket, path pathID, ok bool) {
	q.mx.Lock()
	defer q.mx.Unlock()

	if !q.side.Empty() {
		p := q.side.PopFront()
		if p.source == q.active {
			return p.receivedPacket, activePathID, true
		}
		return p.receivedPacket, p.source.id, true
	}
	if !q.main.Empty() {
		return q.main.PopFront(), activePathID, true
	}
	return receivedPacket{}, activePathID, false
}

func (q *receivedPacketQueue) Empty() bool {
	q.mx.Lock()
	defer q.mx.Unlock()

	return q.main.Empty() && q.side.Empty()
}

// SwapActive is called when switching paths.
// It moves packets queued for the old path to the side queue, and returns the pathReceiver of the old path.
func (q *receivedPacketQueue) SwapActive(active *pathReceiver) (prev *pathReceiver) {
	q.mx.Lock()
	defer q.mx.Unlock()

	prev = q.active
	if active == prev {
		return prev
	}
	for !q.main.Empty() {
		q.side.PushBack(sidePacket{receivedPacket: q.main.PopFront(), source: prev})
	}
	q.active = active
	return prev
}

// Clear drops all queued packets.
func (q *receivedPacketQueue) Clear() {
	q.mx.Lock()
	defer q.mx.Unlock()

	for !q.main.Empty() {
		p := q.main.PopFront()
		p.buffer.Decrement()
		p.buffer.MaybeRelease()
	}
	for !q.side.Empty() {
		p := q.side.PopFront()
		p.buffer.Decrement()
		p.buffer.MaybeRelease()
	}
}
