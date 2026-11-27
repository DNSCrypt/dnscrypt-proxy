package udp

import (
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
)

type PacketBuffer struct {
	Data []byte

	// refCount counts how many packets Data is used in.
	// It doesn't support concurrent use.
	// It is > 1 when used for coalesced packet.
	refCount int
}

// Split increases the refCount.
// It must be called when a packet buffer is used for more than one packet,
// e.g. when splitting coalesced packets.
func (b *PacketBuffer) Split() {
	b.refCount++
}

// Decrement decrements the reference counter.
// It doesn't put the buffer back into the pool.
func (b *PacketBuffer) Decrement() {
	b.refCount--
	if b.refCount < 0 {
		panic("negative packetBuffer refCount")
	}
}

// MaybeRelease puts the packet buffer back into the pool,
// if the reference counter already reached 0.
func (b *PacketBuffer) MaybeRelease() {
	// only put the packetBuffer back if it's not used any more
	if b.refCount == 0 {
		b.putBack()
	}
}

// Release puts back the packet buffer into the pool.
// It should be called when processing is definitely finished.
func (b *PacketBuffer) Release() {
	b.Decrement()
	if b.refCount != 0 {
		panic("packetBuffer refCount not zero")
	}
	b.putBack()
}

// Len returns the length of Data
func (b *PacketBuffer) Len() protocol.ByteCount { return protocol.ByteCount(len(b.Data)) }
func (b *PacketBuffer) Cap() protocol.ByteCount { return protocol.ByteCount(cap(b.Data)) }

func (b *PacketBuffer) putBack() {
	if cap(b.Data) == protocol.MaxPacketBufferSize {
		bufferPool.Put(b)
		return
	}
	if cap(b.Data) == protocol.MaxLargePacketBufferSize {
		largeBufferPool.Put(b)
		return
	}
	panic("putPacketBuffer called with packet of wrong size!")
}

var bufferPool, largeBufferPool sync.Pool

func GetPacketBuffer() *PacketBuffer {
	buf := bufferPool.Get().(*PacketBuffer)
	buf.refCount = 1
	buf.Data = buf.Data[:0]
	return buf
}

func GetLargePacketBuffer() *PacketBuffer {
	buf := largeBufferPool.Get().(*PacketBuffer)
	buf.refCount = 1
	buf.Data = buf.Data[:0]
	return buf
}

func init() {
	bufferPool.New = func() any {
		return &PacketBuffer{Data: make([]byte, 0, protocol.MaxPacketBufferSize)}
	}
	largeBufferPool.New = func() any {
		return &PacketBuffer{Data: make([]byte, 0, protocol.MaxLargePacketBufferSize)}
	}
}
