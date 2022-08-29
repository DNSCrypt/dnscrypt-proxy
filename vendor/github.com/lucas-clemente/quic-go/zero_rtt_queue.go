package quic

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type zeroRTTQueue struct {
	queue       []*receivedPacket
	retireTimer *time.Timer
}

var _ packetHandler = &zeroRTTQueue{}

func (h *zeroRTTQueue) handlePacket(p *receivedPacket) {
	if len(h.queue) < protocol.Max0RTTQueueLen {
		h.queue = append(h.queue, p)
	}
}
func (h *zeroRTTQueue) shutdown()                            {}
func (h *zeroRTTQueue) destroy(error)                        {}
func (h *zeroRTTQueue) getPerspective() protocol.Perspective { return protocol.PerspectiveClient }
func (h *zeroRTTQueue) EnqueueAll(sess packetHandler) {
	for _, p := range h.queue {
		sess.handlePacket(p)
	}
}

func (h *zeroRTTQueue) Clear() {
	for _, p := range h.queue {
		p.buffer.Release()
	}
}
