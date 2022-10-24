package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type datagramQueue struct {
	sendQueue chan *wire.DatagramFrame
	nextFrame *wire.DatagramFrame
	rcvQueue  chan []byte

	closeErr error
	closed   chan struct{}

	hasData func()

	dequeued chan struct{}

	logger utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	return &datagramQueue{
		hasData:   hasData,
		sendQueue: make(chan *wire.DatagramFrame, 1),
		rcvQueue:  make(chan []byte, protocol.DatagramRcvQueueLen),
		dequeued:  make(chan struct{}),
		closed:    make(chan struct{}),
		logger:    logger,
	}
}

// AddAndWait queues a new DATAGRAM frame for sending.
// It blocks until the frame has been dequeued.
func (h *datagramQueue) AddAndWait(f *wire.DatagramFrame) error {
	select {
	case h.sendQueue <- f:
		h.hasData()
	case <-h.closed:
		return h.closeErr
	}

	select {
	case <-h.dequeued:
		return nil
	case <-h.closed:
		return h.closeErr
	}
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	if h.nextFrame != nil {
		return h.nextFrame
	}
	select {
	case h.nextFrame = <-h.sendQueue:
		h.dequeued <- struct{}{}
	default:
		return nil
	}
	return h.nextFrame
}

func (h *datagramQueue) Pop() {
	if h.nextFrame == nil {
		panic("datagramQueue BUG: Pop called for nil frame")
	}
	h.nextFrame = nil
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	data := make([]byte, len(f.Data))
	copy(data, f.Data)
	select {
	case h.rcvQueue <- data:
	default:
		h.logger.Debugf("Discarding DATAGRAM frame (%d bytes payload)", len(f.Data))
	}
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive() ([]byte, error) {
	select {
	case data := <-h.rcvQueue:
		return data, nil
	case <-h.closed:
		return nil, h.closeErr
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.closeErr = e
	close(h.closed)
}
