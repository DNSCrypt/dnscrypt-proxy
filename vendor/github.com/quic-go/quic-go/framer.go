package quic

import (
	"slices"
	"sync"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils/minheap"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	maxPathResponses = 256
	maxControlFrames = 16 << 10
)

// This is the largest possible size of a stream-related control frame
// (which is the RESET_STREAM frame).
const maxStreamControlFrameSize = 25

type streamFrameGetter interface {
	priority() (urgency int8, incremental bool, generation uint32)
	popStreamFrame(protocol.ByteCount, protocol.Version) (_ ackhandler.StreamFrame, _ *wire.StreamDataBlockedFrame, hasMoreData bool)
	popRetransmissionFrame(protocol.ByteCount, protocol.Version) (ackhandler.StreamFrame, bool)
}

type streamControlFrameGetter interface {
	getControlFrame(monotime.Time) (_ ackhandler.Frame, ok, hasMore bool)
}

// streamQueueEntry captures the stream's generation when it is queued.
// A mismatch with the current generation identifies an entry left behind by a priority change.
type streamQueueEntry struct {
	id         protocol.StreamID
	generation uint32
}

// queuedStream tracks the latest generation added to a scheduling queue,
// preventing duplicate and out-of-order notifications from queueing it again.
type queuedStream struct {
	streamFrameGetter
	generation uint32
}

type framer struct {
	mutex sync.Mutex

	activeStreams         map[protocol.StreamID]queuedStream
	retransmissionStreams map[protocol.StreamID]streamFrameGetter

	incrementalStreams    [8]ringbuffer.RingBuffer[streamQueueEntry]
	nonIncrementalStreams [8]minheap.Heap[protocol.StreamID, uint32 /* generation */]
	// If an urgency level contains both incremental and non-incremental streams,
	// we round-robin between incremental and non-incremental streams.
	lastSendWasIncremental [8]bool

	streamsWithControlFrames map[protocol.StreamID]streamControlFrameGetter
	// Retransmissions are not incremental: repair all lost data for the first queued stream.
	// New losses extend its batch, so A, B, A is repaired as A, A, B, delaying B.
	// The ring buffer provides FIFO scheduling while reusing its storage.
	retransmissionQueue [8]ringbuffer.RingBuffer[protocol.StreamID]

	controlFrameMutex          sync.Mutex
	controlFrames              []wire.Frame
	pathResponses              []*wire.PathResponseFrame
	connFlowController         *connectionFlowController
	queuedTooManyControlFrames bool
}

func newFramer(connFlowController *connectionFlowController) *framer {
	return &framer{
		activeStreams:            make(map[protocol.StreamID]queuedStream),
		retransmissionStreams:    make(map[protocol.StreamID]streamFrameGetter),
		streamsWithControlFrames: make(map[protocol.StreamID]streamControlFrameGetter),
		connFlowController:       connFlowController,
	}
}

func (f *framer) HasData() bool {
	f.controlFrameMutex.Lock()
	hasControlFrames := len(f.streamsWithControlFrames) > 0 || len(f.controlFrames) > 0 || len(f.pathResponses) > 0
	f.controlFrameMutex.Unlock()

	if hasControlFrames {
		return true
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()

	for urgency := range f.incrementalStreams {
		if !f.incrementalStreams[urgency].Empty() || !f.nonIncrementalStreams[urgency].Empty() ||
			!f.retransmissionQueue[urgency].Empty() {
			return true
		}
	}
	return false
}

func (f *framer) QueueControlFrame(frame wire.Frame) {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()

	if pr, ok := frame.(*wire.PathResponseFrame); ok {
		// Only queue up to maxPathResponses PATH_RESPONSE frames.
		// This limit should be high enough to never be hit in practice,
		// unless the peer is doing something malicious.
		if len(f.pathResponses) >= maxPathResponses {
			return
		}
		f.pathResponses = append(f.pathResponses, pr)
		return
	}
	// This is a hack.
	if len(f.controlFrames) >= maxControlFrames {
		f.queuedTooManyControlFrames = true
		return
	}
	f.controlFrames = append(f.controlFrames, frame)
}

func (f *framer) Append(
	frames []ackhandler.Frame,
	streamFrames []ackhandler.StreamFrame,
	maxLen protocol.ByteCount,
	now monotime.Time,
	v protocol.Version,
) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
	f.controlFrameMutex.Lock()
	frames, controlFrameLen := f.appendControlFrames(frames, maxLen, now, v)
	maxLen -= controlFrameLen

	var lastFrame ackhandler.StreamFrame
	var streamFrameLen protocol.ByteCount
	f.mutex.Lock()
	// retransmit all lost STREAM data before sending new STREAM data
retransmissions:
	for urgency := range f.retransmissionQueue {
		bucket := &f.retransmissionQueue[urgency]
		for !bucket.Empty() && protocol.MinStreamFrameSize <= maxLen {
			id := bucket.PeekFront()
			str, ok := f.retransmissionStreams[id]
			if !ok {
				bucket.PopFront()
				continue
			}
			currentUrgency, _, _ := str.priority()
			if currentUrgency != int8(urgency) {
				bucket.PopFront()
				f.retransmissionQueue[currentUrgency].PushBack(id)
				continue
			}
			// For the last STREAM frame, we'll remove the DataLen field later.
			frameMaxLen := maxLen + protocol.ByteCount(quicvarint.Len(uint64(maxLen)))
			sf, hasMoreRetransmissions := str.popRetransmissionFrame(frameMaxLen, v)
			if !hasMoreRetransmissions {
				bucket.PopFront()
				delete(f.retransmissionStreams, id)
			}
			if sf.Frame == nil {
				// If the retransmission didn't fit, retry it in the next packet.
				if hasMoreRetransmissions {
					break retransmissions
				}
				continue
			}
			streamFrames = append(streamFrames, sf)
			maxLen -= sf.Frame.Length(v)
			lastFrame = sf
			streamFrameLen += sf.Frame.Length(v)
		}
	}
	// pop STREAM frames, until less than 128 bytes are left in the packet
	for urgency := range f.incrementalStreams {
		numActiveStreams := f.incrementalStreams[urgency].Len() + f.nonIncrementalStreams[urgency].Len()

		for range numActiveStreams {
			if protocol.MinStreamFrameSize > maxLen {
				break
			}
			sf, blocked := f.getNextStreamFrame(maxLen, int8(urgency), v)
			if sf.Frame != nil {
				streamFrames = append(streamFrames, sf)
				maxLen -= sf.Frame.Length(v)
				lastFrame = sf
				streamFrameLen += sf.Frame.Length(v)
			}
			// If the stream just became blocked on stream flow control, attempt to pack the
			// STREAM_DATA_BLOCKED into the same packet.
			if blocked != nil {
				l := blocked.Length(v)
				// In case it doesn't fit, queue it for the next packet.
				if maxLen < l {
					f.controlFrames = append(f.controlFrames, blocked)
					break
				}
				frames = append(frames, ackhandler.Frame{Frame: blocked})
				maxLen -= l
				controlFrameLen += l
			}
		}
	}

	// The only way to become blocked on connection-level flow control is by sending STREAM frames.
	if isBlocked, offset := f.connFlowController.IsNewlyBlocked(); isBlocked {
		blocked := &wire.DataBlockedFrame{MaximumData: offset}
		l := blocked.Length(v)
		// In case it doesn't fit, queue it for the next packet.
		if maxLen >= l {
			frames = append(frames, ackhandler.Frame{Frame: blocked})
			controlFrameLen += l
		} else {
			f.controlFrames = append(f.controlFrames, blocked)
		}
	}

	f.mutex.Unlock()
	f.controlFrameMutex.Unlock()

	if lastFrame.Frame != nil {
		// account for the smaller size of the last STREAM frame
		streamFrameLen -= lastFrame.Frame.Length(v)
		lastFrame.Frame.DataLenPresent = false
		streamFrameLen += lastFrame.Frame.Length(v)
	}

	return frames, streamFrames, controlFrameLen + streamFrameLen
}

func (f *framer) appendControlFrames(
	frames []ackhandler.Frame,
	maxLen protocol.ByteCount,
	now monotime.Time,
	v protocol.Version,
) ([]ackhandler.Frame, protocol.ByteCount) {
	var length protocol.ByteCount
	// add a PATH_RESPONSE first, but only pack a single PATH_RESPONSE per packet
	if len(f.pathResponses) > 0 {
		frame := f.pathResponses[0]
		frameLen := frame.Length(v)
		if frameLen <= maxLen {
			frames = append(frames, ackhandler.Frame{Frame: frame})
			length += frameLen
			f.pathResponses = f.pathResponses[1:]
		}
	}

	// add stream-related control frames
	for id, str := range f.streamsWithControlFrames {
	start:
		remainingLen := maxLen - length
		if remainingLen <= maxStreamControlFrameSize {
			break
		}
		fr, ok, hasMore := str.getControlFrame(now)
		if !hasMore {
			delete(f.streamsWithControlFrames, id)
		}
		if !ok {
			continue
		}
		frames = append(frames, fr)
		length += fr.Frame.Length(v)
		if hasMore {
			// It is rare that a stream has more than one control frame to queue.
			// We don't want to spawn another loop for just to cover that case.
			goto start
		}
	}

	for len(f.controlFrames) > 0 {
		frame := f.controlFrames[len(f.controlFrames)-1]
		frameLen := frame.Length(v)
		if length+frameLen > maxLen {
			break
		}
		frames = append(frames, ackhandler.Frame{Frame: frame})
		length += frameLen
		f.controlFrames = f.controlFrames[:len(f.controlFrames)-1]
	}

	return frames, length
}

// QueuedTooManyControlFrames says if the control frame queue exceeded its maximum queue length.
// This is a hack.
// It is easier to implement than propagating an error return value in QueueControlFrame.
// The correct solution would be to queue frames with their respective structs.
// See https://github.com/quic-go/quic-go/issues/4271 for the queueing of stream-related control frames.
func (f *framer) QueuedTooManyControlFrames() bool {
	return f.queuedTooManyControlFrames
}

func (f *framer) AddActiveStream(id protocol.StreamID, str streamFrameGetter) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	urgency, incremental, generation := str.priority()
	if activeStr, ok := f.activeStreams[id]; ok && activeStr.generation == generation {
		return
	}
	if incremental {
		f.incrementalStreams[urgency].PushBack(streamQueueEntry{id: id, generation: generation})
	} else {
		f.nonIncrementalStreams[urgency].Push(id, generation)
	}
	f.activeStreams[id] = queuedStream{streamFrameGetter: str, generation: generation}
}

func (f *framer) AddStreamWithRetransmission(id protocol.StreamID, str streamFrameGetter) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	urgency, _, _ := str.priority()
	if _, ok := f.retransmissionStreams[id]; ok {
		return
	}
	f.retransmissionQueue[urgency].PushBack(id)
	f.retransmissionStreams[id] = str
}

func (f *framer) AddStreamWithControlFrames(id protocol.StreamID, str streamControlFrameGetter) {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()

	if _, ok := f.streamsWithControlFrames[id]; !ok {
		f.streamsWithControlFrames[id] = str
	}
}

// RemoveActiveStream is called when a stream completes.
func (f *framer) RemoveActiveStream(id protocol.StreamID) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// We don't delete the stream from the ring buffers and heaps,
	// since we'd have to find it there first.
	// Instead, we check if the stream is still in active when appending STREAM frames.
	delete(f.activeStreams, id)
	delete(f.retransmissionStreams, id)
}

func (f *framer) UpdateStreamPriority(id protocol.StreamID) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	str, ok := f.activeStreams[id]
	if !ok {
		return
	}
	urgency, incremental, generation := str.priority()
	if str.generation != generation {
		// Leave the old queue entry in place. It will be discarded when it reaches
		// the front of that queue and no longer matches the stream's generation.
		if incremental {
			f.incrementalStreams[urgency].PushBack(streamQueueEntry{id: id, generation: generation})
		} else {
			f.nonIncrementalStreams[urgency].Push(id, generation)
		}
		str.generation = generation
		f.activeStreams[id] = str
	}
}

func (f *framer) getNextStreamFrame(
	maxLen protocol.ByteCount,
	urgency int8,
	v protocol.Version,
) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame) {
	if f.nonIncrementalStreams[urgency].Empty() || (!f.lastSendWasIncremental[urgency] && !f.incrementalStreams[urgency].Empty()) {
		return f.getNextIncrementalStreamFrame(maxLen, urgency, v)
	}
	return f.getNextNonIncrementalStreamFrame(maxLen, urgency, v)
}

func (f *framer) getNextIncrementalStreamFrame(
	maxLen protocol.ByteCount,
	urgency int8,
	v protocol.Version,
) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame) {
	queue := &f.incrementalStreams[urgency]
	if queue.Empty() {
		return ackhandler.StreamFrame{}, nil
	}
	entry := queue.PopFront()
	str, ok := f.activeStreams[entry.id]
	if !ok {
		return ackhandler.StreamFrame{}, nil
	}
	_, _, generation := str.priority()
	if generation != entry.generation {
		return ackhandler.StreamFrame{}, nil
	}

	frame, blocked, hasMoreData := f.popStreamFrame(entry.id, str, maxLen, v)
	if hasMoreData {
		queue.PushBack(entry)
	}
	f.lastSendWasIncremental[urgency] = true
	return frame, blocked
}

func (f *framer) getNextNonIncrementalStreamFrame(
	maxLen protocol.ByteCount,
	urgency int8,
	v protocol.Version,
) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame) {
	queue := &f.nonIncrementalStreams[urgency]
	if queue.Empty() {
		return ackhandler.StreamFrame{}, nil
	}
	id, queuedGeneration := queue.Peek()
	str, ok := f.activeStreams[id]
	if !ok {
		queue.Pop()
		return ackhandler.StreamFrame{}, nil
	}
	_, _, generation := str.priority()
	if generation != queuedGeneration {
		queue.Pop()
		return ackhandler.StreamFrame{}, nil
	}

	frame, blocked, hasMoreData := f.popStreamFrame(id, str, maxLen, v)
	if !hasMoreData {
		queue.Pop()
	}
	f.lastSendWasIncremental[urgency] = false
	return frame, blocked
}

func (f *framer) popStreamFrame(
	id protocol.StreamID,
	str queuedStream,
	maxLen protocol.ByteCount,
	v protocol.Version,
) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
	// For the last STREAM frame, we'll remove the DataLen field later.
	// Therefore, we can pretend to have more bytes available when popping
	// the STREAM frame (which will always have the DataLen set).
	maxLen += protocol.ByteCount(quicvarint.Len(uint64(maxLen)))
	frame, blocked, hasMoreData := str.popStreamFrame(maxLen, v)
	if !hasMoreData {
		delete(f.activeStreams, id)
	}
	// Note that the frame.Frame can be nil:
	// * if the stream was canceled after it said it had data
	// * the remaining size doesn't allow us to add another STREAM frame
	return frame, blocked, hasMoreData
}

func (f *framer) Handle0RTTRejection() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()

	for urgency := range f.incrementalStreams {
		f.incrementalStreams[urgency].Clear()
		f.nonIncrementalStreams[urgency].Clear()
		f.lastSendWasIncremental[urgency] = false
		f.retransmissionQueue[urgency].Clear()
	}
	clear(f.activeStreams)
	clear(f.retransmissionStreams)
	clear(f.streamsWithControlFrames)

	var j int
	for i, frame := range f.controlFrames {
		switch frame.(type) {
		case *wire.MaxDataFrame, *wire.MaxStreamDataFrame, *wire.MaxStreamsFrame,
			*wire.DataBlockedFrame, *wire.StreamDataBlockedFrame, *wire.StreamsBlockedFrame:
			continue
		default:
			f.controlFrames[j] = f.controlFrames[i]
			j++
		}
	}
	f.controlFrames = slices.Delete(f.controlFrames, j, len(f.controlFrames))
}
