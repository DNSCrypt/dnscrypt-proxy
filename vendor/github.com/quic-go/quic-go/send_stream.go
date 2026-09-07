package quic

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

const defaultUrgency = 3

func encodeStreamPriority(urgency int8, incremental bool, generation uint32) uint64 {
	priorityValue := uint64(uint8(urgency)) | uint64(generation)<<32
	if incremental {
		priorityValue |= 1 << 8
	}
	return priorityValue
}

func decodeStreamPriority(priorityValue uint64) (urgency int8, incremental bool, generation uint32) {
	return int8(priorityValue), uint8(priorityValue>>8) != 0, uint32(priorityValue >> 32)
}

// A SendStream is a unidirectional Send Stream.
type SendStream struct {
	mutex sync.Mutex

	numOutstandingFrames int64 // outstanding STREAM and RESET_STREAM frames
	retransmissionQueue  []*wire.StreamFrame

	ctx       context.Context
	ctxCancel context.CancelCauseFunc

	streamID protocol.StreamID
	sender   streamSender

	// reliableSize is the portion of the stream that needs to be transmitted reliably,
	// even if the stream is cancelled.
	// This requires the peer to support RESET_STREAM_AT.
	// This value should not be accessed directly, but only through the reliableOffset method.
	// This method returns 0 if the peer doesn't support the RESET_STREAM_AT extension.
	reliableSize protocol.ByteCount
	writeOffset  protocol.ByteCount

	shutdownErr            error
	resetErr               *StreamError
	queuedResetStreamFrame *wire.ResetStreamFrame

	dataForWriting []byte // during a Write() call, this slice is the part of p that still needs to be sent out

	writeLimiter func(int) int
	// Set by the packetizer when writeLimiter reduces the allowed byte count. It makes the blocked
	// WriteWithLimit return ErrWriteLimitReached and prevents another dequeue before it wakes up.
	writeLimited bool

	nextFrame *wire.StreamFrame
	// set if flow control credit for nextFrame was already consumed
	nextFrameReserved bool

	supportsResetStreamAt bool
	finishedWriting       bool // set once Close() is called
	finSent               bool // set when a STREAM_FRAME with FIN bit has been sent
	// Set when the application knows about the cancellation.
	// This can happen because the application called CancelWrite,
	// or because Write returned the error (for remote cancellations).
	cancellationFlagged bool
	completed           bool // set when this stream no longer needs to be scheduled

	priorityValue atomic.Uint64

	writeChan chan struct{}
	writeOnce chan struct{}
	deadline  monotime.Time

	flowController *streamFlowController
}

var (
	_ streamControlFrameGetter = &SendStream{}
	_ outgoingStream           = &SendStream{}
	_ sendStreamFrameHandler   = &SendStream{}
)

func newSendStream(
	ctx context.Context,
	streamID protocol.StreamID,
	sender streamSender,
	flowController *streamFlowController,
	supportsResetStreamAt bool,
) *SendStream {
	s := &SendStream{
		streamID:              streamID,
		sender:                sender,
		flowController:        flowController,
		writeChan:             make(chan struct{}, 1),
		writeOnce:             make(chan struct{}, 1), // cap: 1, to protect against concurrent use of Write
		supportsResetStreamAt: supportsResetStreamAt,
	}
	s.priorityValue.Store(encodeStreamPriority(defaultUrgency, true, 0))
	s.ctx, s.ctxCancel = context.WithCancelCause(ctx)
	return s
}

// StreamID returns the stream ID.
func (s *SendStream) StreamID() StreamID {
	return s.streamID // same for receiveStream and sendStream
}

// Write writes data to the stream.
// Write can be made to time out using [SendStream.SetWriteDeadline].
// If the stream was canceled, the error is a [StreamError].
func (s *SendStream) Write(p []byte) (int, error) {
	return s.WriteWithLimit(p, nil)
}

// WriteWithLimit writes data to the stream, subject to an additional send limit.
// During packetization, limiter receives the bytes allowed for the next STREAM frame after
// QUIC flow control and returns how many may be sent. Returning n in [0, maxBytes] commits
// n bytes of limiter credit; the limiter is not called again when those bytes are retransmitted.
// Values outside [0, maxBytes] are clamped.
// A short result returns the accepted prefix and [ErrWriteLimitReached]; the caller can wait
// for external credit and retry the suffix. QUIC blocking behaves like [SendStream.Write].
// limiter can run multiple times on another goroutine while QUIC send flow-control accounting
// is locked. It must be concurrency-safe and must not block or call QUIC methods.
// A nil limiter behaves like [SendStream.Write].
func (s *SendStream) WriteWithLimit(p []byte, limiter func(maxBytes int) int) (int, error) {
	// Concurrent use of Write is not permitted (and doesn't make any sense),
	// but sometimes people do it anyway.
	// Make sure that we only execute one call at any given time to avoid hard to debug failures.
	s.writeOnce <- struct{}{}
	defer func() { <-s.writeOnce }()

	isNewlyCompleted, n, err := s.write(p, limiter)
	if isNewlyCompleted {
		s.sender.onStreamCompleted(s.streamID)
	}
	return n, err
}

// TryWriteAll writes data to the stream if it can be queued immediately.
// It doesn't block for flow control credit and doesn't respect the write deadline.
// If the entire slice can't be queued immediately, it queues nothing and returns [ErrWouldBlock].
func (s *SendStream) TryWriteAll(p []byte) error {
	select {
	case s.writeOnce <- struct{}{}:
		defer func() { <-s.writeOnce }()
	default:
		return ErrWouldBlock
	}

	isNewlyCompleted, hasData, err := s.tryWriteAll(p)
	if isNewlyCompleted {
		s.sender.onStreamCompleted(s.streamID)
	}
	if hasData {
		s.sender.onHasStreamData(s.streamID, s)
	}
	return err
}

func (s *SendStream) tryWriteAll(p []byte) (bool /* is newly completed */, bool /* has data */, error) {
	// This might wait briefly while a packet is dequeuing stream data.
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resetErr != nil {
		s.cancellationFlagged = true
		return s.isNewlyCompleted(), false, s.resetErr
	}
	if s.shutdownErr != nil {
		return false, false, s.shutdownErr
	}
	if s.finishedWriting {
		return false, false, fmt.Errorf("write on closed stream %d", s.streamID)
	}
	if len(p) == 0 {
		return false, false, nil
	}

	bytesToReserve := protocol.ByteCount(len(p))
	if s.nextFrame != nil && !s.nextFrameReserved {
		bytesToReserve += s.nextFrame.DataLen()
	}
	if !s.flowController.TryAddBytesSent(bytesToReserve) {
		return false, false, ErrWouldBlock
	}

	if s.nextFrame == nil {
		s.nextFrame = wire.GetStreamFrame()
		s.nextFrame.Offset = s.writeOffset
		s.nextFrame.StreamID = s.streamID
		s.nextFrame.DataLenPresent = true
		s.nextFrame.Data = s.nextFrame.Data[:0]
	}
	l := len(s.nextFrame.Data)
	if l+len(p) > cap(s.nextFrame.Data) {
		// Pooled STREAM frames must keep their packet-sized buffer.
		// Use a non-pooled frame when the queued data grows beyond that.
		nextFrame := &wire.StreamFrame{
			StreamID:       s.streamID,
			Offset:         s.nextFrame.Offset,
			DataLenPresent: true,
			Data:           make([]byte, l+len(p)),
		}
		copy(nextFrame.Data, s.nextFrame.Data)
		s.nextFrame.PutBack()
		s.nextFrame = nextFrame
	} else {
		s.nextFrame.Data = s.nextFrame.Data[:l+len(p)]
	}
	copy(s.nextFrame.Data[l:], p)
	s.nextFrameReserved = true
	return false, true, nil
}

func (s *SendStream) write(p []byte, limiter func(int) int) (bool /* is newly completed */, int, error) {
	s.mutex.Lock()
	s.writeLimiter = limiter
	s.writeLimited = false
	defer func() {
		s.writeLimiter = nil
		s.writeLimited = false
		s.mutex.Unlock()
	}()

	if s.resetErr != nil {
		s.cancellationFlagged = true
		return s.isNewlyCompleted(), 0, s.resetErr
	}
	if s.shutdownErr != nil {
		return false, 0, s.shutdownErr
	}
	if s.finishedWriting {
		return false, 0, fmt.Errorf("write on closed stream %d", s.streamID)
	}
	if !s.deadline.IsZero() && !monotime.Now().Before(s.deadline) {
		return false, 0, errDeadline
	}
	if len(p) == 0 {
		return false, 0, nil
	}

	s.dataForWriting = p

	var (
		deadlineTimer  *time.Timer
		bytesWritten   int
		notifiedSender bool
	)
	for {
		if s.writeLimited {
			bytesWritten = len(p) - len(s.dataForWriting)
			s.dataForWriting = nil
			break
		}
		var copied bool
		var deadline monotime.Time
		// As soon as dataForWriting becomes smaller than a certain size x, we copy all the data to a STREAM frame (s.nextFrame),
		// which can then be popped the next time we assemble a packet.
		// This allows us to return Write() when all data but x bytes have been sent out.
		// When the user now calls Close(), this is much more likely to happen before we popped that last STREAM frame,
		// allowing us to set the FIN bit on that frame (instead of sending an empty STREAM frame with FIN).
		if s.canBufferStreamFrame() && len(s.dataForWriting) > 0 {
			if s.nextFrame == nil {
				f := wire.GetStreamFrame()
				f.Offset = s.writeOffset
				f.StreamID = s.streamID
				f.DataLenPresent = true
				f.Data = f.Data[:len(s.dataForWriting)]
				copy(f.Data, s.dataForWriting)
				s.nextFrame = f
			} else {
				l := len(s.nextFrame.Data)
				s.nextFrame.Data = s.nextFrame.Data[:l+len(s.dataForWriting)]
				copy(s.nextFrame.Data[l:], s.dataForWriting)
			}
			s.dataForWriting = nil
			bytesWritten = len(p)
			copied = true
		} else {
			bytesWritten = len(p) - len(s.dataForWriting)
			deadline = s.deadline
			if !deadline.IsZero() {
				if !monotime.Now().Before(deadline) {
					s.dataForWriting = nil
					return false, bytesWritten, errDeadline
				}
				if deadlineTimer == nil {
					deadlineTimer = time.NewTimer(monotime.Until(deadline))
					defer deadlineTimer.Stop()
				} else {
					deadlineTimer.Reset(monotime.Until(deadline))
				}
			}
			if s.dataForWriting == nil || s.shutdownErr != nil || s.resetErr != nil {
				break
			}
		}

		s.mutex.Unlock()
		if !notifiedSender {
			s.sender.onHasStreamData(s.streamID, s) // must be called without holding the mutex
			notifiedSender = true
		}
		if copied {
			s.mutex.Lock()
			break
		}
		if deadline.IsZero() {
			<-s.writeChan
		} else {
			select {
			case <-s.writeChan:
			case <-deadlineTimer.C:
			}
		}
		s.mutex.Lock()
	}

	if bytesWritten == len(p) {
		return false, bytesWritten, nil
	}
	if s.shutdownErr != nil {
		return false, bytesWritten, s.shutdownErr
	}
	if s.resetErr != nil {
		s.cancellationFlagged = true
		return s.isNewlyCompleted(), bytesWritten, s.resetErr
	}
	if s.writeLimited {
		return false, bytesWritten, ErrWriteLimitReached
	}
	return false, bytesWritten, nil
}

func (s *SendStream) canBufferStreamFrame() bool {
	if s.writeLimiter != nil || s.nextFrameReserved {
		return false
	}
	var l protocol.ByteCount
	if s.nextFrame != nil {
		l = s.nextFrame.DataLen()
	}
	return l+protocol.ByteCount(len(s.dataForWriting)) <= protocol.MaxPacketBufferSize
}

// popStreamFrame returns the next STREAM frame that is supposed to be sent on this stream
// maxBytes is the maximum length this frame (including frame header) will have.
// hasMoreData says if more data can be sent after this call without first
// receiving a MAX_STREAM_DATA frame.
func (s *SendStream) popStreamFrame(maxBytes protocol.ByteCount, v protocol.Version) (_ ackhandler.StreamFrame, _ *wire.StreamDataBlockedFrame, hasMoreData bool) {
	s.mutex.Lock()
	f, blocked, hasMoreData := s.popNewStreamFrameForPacket(maxBytes, v)
	if f != nil {
		s.numOutstandingFrames++
	}
	s.mutex.Unlock()
	if blocked != nil {
		hasMoreData = false
	}

	if f == nil {
		return ackhandler.StreamFrame{}, blocked, hasMoreData
	}
	return ackhandler.StreamFrame{
		Frame:   f,
		Handler: (*sendStreamAckHandler)(s),
	}, blocked, hasMoreData
}

func (s *SendStream) popNewStreamFrameForPacket(maxBytes protocol.ByteCount, v protocol.Version) (_ *wire.StreamFrame, _ *wire.StreamDataBlockedFrame, hasMoreData bool) {
	if s.shutdownErr != nil {
		return nil, nil, false
	}
	if s.resetErr != nil {
		reliableOffset := s.reliableOffset()
		if reliableOffset == 0 || s.writeOffset >= reliableOffset {
			return nil, nil, false
		}
	}

	if s.writeLimited {
		return nil, nil, false
	}

	if len(s.dataForWriting) == 0 && s.nextFrame == nil {
		if s.finishedWriting && !s.finSent {
			s.finSent = true
			return &wire.StreamFrame{
				StreamID:       s.streamID,
				Offset:         s.writeOffset,
				DataLenPresent: true,
				Fin:            true,
			}, nil, false
		}
		return nil, nil, false
	}

	// if the stream is canceled, only data up to the reliable size needs to be sent
	reliableOffset := s.reliableOffset()
	limitedWrite := s.writeLimiter != nil && s.nextFrame == nil
	var maxDataLen protocol.ByteCount
	if s.nextFrameReserved {
		maxDataLen = s.nextFrame.DataLen()
	} else {
		maxDataLen = s.flowController.SendWindowSize()
	}
	if s.resetErr != nil && reliableOffset > 0 {
		maxDataLen = min(maxDataLen, reliableOffset-s.writeOffset)
	}
	if s.nextFrame != nil {
		maxDataLen = min(maxDataLen, s.nextFrame.MaxDataLen(maxBytes, v), s.nextFrame.DataLen())
	} else {
		f := wire.StreamFrame{
			StreamID:       s.streamID,
			Offset:         s.writeOffset,
			DataLenPresent: true,
		}
		maxDataLen = min(maxDataLen, f.MaxDataLen(maxBytes, v), protocol.ByteCount(len(s.dataForWriting)))
	}
	if maxDataLen == 0 {
		return nil, nil, true
	}
	if limitedWrite {
		added, limited := s.flowController.AddBytesSentWithLimiter(maxDataLen, s.writeLimiter)
		if limited {
			s.writeLimited = true
			s.signalWrite()
		}
		maxDataLen = added
		if maxDataLen == 0 {
			return nil, nil, !limited
		}
	} else if !s.nextFrameReserved && !s.flowController.TryAddBytesSent(maxDataLen) {
		return nil, nil, true
	}
	f, hasMoreData := s.popNewStreamFrame(maxDataLen)
	if f.DataLen() > 0 {
		s.writeOffset += f.DataLen()
	}
	if s.resetErr != nil && s.writeOffset >= reliableOffset {
		hasMoreData = false
	}
	if s.writeLimited {
		hasMoreData = false
	}
	var blocked *wire.StreamDataBlockedFrame
	// Flow control for a reserved frame was consumed when it was queued. Don't
	// report the stream blocked while reserved bytes can still be sent.
	if f.DataLen() > 0 && !s.nextFrameReserved {
		if isBlocked, offset := s.flowController.isNewlyBlocked(); isBlocked {
			blocked = &wire.StreamDataBlockedFrame{StreamID: s.streamID, MaximumStreamData: offset}
		}
	}
	f.Fin = s.finishedWriting && s.dataForWriting == nil && s.nextFrame == nil && !s.finSent
	if f.Fin {
		s.finSent = true
	}
	return f, blocked, hasMoreData
}

// popNewStreamFrame returns a new STREAM frame to send for this stream
// hasMoreData says if there's more data to send, *not* taking into account the reliable size
func (s *SendStream) popNewStreamFrame(maxDataLen protocol.ByteCount) (_ *wire.StreamFrame, hasMoreData bool) {
	if s.nextFrame != nil {
		nextFrame := s.nextFrame
		nextFrameReserved := s.nextFrameReserved
		s.nextFrame = nil
		s.nextFrameReserved = false
		if nextFrame.DataLen() > maxDataLen {
			if nextFrame.DataLen()-maxDataLen > protocol.MaxPacketBufferSize {
				s.nextFrame = &wire.StreamFrame{
					Data: make([]byte, nextFrame.DataLen()-maxDataLen),
				}
			} else {
				s.nextFrame = wire.GetStreamFrame()
				s.nextFrame.Data = s.nextFrame.Data[:nextFrame.DataLen()-maxDataLen]
			}
			s.nextFrame.StreamID = s.streamID
			s.nextFrame.Offset = s.writeOffset + maxDataLen
			s.nextFrame.DataLenPresent = true
			copy(s.nextFrame.Data, nextFrame.Data[maxDataLen:])
			nextFrame.Data = nextFrame.Data[:maxDataLen]
			s.nextFrameReserved = nextFrameReserved
		} else {
			s.signalWrite()
		}
		return nextFrame, s.nextFrame != nil || s.dataForWriting != nil
	}

	f := wire.GetStreamFrame()
	f.Fin = false
	f.StreamID = s.streamID
	f.Offset = s.writeOffset
	f.DataLenPresent = true
	f.Data = f.Data[:0]

	s.getDataForWriting(f, maxDataLen)
	return f, s.dataForWriting != nil || s.nextFrame != nil || s.finishedWriting
}

func (s *SendStream) popRetransmissionFrame(maxBytes protocol.ByteCount, v protocol.Version) (_ ackhandler.StreamFrame, hasMore bool) {
	s.mutex.Lock()
	if s.shutdownErr != nil || len(s.retransmissionQueue) == 0 {
		s.mutex.Unlock()
		return ackhandler.StreamFrame{}, false
	}
	f := s.retransmissionQueue[0]
	newFrame, needsSplit := f.MaybeSplitOffFrame(maxBytes, v)
	if needsSplit {
		f = newFrame
		hasMore = true
	} else {
		s.retransmissionQueue = s.retransmissionQueue[1:]
		hasMore = len(s.retransmissionQueue) > 0
	}
	if f != nil {
		s.numOutstandingFrames++
	}
	s.mutex.Unlock()

	if f == nil {
		return ackhandler.StreamFrame{}, hasMore
	}
	return ackhandler.StreamFrame{Frame: f, Handler: (*sendStreamAckHandler)(s)}, hasMore
}

func (s *SendStream) getDataForWriting(f *wire.StreamFrame, maxBytes protocol.ByteCount) {
	if protocol.ByteCount(len(s.dataForWriting)) <= maxBytes {
		f.Data = f.Data[:len(s.dataForWriting)]
		copy(f.Data, s.dataForWriting)
		s.dataForWriting = nil
		s.signalWrite()
		return
	}
	f.Data = f.Data[:maxBytes]
	copy(f.Data, s.dataForWriting)
	s.dataForWriting = s.dataForWriting[maxBytes:]
	if s.canBufferStreamFrame() {
		s.signalWrite()
	}
}

func (s *SendStream) isNewlyCompleted() bool {
	if s.completed {
		return false
	}
	if s.nextFrame != nil && s.nextFrame.DataLen() > 0 {
		return false
	}
	// We need to keep the stream around until all frames have been sent and acknowledged.
	if s.numOutstandingFrames > 0 || len(s.retransmissionQueue) > 0 || s.queuedResetStreamFrame != nil {
		return false
	}
	// The stream is completed if we sent the FIN.
	if s.finSent {
		s.completed = true
		return true
	}
	// The stream is also completed if:
	// 1. the application called CancelWrite, or
	// 2. we received a STOP_SENDING, and
	// 		* the application consumed the error via Write, or
	//		* the application called Close
	if s.resetErr != nil && (s.cancellationFlagged || s.finishedWriting) {
		s.completed = true
		return true
	}
	return false
}

// Close closes the write-direction of the stream.
// Future calls to [SendStream.Write] are not permitted after calling Close.
// It must not be called concurrently with [SendStream.Write].
// It must not be called after calling [SendStream.CancelWrite].
func (s *SendStream) Close() error {
	s.mutex.Lock()
	if s.shutdownErr != nil || s.finishedWriting {
		s.mutex.Unlock()
		return nil
	}
	s.finishedWriting = true
	cancelled := s.resetErr != nil
	if cancelled {
		s.cancellationFlagged = true
	}
	completed := s.isNewlyCompleted()
	s.mutex.Unlock()

	if completed {
		s.sender.onStreamCompleted(s.streamID)
	}
	if cancelled {
		return fmt.Errorf("close called for canceled stream %d", s.streamID)
	}
	s.sender.onHasStreamData(s.streamID, s) // need to send the FIN, must be called without holding the mutex

	s.ctxCancel(nil)
	return nil
}

// SetReliableBoundary marks the data written to this stream so far as reliable.
// It is valid to call this function multiple times, thereby increasing the reliable size.
// It only has an effect if the peer enabled support for the RESET_STREAM_AT extension,
// otherwise, it is a no-op.
func (s *SendStream) SetReliableBoundary() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.nextFrame != nil {
		s.reliableSize = max(s.reliableSize, s.writeOffset+s.nextFrame.DataLen())
	} else {
		s.reliableSize = max(s.reliableSize, s.writeOffset)
	}
}

// returnFramesToPool returns all queued frames to the sync.Pool
func (s *SendStream) returnFramesToPool() {
	for _, f := range s.retransmissionQueue {
		f.PutBack()
	}
	clear(s.retransmissionQueue)
	s.retransmissionQueue = nil
	if s.nextFrame != nil {
		s.nextFrame.PutBack()
		s.nextFrame = nil
	}
	s.nextFrameReserved = false
}

// CancelWrite aborts sending on this stream.
// Data already written, but not yet delivered to the peer is not guaranteed to be delivered reliably.
// [SendStream.Write] will unblock immediately, and future calls to it will fail.
// When called multiple times it is a no-op.
// When called after [SendStream.Close], it aborts reliable delivery of outstanding stream data.
// Note that there is no guarantee if the peer will receive the FIN or the cancellation error first.
func (s *SendStream) CancelWrite(errorCode StreamErrorCode) {
	s.mutex.Lock()
	if s.shutdownErr != nil {
		s.mutex.Unlock()
		return
	}

	s.cancellationFlagged = true

	if s.resetErr != nil {
		completed := s.isNewlyCompleted()
		s.mutex.Unlock()
		// The user has called CancelWrite. If the previous cancellation was because of a
		// STOP_SENDING, we don't need to flag the error to the user anymore.
		if completed {
			s.sender.onStreamCompleted(s.streamID)
		}
		return
	}
	s.resetErr = &StreamError{StreamID: s.streamID, ErrorCode: errorCode, Remote: false}
	s.ctxCancel(s.resetErr)

	reliableOffset := s.reliableOffset()
	finalSize := max(s.writeOffset, reliableOffset)
	if s.nextFrameReserved && s.nextFrame != nil {
		finalSize = max(finalSize, s.nextFrame.Offset+s.nextFrame.DataLen())
	}
	if reliableOffset == 0 {
		s.numOutstandingFrames = 0
		s.returnFramesToPool()
	}
	s.queuedResetStreamFrame = &wire.ResetStreamFrame{
		StreamID:  s.streamID,
		FinalSize: finalSize,
		ErrorCode: errorCode,
		// if the peer doesn't support the extension, the reliable offset will always be 0
		ReliableSize: reliableOffset,
	}
	if reliableOffset > 0 {
		if s.nextFrame != nil {
			if s.nextFrame.Offset >= reliableOffset {
				s.nextFrame.PutBack()
				s.nextFrame = nil
				s.nextFrameReserved = false
			} else if s.nextFrame.Offset+s.nextFrame.DataLen() > reliableOffset {
				s.nextFrame.Data = s.nextFrame.Data[:reliableOffset-s.nextFrame.Offset]
			}
		}
		if len(s.retransmissionQueue) > 0 {
			retransmissionQueue := make([]*wire.StreamFrame, 0, len(s.retransmissionQueue))
			for _, f := range s.retransmissionQueue {
				if f.Offset >= reliableOffset {
					f.PutBack()
					continue
				}
				if f.Offset+f.DataLen() <= reliableOffset {
					retransmissionQueue = append(retransmissionQueue, f)
				} else {
					f.Data = f.Data[:reliableOffset-f.Offset]
					retransmissionQueue = append(retransmissionQueue, f)
				}
			}
			s.retransmissionQueue = retransmissionQueue
		}
	}
	s.mutex.Unlock()

	s.signalWrite()
	s.sender.onHasStreamControlFrame(s.streamID, s)
}

func (s *SendStream) enableResetStreamAt() {
	s.mutex.Lock()
	s.supportsResetStreamAt = true
	s.mutex.Unlock()
}

func (s *SendStream) updateSendWindow(limit protocol.ByteCount) {
	s.mutex.Lock()
	updated := s.flowController.UpdateSendWindow(limit)
	if !updated { // duplicate or reordered MAX_STREAM_DATA frame
		s.mutex.Unlock()
		return
	}
	hasStreamData := s.dataForWriting != nil || s.nextFrame != nil
	s.mutex.Unlock()
	if hasStreamData {
		s.sender.onHasStreamData(s.streamID, s)
	}
}

func (s *SendStream) handleStopSendingFrame(f *wire.StopSendingFrame) {
	s.mutex.Lock()
	if s.shutdownErr != nil {
		s.mutex.Unlock()
		return
	}

	// If the stream was already cancelled (either locally, or due to a previous STOP_SENDING frame),
	// there's nothing else to do.
	if s.resetErr != nil && s.reliableOffset() == 0 {
		s.mutex.Unlock()
		return
	}
	// if the peer stopped reading from the stream, there's no need to transmit any data reliably
	s.reliableSize = 0
	s.numOutstandingFrames = 0
	finalSize := s.writeOffset
	if s.nextFrameReserved && s.nextFrame != nil {
		finalSize = max(finalSize, s.nextFrame.Offset+s.nextFrame.DataLen())
	}
	s.returnFramesToPool()
	if s.resetErr == nil {
		s.resetErr = &StreamError{StreamID: s.streamID, ErrorCode: f.ErrorCode, Remote: true}
		s.ctxCancel(s.resetErr)
	}
	s.queuedResetStreamFrame = &wire.ResetStreamFrame{
		StreamID:  s.streamID,
		FinalSize: finalSize,
		ErrorCode: s.resetErr.ErrorCode,
	}
	s.mutex.Unlock()

	s.signalWrite()
	s.sender.onHasStreamControlFrame(s.streamID, s)
}

func (s *SendStream) getControlFrame(monotime.Time) (_ ackhandler.Frame, ok, hasMore bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.queuedResetStreamFrame == nil {
		return ackhandler.Frame{}, false, false
	}
	s.numOutstandingFrames++
	f := ackhandler.Frame{
		Frame:   s.queuedResetStreamFrame,
		Handler: (*sendStreamResetStreamHandler)(s),
	}
	s.queuedResetStreamFrame = nil
	return f, true, false
}

func (s *SendStream) reliableOffset() protocol.ByteCount {
	if !s.supportsResetStreamAt {
		return 0
	}
	return s.reliableSize
}

// SetPriority sets the scheduling priority for data sent on the stream.
// It uses the urgency and incremental parameters defined by [RFC 9218].
// Urgency is clipped to the range 0 through 7, with lower values taking priority.
// Within an urgency level, incremental streams are scheduled round-robin,
// while non-incremental streams are scheduled by stream ID.
//
// The default priority is urgency 3 with incremental set to true. RFC 9218
// instead defaults incremental to false.
//
// [RFC 9218]: https://www.rfc-editor.org/rfc/rfc9218.html
func (s *SendStream) SetPriority(urgency int8, incremental bool) {
	urgency = max(0, min(urgency, 7)) // urgency must be between 0 and 7
	s.mutex.Lock()
	if s.completed {
		s.mutex.Unlock()
		return
	}
	oldUrgency, oldIncremental, generation := decodeStreamPriority(s.priorityValue.Load())
	if oldUrgency == urgency && oldIncremental == incremental {
		s.mutex.Unlock()
		return
	}
	s.priorityValue.Store(encodeStreamPriority(urgency, incremental, generation+1))
	// Keep qlogging under the lock so shutdown can't close the qlogger concurrently.
	s.sender.recordStreamPriorityUpdated(s.streamID, urgency, incremental)
	s.mutex.Unlock()
	// The framer calls back into the stream while holding its lock.
	s.sender.updateStreamPriority(s.streamID)
}

// The Context is canceled as soon as the write-side of the stream is closed.
// This happens when [SendStream.Close] or [SendStream.CancelWrite] is called, or when the peer
// cancels the read-side of their stream.
// The cancellation cause is set to the error that caused the stream to
// close, or [context.Canceled] in case the stream is closed without error.
func (s *SendStream) Context() context.Context {
	return s.ctx
}

// SetWriteDeadline sets the deadline for future [SendStream.Write] calls
// and any currently blocked call.
// Even if write times out, it may return n > 0, indicating that
// some data was successfully written.
// A zero value for t means [SendStream.Write] will not time out.
func (s *SendStream) SetWriteDeadline(t time.Time) error {
	s.mutex.Lock()
	s.deadline = monotime.FromTime(t)
	s.mutex.Unlock()
	s.signalWrite()
	return nil
}

// CloseForShutdown closes a stream abruptly.
// It makes Write unblock (and return the error) immediately.
// The peer will NOT be informed about this: the stream is closed without sending a FIN or RST.
func (s *SendStream) closeForShutdown(err error) {
	s.mutex.Lock()
	s.completed = true
	if s.shutdownErr == nil && !s.finishedWriting {
		s.shutdownErr = err
		s.returnFramesToPool()
	}
	s.mutex.Unlock()
	s.ctxCancel(err)
	s.signalWrite()
}

// signalWrite performs a non-blocking send on the writeChan
func (s *SendStream) signalWrite() {
	select {
	case s.writeChan <- struct{}{}:
	default:
	}
}

func (s *SendStream) priority() (urgency int8, incremental bool, generation uint32) {
	return decodeStreamPriority(s.priorityValue.Load())
}

type sendStreamAckHandler SendStream

var _ ackhandler.FrameHandler = &sendStreamAckHandler{}

func (s *sendStreamAckHandler) OnAcked(f wire.Frame) {
	sf := f.(*wire.StreamFrame)
	sf.PutBack()

	s.mutex.Lock()
	if s.resetErr != nil && (*SendStream)(s).reliableOffset() == 0 {
		s.mutex.Unlock()
		return
	}
	s.numOutstandingFrames--
	if s.numOutstandingFrames < 0 {
		panic("numOutStandingFrames negative")
	}
	completed := (*SendStream)(s).isNewlyCompleted()
	s.mutex.Unlock()

	if completed {
		s.sender.onStreamCompleted(s.streamID)
	}
}

func (s *sendStreamAckHandler) OnLost(f wire.Frame) {
	sf := f.(*wire.StreamFrame)
	s.mutex.Lock()
	// If the reliable size was 0 when the stream was cancelled,
	// the number of outstanding frames was immediately set to 0, and the retransmission queue was dropped.
	if s.resetErr != nil && (*SendStream)(s).reliableOffset() == 0 {
		// Return the frame to pool since it won't be retransmitted
		sf.PutBack()
		s.mutex.Unlock()
		return
	}
	s.numOutstandingFrames--
	if s.numOutstandingFrames < 0 {
		panic("numOutStandingFrames negative")
	}

	if s.resetErr != nil && (*SendStream)(s).reliableOffset() > 0 {
		// If the stream was reset, and this frame is beyond the reliable offset,
		// it doesn't need to be retransmitted.
		if sf.Offset >= (*SendStream)(s).reliableOffset() {
			sf.PutBack()
			// If this frame was the last one tracked, losing it might cause the stream to be completed.
			completed := (*SendStream)(s).isNewlyCompleted()
			s.mutex.Unlock()
			if completed {
				s.sender.onStreamCompleted(s.streamID)
			}
			return
		}
		// If the payload of the frame extends beyond the reliable size,
		// truncate the frame to the reliable size.
		if sf.Offset+sf.DataLen() > (*SendStream)(s).reliableOffset() {
			sf.Data = sf.Data[:(*SendStream)(s).reliableOffset()-sf.Offset]
		}
	}

	sf.DataLenPresent = true
	wasEmpty := len(s.retransmissionQueue) == 0
	s.retransmissionQueue = append(s.retransmissionQueue, sf)
	s.mutex.Unlock()

	if wasEmpty {
		s.sender.onHasStreamRetransmission(s.streamID, (*SendStream)(s))
	}
}

type sendStreamResetStreamHandler SendStream

var _ ackhandler.FrameHandler = &sendStreamResetStreamHandler{}

func (s *sendStreamResetStreamHandler) OnAcked(f wire.Frame) {
	rsf := f.(*wire.ResetStreamFrame)
	s.mutex.Lock()
	// If the peer sent a STOP_SENDING after we sent a RESET_STREAM_AT frame,
	// we sent 1. reduced the reliable size to 0 and 2. sent a RESET_STREAM frame.
	// In this case, we don't care about the acknowledgment of this frame.
	if rsf.ReliableSize != (*SendStream)(s).reliableOffset() {
		s.mutex.Unlock()
		return
	}
	s.numOutstandingFrames--
	if s.numOutstandingFrames < 0 {
		panic("numOutStandingFrames negative")
	}
	completed := (*SendStream)(s).isNewlyCompleted()
	s.mutex.Unlock()

	if completed {
		s.sender.onStreamCompleted(s.streamID)
	}
}

func (s *sendStreamResetStreamHandler) OnLost(f wire.Frame) {
	rsf := f.(*wire.ResetStreamFrame)
	s.mutex.Lock()
	// If the peer sent a STOP_SENDING after we sent a RESET_STREAM_AT frame,
	// we sent 1. reduced the reliable size to 0 and 2. sent a RESET_STREAM frame.
	// In this case, the loss of the RESET_STREAM_AT frame can be ignored.
	if rsf.ReliableSize != (*SendStream)(s).reliableOffset() {
		s.mutex.Unlock()
		return
	}
	s.queuedResetStreamFrame = rsf
	s.numOutstandingFrames--
	s.mutex.Unlock()
	s.sender.onHasStreamControlFrame(s.streamID, (*SendStream)(s))
}
