package quic

import (
	"context"
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

type incomingStream interface {
	closeForShutdown(error)
}

// When a stream is deleted before it was accepted, we can't delete it from the map immediately.
// We need to wait until the application accepts it, and delete it then.
type incomingStreamEntry[T incomingStream] struct {
	stream       T
	shouldDelete bool
}

type incomingStreamsMap[T incomingStream] struct {
	mutex         sync.RWMutex
	newStreamChan chan struct{}

	streamType protocol.StreamType
	streams    map[protocol.StreamNum]incomingStreamEntry[T]

	nextStreamToAccept protocol.StreamNum // the next stream that will be returned by AcceptStream()
	nextStreamToOpen   protocol.StreamNum // the highest stream that the peer opened
	maxStream          protocol.StreamNum // the highest stream that the peer is allowed to open
	maxNumStreams      uint64             // maximum number of streams

	newStream        func(protocol.StreamNum) T
	queueMaxStreamID func(*wire.MaxStreamsFrame)

	closeErr error
}

func newIncomingStreamsMap[T incomingStream](
	streamType protocol.StreamType,
	newStream func(protocol.StreamNum) T,
	maxStreams uint64,
	queueControlFrame func(wire.Frame),
) *incomingStreamsMap[T] {
	return &incomingStreamsMap[T]{
		newStreamChan:      make(chan struct{}, 1),
		streamType:         streamType,
		streams:            make(map[protocol.StreamNum]incomingStreamEntry[T]),
		maxStream:          protocol.StreamNum(maxStreams),
		maxNumStreams:      maxStreams,
		newStream:          newStream,
		nextStreamToOpen:   1,
		nextStreamToAccept: 1,
		queueMaxStreamID:   func(f *wire.MaxStreamsFrame) { queueControlFrame(f) },
	}
}

func (m *incomingStreamsMap[T]) AcceptStream(ctx context.Context) (T, error) {
	// drain the newStreamChan, so we don't check the map twice if the stream doesn't exist
	select {
	case <-m.newStreamChan:
	default:
	}

	m.mutex.Lock()

	var num protocol.StreamNum
	var entry incomingStreamEntry[T]
	for {
		num = m.nextStreamToAccept
		if m.closeErr != nil {
			m.mutex.Unlock()
			return *new(T), m.closeErr
		}
		var ok bool
		entry, ok = m.streams[num]
		if ok {
			break
		}
		m.mutex.Unlock()
		select {
		case <-ctx.Done():
			return *new(T), ctx.Err()
		case <-m.newStreamChan:
		}
		m.mutex.Lock()
	}
	m.nextStreamToAccept++
	// If this stream was completed before being accepted, we can delete it now.
	if entry.shouldDelete {
		if err := m.deleteStream(num); err != nil {
			m.mutex.Unlock()
			return *new(T), err
		}
	}
	m.mutex.Unlock()
	return entry.stream, nil
}

func (m *incomingStreamsMap[T]) GetOrOpenStream(num protocol.StreamNum) (T, error) {
	m.mutex.RLock()
	if num > m.maxStream {
		m.mutex.RUnlock()
		return *new(T), streamError{
			message: "peer tried to open stream %d (current limit: %d)",
			nums:    []protocol.StreamNum{num, m.maxStream},
		}
	}
	// if the num is smaller than the highest we accepted
	// * this stream exists in the map, and we can return it, or
	// * this stream was already closed, then we can return the nil
	if num < m.nextStreamToOpen {
		var s T
		// If the stream was already queued for deletion, and is just waiting to be accepted, don't return it.
		if entry, ok := m.streams[num]; ok && !entry.shouldDelete {
			s = entry.stream
		}
		m.mutex.RUnlock()
		return s, nil
	}
	m.mutex.RUnlock()

	m.mutex.Lock()
	// no need to check the two error conditions from above again
	// * maxStream can only increase, so if the id was valid before, it definitely is valid now
	// * highestStream is only modified by this function
	for newNum := m.nextStreamToOpen; newNum <= num; newNum++ {
		m.streams[newNum] = incomingStreamEntry[T]{stream: m.newStream(newNum)}
		select {
		case m.newStreamChan <- struct{}{}:
		default:
		}
	}
	m.nextStreamToOpen = num + 1
	entry := m.streams[num]
	m.mutex.Unlock()
	return entry.stream, nil
}

func (m *incomingStreamsMap[T]) DeleteStream(num protocol.StreamNum) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.deleteStream(num)
}

func (m *incomingStreamsMap[T]) deleteStream(num protocol.StreamNum) error {
	if _, ok := m.streams[num]; !ok {
		return streamError{
			message: "tried to delete unknown incoming stream %d",
			nums:    []protocol.StreamNum{num},
		}
	}

	// Don't delete this stream yet, if it was not yet accepted.
	// Just save it to streamsToDelete map, to make sure it is deleted as soon as it gets accepted.
	if num >= m.nextStreamToAccept {
		entry, ok := m.streams[num]
		if ok && entry.shouldDelete {
			return streamError{
				message: "tried to delete incoming stream %d multiple times",
				nums:    []protocol.StreamNum{num},
			}
		}
		entry.shouldDelete = true
		m.streams[num] = entry // can't assign to struct in map, so we need to reassign
		return nil
	}

	delete(m.streams, num)
	// queue a MAX_STREAM_ID frame, giving the peer the option to open a new stream
	if m.maxNumStreams > uint64(len(m.streams)) {
		maxStream := m.nextStreamToOpen + protocol.StreamNum(m.maxNumStreams-uint64(len(m.streams))) - 1
		// Never send a value larger than protocol.MaxStreamCount.
		if maxStream <= protocol.MaxStreamCount {
			m.maxStream = maxStream
			m.queueMaxStreamID(&wire.MaxStreamsFrame{
				Type:         m.streamType,
				MaxStreamNum: m.maxStream,
			})
		}
	}
	return nil
}

func (m *incomingStreamsMap[T]) CloseWithError(err error) {
	m.mutex.Lock()
	m.closeErr = err
	for _, entry := range m.streams {
		entry.stream.closeForShutdown(err)
	}
	m.mutex.Unlock()
	close(m.newStreamChan)
}
