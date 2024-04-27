package http3

import (
	"errors"
	"sync"

	"github.com/quic-go/quic-go"
)

type streamState uint8

const (
	streamStateOpen streamState = iota
	streamStateReceiveClosed
	streamStateSendClosed
	streamStateSendAndReceiveClosed
)

type stateTrackingStream struct {
	quic.Stream

	mx    sync.Mutex
	state streamState

	onStateChange func(streamState, error)
}

func newStateTrackingStream(s quic.Stream, onStateChange func(streamState, error)) *stateTrackingStream {
	return &stateTrackingStream{
		Stream:        s,
		state:         streamStateOpen,
		onStateChange: onStateChange,
	}
}

var _ quic.Stream = &stateTrackingStream{}

func (s *stateTrackingStream) closeSend(e error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	if s.state == streamStateReceiveClosed || s.state == streamStateSendAndReceiveClosed {
		s.state = streamStateSendAndReceiveClosed
	} else {
		s.state = streamStateSendClosed
	}
	s.onStateChange(s.state, e)
}

func (s *stateTrackingStream) closeReceive(e error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	if s.state == streamStateSendClosed || s.state == streamStateSendAndReceiveClosed {
		s.state = streamStateSendAndReceiveClosed
	} else {
		s.state = streamStateReceiveClosed
	}
	s.onStateChange(s.state, e)
}

func (s *stateTrackingStream) Close() error {
	s.closeSend(errors.New("write on closed stream"))
	return s.Stream.Close()
}

func (s *stateTrackingStream) CancelWrite(e quic.StreamErrorCode) {
	s.closeSend(&quic.StreamError{StreamID: s.Stream.StreamID(), ErrorCode: e})
	s.Stream.CancelWrite(e)
}

func (s *stateTrackingStream) Write(b []byte) (int, error) {
	n, err := s.Stream.Write(b)
	if err != nil {
		s.closeSend(err)
	}
	return n, err
}

func (s *stateTrackingStream) CancelRead(e quic.StreamErrorCode) {
	s.closeReceive(&quic.StreamError{StreamID: s.Stream.StreamID(), ErrorCode: e})
	s.Stream.CancelRead(e)
}

func (s *stateTrackingStream) Read(b []byte) (int, error) {
	n, err := s.Stream.Read(b)
	if err != nil {
		s.closeReceive(err)
	}
	return n, err
}
