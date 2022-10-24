package wire

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

// A StreamsBlockedFrame is a STREAMS_BLOCKED frame
type StreamsBlockedFrame struct {
	Type        protocol.StreamType
	StreamLimit protocol.StreamNum
}

func parseStreamsBlockedFrame(r *bytes.Reader, _ protocol.VersionNumber) (*StreamsBlockedFrame, error) {
	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	f := &StreamsBlockedFrame{}
	switch typeByte {
	case 0x16:
		f.Type = protocol.StreamTypeBidi
	case 0x17:
		f.Type = protocol.StreamTypeUni
	}
	streamLimit, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	f.StreamLimit = protocol.StreamNum(streamLimit)
	if f.StreamLimit > protocol.MaxStreamCount {
		return nil, fmt.Errorf("%d exceeds the maximum stream count", f.StreamLimit)
	}
	return f, nil
}

func (f *StreamsBlockedFrame) Append(b []byte, _ protocol.VersionNumber) ([]byte, error) {
	switch f.Type {
	case protocol.StreamTypeBidi:
		b = append(b, 0x16)
	case protocol.StreamTypeUni:
		b = append(b, 0x17)
	}
	b = quicvarint.Append(b, uint64(f.StreamLimit))
	return b, nil
}

// Length of a written frame
func (f *StreamsBlockedFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	return 1 + quicvarint.Len(uint64(f.StreamLimit))
}
