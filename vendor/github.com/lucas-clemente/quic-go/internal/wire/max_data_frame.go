package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

// A MaxDataFrame carries flow control information for the connection
type MaxDataFrame struct {
	MaximumData protocol.ByteCount
}

// parseMaxDataFrame parses a MAX_DATA frame
func parseMaxDataFrame(r *bytes.Reader, _ protocol.VersionNumber) (*MaxDataFrame, error) {
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	frame := &MaxDataFrame{}
	byteOffset, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	frame.MaximumData = protocol.ByteCount(byteOffset)
	return frame, nil
}

// Write writes a MAX_STREAM_DATA frame
func (f *MaxDataFrame) Append(b []byte, _ protocol.VersionNumber) ([]byte, error) {
	b = append(b, 0x10)
	b = quicvarint.Append(b, uint64(f.MaximumData))
	return b, nil
}

// Length of a written frame
func (f *MaxDataFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	return 1 + quicvarint.Len(uint64(f.MaximumData))
}
