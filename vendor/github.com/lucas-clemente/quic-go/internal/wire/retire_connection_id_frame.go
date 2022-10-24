package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

// A RetireConnectionIDFrame is a RETIRE_CONNECTION_ID frame
type RetireConnectionIDFrame struct {
	SequenceNumber uint64
}

func parseRetireConnectionIDFrame(r *bytes.Reader, _ protocol.VersionNumber) (*RetireConnectionIDFrame, error) {
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	seq, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	return &RetireConnectionIDFrame{SequenceNumber: seq}, nil
}

func (f *RetireConnectionIDFrame) Append(b []byte, _ protocol.VersionNumber) ([]byte, error) {
	b = append(b, 0x19)
	b = quicvarint.Append(b, f.SequenceNumber)
	return b, nil
}

// Length of a written frame
func (f *RetireConnectionIDFrame) Length(protocol.VersionNumber) protocol.ByteCount {
	return 1 + quicvarint.Len(f.SequenceNumber)
}
