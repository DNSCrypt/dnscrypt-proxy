package wire

import (
	"bytes"

	"github.com/quic-go/quic-go/internal/protocol"
)

// A PingFrame is a PING frame
type PingFrame struct{}

func parsePingFrame(r *bytes.Reader, _ protocol.VersionNumber) (*PingFrame, error) {
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}
	return &PingFrame{}, nil
}

func (f *PingFrame) Append(b []byte, _ protocol.VersionNumber) ([]byte, error) {
	return append(b, 0x1), nil
}

// Length of a written frame
func (f *PingFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	return 1
}
