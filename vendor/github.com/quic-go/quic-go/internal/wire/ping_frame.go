package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
)

// A PingFrame is a PING frame
type PingFrame struct{}

func (f *PingFrame) Append(b []byte, _ protocol.VersionNumber) ([]byte, error) {
	return append(b, pingFrameType), nil
}

// Length of a written frame
func (f *PingFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	return 1
}
