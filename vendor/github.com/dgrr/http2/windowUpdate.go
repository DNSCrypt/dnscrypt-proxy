package http2

import (
	"github.com/dgrr/http2/http2utils"
)

const FrameWindowUpdate FrameType = 0x8

var _ Frame = &WindowUpdate{}

// WindowUpdate https://tools.ietf.org/html/rfc7540#section-6.9
type WindowUpdate struct {
	increment int
}

func (wu *WindowUpdate) Type() FrameType {
	return FrameWindowUpdate
}

func (wu *WindowUpdate) Reset() {
	wu.increment = 0
}

func (wu *WindowUpdate) CopyTo(w *WindowUpdate) {
	w.increment = wu.increment
}

func (wu *WindowUpdate) Increment() int {
	return wu.increment
}

func (wu *WindowUpdate) SetIncrement(increment int) {
	wu.increment = increment
}

func (wu *WindowUpdate) Deserialize(fr *FrameHeader) error {
	if len(fr.payload) < 4 {
		wu.increment = 0
		return ErrMissingBytes
	}

	wu.increment = int(http2utils.BytesToUint32(fr.payload) & (1<<31 - 1))

	return nil
}

func (wu *WindowUpdate) Serialize(fr *FrameHeader) {
	fr.payload = http2utils.AppendUint32Bytes(
		fr.payload[:0], uint32(wu.increment))
	fr.length = 4
}
