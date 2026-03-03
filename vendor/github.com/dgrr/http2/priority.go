package http2

import (
	"github.com/dgrr/http2/http2utils"
)

const FramePriority FrameType = 0x2

var _ Frame = &Priority{}

// Priority represents the Priority frame.
//
// https://tools.ietf.org/html/rfc7540#section-6.3
type Priority struct {
	stream uint32
	weight byte
}

func (pry *Priority) Type() FrameType {
	return FramePriority
}

// Reset resets priority fields.
func (pry *Priority) Reset() {
	pry.stream = 0
	pry.weight = 0
}

func (pry *Priority) CopyTo(p *Priority) {
	p.stream = pry.stream
	p.weight = pry.weight
}

// Stream returns the Priority frame stream.
func (pry *Priority) Stream() uint32 {
	return pry.stream
}

// SetStream sets the Priority frame stream.
func (pry *Priority) SetStream(stream uint32) {
	pry.stream = stream & (1<<31 - 1)
}

// Weight returns the Priority frame weight.
func (pry *Priority) Weight() byte {
	return pry.weight
}

// SetWeight sets the Priority frame weight.
func (pry *Priority) SetWeight(w byte) {
	pry.weight = w
}

func (pry *Priority) Deserialize(fr *FrameHeader) (err error) {
	if len(fr.payload) < 5 {
		err = ErrMissingBytes
	} else {
		pry.stream = http2utils.BytesToUint32(fr.payload) & (1<<31 - 1)
		pry.weight = fr.payload[4]
	}

	return
}

func (pry *Priority) Serialize(fr *FrameHeader) {
	fr.payload = http2utils.AppendUint32Bytes(fr.payload[:0], pry.stream)
	fr.payload = append(fr.payload, pry.weight)
}
