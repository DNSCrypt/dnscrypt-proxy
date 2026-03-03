package http2

import (
	"fmt"

	"github.com/dgrr/http2/http2utils"
)

const FrameGoAway FrameType = 0x7

var _ Frame = &GoAway{}

// GoAway https://tools.ietf.org/html/rfc7540#section-6.8
type GoAway struct {
	stream uint32
	code   ErrorCode
	data   []byte // additional data
}

func (ga *GoAway) Error() string {
	return fmt.Sprintf("stream=%d, code=%s, data=%s", ga.stream, ga.code, ga.data)
}

func (ga *GoAway) Type() FrameType {
	return FrameGoAway
}

func (ga *GoAway) Reset() {
	ga.stream = 0
	ga.code = 0
	ga.data = ga.data[:0]
}

func (ga *GoAway) CopyTo(other *GoAway) {
	other.stream = ga.stream
	other.code = ga.code
	other.data = append(other.data[:0], ga.data...)
}

func (ga *GoAway) Copy() *GoAway {
	other := new(GoAway)
	other.stream = ga.stream
	other.code = ga.code
	other.data = append(other.data[:0], ga.data...)
	return other
}

func (ga *GoAway) Code() ErrorCode {
	return ga.code
}

func (ga *GoAway) SetCode(code ErrorCode) {
	ga.code = code & (1<<31 - 1)
	// TODO: Set error description as a debug data?
}

func (ga *GoAway) Stream() uint32 {
	return ga.stream
}

func (ga *GoAway) SetStream(stream uint32) {
	ga.stream = stream & (1<<31 - 1)
}

func (ga *GoAway) Data() []byte {
	return ga.data
}

func (ga *GoAway) SetData(b []byte) {
	ga.data = append(ga.data[:0], b...)
}

func (ga *GoAway) Deserialize(fr *FrameHeader) (err error) {
	if len(fr.payload) < 8 { // 8 is the min number of bytes
		err = ErrMissingBytes
	} else {
		ga.stream = http2utils.BytesToUint32(fr.payload)
		ga.code = ErrorCode(http2utils.BytesToUint32(fr.payload[4:]))
		// TODO: what?

		if len(fr.payload[8:]) != 0 {
			ga.data = append(ga.data[:0], fr.payload[8:]...)
		}
	}

	return
}

func (ga *GoAway) Serialize(fr *FrameHeader) {
	fr.payload = http2utils.AppendUint32Bytes(fr.payload[:0], ga.stream)
	fr.payload = http2utils.AppendUint32Bytes(fr.payload[:4], uint32(ga.code))

	fr.payload = append(fr.payload, ga.data...)
}
