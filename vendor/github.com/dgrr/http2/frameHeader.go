package http2

import (
	"bufio"
	"fmt"
	"io"
	"sync"

	"github.com/dgrr/http2/http2utils"
)

const (
	// DefaultFrameSize FrameHeader default size
	// http://httpwg.org/specs/rfc7540.html#FrameHeader
	DefaultFrameSize = 9
	// https://httpwg.org/specs/rfc7540.html#SETTINGS_MAX_FRAME_SIZE
	defaultMaxLen = 1 << 14
)

// Frame Flag (described along the frame types)
// More flags have been ignored due to redundancy.
const (
	FlagAck        FrameFlags = 0x1
	FlagEndStream  FrameFlags = 0x1
	FlagEndHeaders FrameFlags = 0x4
	FlagPadded     FrameFlags = 0x8
	FlagPriority   FrameFlags = 0x20
)

// TODO: Develop methods for FrameFlags

var frameHeaderPool = sync.Pool{
	New: func() interface{} {
		return &FrameHeader{}
	},
}

// FrameHeader is frame representation of HTTP2 protocol
//
// Use AcquireFrameHeader instead of creating FrameHeader every time
// if you are going to use FrameHeader as your own and ReleaseFrameHeader to
// delete the FrameHeader
//
// FrameHeader instance MUST NOT be used from different goroutines.
//
// https://tools.ietf.org/html/rfc7540#section-4.1
type FrameHeader struct {
	length int        // 24 bits
	kind   FrameType  // 8 bits
	flags  FrameFlags // 8 bits
	stream uint32     // 31 bits

	maxLen uint32

	rawHeader [DefaultFrameSize]byte
	payload   []byte

	fr Frame
}

// AcquireFrameHeader gets a FrameHeader from pool.
func AcquireFrameHeader() *FrameHeader {
	fr := frameHeaderPool.Get().(*FrameHeader)
	fr.Reset()
	return fr
}

// ReleaseFrameHeader reset and puts fr to the pool.
func ReleaseFrameHeader(fr *FrameHeader) {
	ReleaseFrame(fr.Body())
	frameHeaderPool.Put(fr)
}

// Reset resets header values.
func (f *FrameHeader) Reset() {
	f.kind = 0
	f.flags = 0
	f.stream = 0
	f.length = 0
	f.maxLen = defaultMaxLen
	f.fr = nil
	f.payload = f.payload[:0]
}

// Type returns the frame type (https://httpwg.org/specs/rfc7540.html#Frame_types)
func (f *FrameHeader) Type() FrameType {
	return f.kind
}

func (f *FrameHeader) Flags() FrameFlags {
	return f.flags
}

func (f *FrameHeader) SetFlags(flags FrameFlags) {
	f.flags = flags
}

// Stream returns the stream id of the current frame.
func (f *FrameHeader) Stream() uint32 {
	return f.stream
}

// SetStream sets the stream id on the current frame.
//
// This function DOESN'T delete the reserved bit (first bit)
// in order to support personalized implementations of the protocol.
func (f *FrameHeader) SetStream(stream uint32) {
	f.stream = stream
}

// Len returns the payload length.
func (f *FrameHeader) Len() int {
	return f.length
}

// MaxLen returns max negotiated payload length.
func (f *FrameHeader) MaxLen() uint32 {
	return f.maxLen
}

func (f *FrameHeader) parseValues(header []byte) {
	f.length = int(http2utils.BytesToUint24(header[:3]))          // & (1<<24 - 1)    // 3
	f.kind = FrameType(header[3])                                 // 1
	f.flags = FrameFlags(header[4])                               // 1
	f.stream = http2utils.BytesToUint32(header[5:]) & (1<<31 - 1) // 4
}

func (f *FrameHeader) parseHeader(header []byte) {
	http2utils.Uint24ToBytes(header[:3], uint32(f.length)) // 2
	header[3] = byte(f.kind)                               // 1
	header[4] = byte(f.flags)                              // 1
	http2utils.Uint32ToBytes(header[5:], f.stream)         // 4
}

func ReadFrameFrom(br *bufio.Reader) (*FrameHeader, error) {
	fr := AcquireFrameHeader()

	_, err := fr.ReadFrom(br)
	if err != nil {
		if fr.Body() != nil {
			ReleaseFrameHeader(fr)
		} else {
			frameHeaderPool.Put(fr)
		}

		fr = nil
	}

	return fr, err
}

func ReadFrameFromWithSize(br *bufio.Reader, max uint32) (*FrameHeader, error) {
	fr := AcquireFrameHeader()
	fr.maxLen = max

	_, err := fr.ReadFrom(br)
	if err != nil {
		if fr.Body() != nil {
			ReleaseFrameHeader(fr)
		} else {
			frameHeaderPool.Put(fr)
		}

		fr = nil
	}

	return fr, err
}

// ReadFrom reads frame from Reader.
//
// This function returns read bytes and/or error.
//
// Unlike io.ReaderFrom this method does not read until io.EOF.
func (f *FrameHeader) ReadFrom(br *bufio.Reader) (int64, error) {
	return f.readFrom(br)
}

// TODO: Delete rb?
func (f *FrameHeader) readFrom(br *bufio.Reader) (int64, error) {
	header, err := br.Peek(DefaultFrameSize)
	if err != nil {
		return -1, err
	}

	_, _ = br.Discard(DefaultFrameSize)

	rn := int64(DefaultFrameSize)

	// Parsing FrameHeader's Header field.
	f.parseValues(header)
	if err = f.checkLen(); err != nil {
		return 0, err
	}

	if f.kind > FrameContinuation {
		_, _ = br.Discard(f.length)
		return 0, ErrUnknownFrameType
	}
	f.fr = AcquireFrame(f.kind)

	// if max > 0 && frh.length > max {
	// TODO: Discard bytes and return an error
	if f.length > 0 {
		n := f.length
		if n < 0 {
			panic(fmt.Sprintf("length is less than 0 (%d). Overflow? (%d)", n, f.length))
		}

		f.payload = http2utils.Resize(f.payload, n)

		n, err = io.ReadFull(br, f.payload[:n])
		if err != nil {
			ReleaseFrame(f.fr)
			return 0, err
		}

		rn += int64(n)
	}

	return rn, f.fr.Deserialize(f)
}

// WriteTo writes frame to the Writer.
//
// This function returns FrameHeader bytes written and/or error.
func (f *FrameHeader) WriteTo(w *bufio.Writer) (wb int64, err error) {
	f.fr.Serialize(f)

	f.length = len(f.payload)
	f.parseHeader(f.rawHeader[:])

	n, err := w.Write(f.rawHeader[:])
	if err == nil {
		wb += int64(n)

		n, err = w.Write(f.payload)
		wb += int64(n)
	}

	return wb, err
}

func (f *FrameHeader) Body() Frame {
	return f.fr
}

func (f *FrameHeader) SetBody(fr Frame) {
	if fr == nil {
		panic("Body cannot be nil")
	}

	f.kind = fr.Type()
	f.fr = fr
}

func (f *FrameHeader) setPayload(payload []byte) {
	f.payload = append(f.payload[:0], payload...)
}

func (f *FrameHeader) checkLen() error {
	if f.maxLen != 0 && f.length > int(f.maxLen) {
		return ErrPayloadExceeds
	}
	return nil
}
