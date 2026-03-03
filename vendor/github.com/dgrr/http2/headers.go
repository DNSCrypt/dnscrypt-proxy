package http2

import (
	"github.com/dgrr/http2/http2utils"
)

const FrameHeaders FrameType = 0x1

var (
	_ Frame            = &Headers{}
	_ FrameWithHeaders = &Headers{}
)

type FrameWithHeaders interface {
	Headers() []byte
}

// Headers defines a FrameHeaders
//
// https://tools.ietf.org/html/rfc7540#section-6.2
type Headers struct {
	hasPadding bool
	stream     uint32
	weight     uint8
	endStream  bool
	endHeaders bool
	priority   bool
	rawHeaders []byte // this field is used to store uncompleted headers.
}

func (h *Headers) Reset() {
	h.hasPadding = false
	h.stream = 0
	h.weight = 0
	h.endStream = false
	h.endHeaders = false
	h.priority = false
	h.rawHeaders = h.rawHeaders[:0]
}

// CopyTo copies h fields to h2.
func (h *Headers) CopyTo(h2 *Headers) {
	h2.hasPadding = h.hasPadding
	h2.stream = h.stream
	h2.weight = h.weight
	h2.endStream = h.endStream
	h2.endHeaders = h.endHeaders
	h2.rawHeaders = append(h2.rawHeaders[:0], h.rawHeaders...)
}

func (h *Headers) Type() FrameType {
	return FrameHeaders
}

func (h *Headers) Headers() []byte {
	return h.rawHeaders
}

func (h *Headers) SetHeaders(b []byte) {
	h.rawHeaders = append(h.rawHeaders[:0], b...)
}

// AppendRawHeaders appends b to the raw headers.
func (h *Headers) AppendRawHeaders(b []byte) {
	h.rawHeaders = append(h.rawHeaders, b...)
}

func (h *Headers) AppendHeaderField(hp *HPACK, hf *HeaderField, store bool) {
	h.rawHeaders = hp.AppendHeader(h.rawHeaders, hf, store)
}

func (h *Headers) EndStream() bool {
	return h.endStream
}

func (h *Headers) SetEndStream(value bool) {
	h.endStream = value
}

func (h *Headers) EndHeaders() bool {
	return h.endHeaders
}

func (h *Headers) SetEndHeaders(value bool) {
	h.endHeaders = value
}

func (h *Headers) Stream() uint32 {
	return h.stream
}

func (h *Headers) SetStream(stream uint32) {
	h.stream = stream
}

func (h *Headers) Weight() byte {
	return h.weight
}

func (h *Headers) SetWeight(w byte) {
	h.weight = w
}

func (h *Headers) Padding() bool {
	return h.hasPadding
}

func (h *Headers) SetPadding(value bool) {
	h.hasPadding = value
}

func (h *Headers) Deserialize(frh *FrameHeader) error {
	flags := frh.Flags()
	payload := frh.payload

	if flags.Has(FlagPadded) {
		var err error
		payload, err = http2utils.CutPadding(payload, len(payload))
		if err != nil {
			return err
		}
	}

	if flags.Has(FlagPriority) {
		if len(payload) < 5 { // 4 (stream) + 1 (weight)
			return ErrMissingBytes
		}
		h.priority = true
		h.stream = http2utils.BytesToUint32(payload) & (1<<31 - 1)
		h.weight = payload[4]
		payload = payload[5:]
	}

	h.endStream = flags.Has(FlagEndStream)
	h.endHeaders = flags.Has(FlagEndHeaders)
	h.rawHeaders = append(h.rawHeaders, payload...)

	return nil
}

func (h *Headers) Serialize(frh *FrameHeader) {
	if h.endStream {
		frh.SetFlags(
			frh.Flags().Add(FlagEndStream))
	}

	if h.endHeaders {
		frh.SetFlags(
			frh.Flags().Add(FlagEndHeaders))
	}

	if h.priority {
		frh.SetFlags(
			frh.Flags().Add(FlagPriority))

		// prepend stream and weight to rawHeaders
		h.rawHeaders = append(h.rawHeaders, 0, 0, 0, 0, 0)
		copy(h.rawHeaders[5:], h.rawHeaders)
		http2utils.Uint32ToBytes(h.rawHeaders[0:4], frh.stream)
		h.rawHeaders[4] = h.weight
	}

	if h.hasPadding {
		frh.SetFlags(
			frh.Flags().Add(FlagPadded))
		h.rawHeaders = http2utils.AddPadding(h.rawHeaders)
	}

	frh.payload = append(frh.payload[:0], h.rawHeaders...)
}
