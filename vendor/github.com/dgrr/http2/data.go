package http2

import (
	"github.com/dgrr/http2/http2utils"
)

const FrameData FrameType = 0x0

var _ Frame = &Data{}

// Data defines a FrameData
//
// Data frames can have the following flags:
// END_STREAM
// PADDED
//
// https://tools.ietf.org/html/rfc7540#section-6.1
type Data struct {
	endStream  bool
	hasPadding bool
	b          []byte // data bytes
}

func (data *Data) Type() FrameType {
	return FrameData
}

func (data *Data) Reset() {
	data.endStream = false
	data.hasPadding = false
	data.b = data.b[:0]
}

// CopyTo copies data to d.
func (data *Data) CopyTo(d *Data) {
	d.hasPadding = data.hasPadding
	d.endStream = data.endStream
	d.b = append(d.b[:0], data.b...)
}

func (data *Data) SetEndStream(value bool) {
	data.endStream = value
}

func (data *Data) EndStream() bool {
	return data.endStream
}

// Data returns the byte slice of the data read/to be sendStream.
func (data *Data) Data() []byte {
	return data.b
}

// SetData resets data byte slice and sets b.
func (data *Data) SetData(b []byte) {
	data.b = append(data.b[:0], b...)
}

// Padding returns true if the data will be/was hasPaddingded.
func (data *Data) Padding() bool {
	return data.hasPadding
}

// SetPadding sets hasPaddingding to the data if true. If false the data won't be hasPaddingded.
func (data *Data) SetPadding(value bool) {
	data.hasPadding = value
}

// Append appends b to data.
func (data *Data) Append(b []byte) {
	data.b = append(data.b, b...)
}

func (data *Data) Len() int {
	return len(data.b)
}

// Write writes b to data.
func (data *Data) Write(b []byte) (int, error) {
	n := len(b)
	data.Append(b)

	return n, nil
}

func (data *Data) Deserialize(fr *FrameHeader) error {
	payload := fr.payload

	if fr.Flags().Has(FlagPadded) {
		var err error
		payload, err = http2utils.CutPadding(payload, fr.Len())
		if err != nil {
			return err
		}
	}

	data.endStream = fr.Flags().Has(FlagEndStream)
	data.b = append(data.b[:0], payload...)

	return nil
}

func (data *Data) Serialize(fr *FrameHeader) {
	// TODO: generate hasPadding and set to the frame payload
	if data.endStream {
		fr.SetFlags(
			fr.Flags().Add(FlagEndStream))
	}

	if data.hasPadding {
		fr.SetFlags(
			fr.Flags().Add(FlagPadded))
		data.b = http2utils.AddPadding(data.b)
	}

	fr.setPayload(data.b)
}
