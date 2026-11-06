package qlog

import (
	"encoding/hex"
	"unicode/utf8"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

// Frame represents an HTTP/3 frame.
type Frame struct {
	Frame any
}

func (f Frame) encode(enc *jsontext.Encoder, raw RawInfo) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if raw.HasValues() {
		h.WriteToken(jsontext.String("raw"))
		if err := raw.encode(enc); err != nil {
			return err
		}
	}
	switch frame := f.Frame.(type) {
	case DataFrame:
		frame.encode(&h)
	case HeadersFrame:
		frame.encode(&h)
	case GoAwayFrame:
		frame.encode(&h)
	case SettingsFrame:
		frame.encode(&h)
	case PushPromiseFrame:
		frame.encode(&h)
	case CancelPushFrame:
		frame.encode(&h)
	case MaxPushIDFrame:
		frame.encode(&h)
	case PriorityUpdateFrame:
		frame.encode(&h)
	case ReservedFrame:
		frame.encode(&h)
	case UnknownFrame:
		frame.encode(&h)
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// A DataFrame is a DATA frame
type DataFrame struct{}

func (f *DataFrame) encode(h *encoderHelper) {
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("data"))
}

type HeaderField struct {
	Name  string
	Value string
	// InvalidName and InvalidValue report character validation failures in HTTP/3.
	InvalidName  bool
	InvalidValue bool
}

// A HeadersFrame is a HEADERS frame
type HeadersFrame struct {
	HeaderFields []HeaderField
}

func (f *HeadersFrame) encode(h *encoderHelper) {
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("headers"))
	h.WriteToken(jsontext.String("headers"))
	h.WriteToken(jsontext.BeginArray)
	for _, f := range f.HeaderFields {
		h.WriteToken(jsontext.BeginObject)
		if !f.InvalidName && utf8.ValidString(f.Name) {
			h.WriteToken(jsontext.String("name"))
			h.WriteToken(jsontext.String(f.Name))
		} else {
			h.WriteToken(jsontext.String("name_bytes"))
			h.WriteToken(jsontext.String(hex.EncodeToString([]byte(f.Name))))
		}
		// HTTP permits non-UTF-8 bytes in field values.
		if !f.InvalidValue && utf8.ValidString(f.Value) {
			h.WriteToken(jsontext.String("value"))
			h.WriteToken(jsontext.String(f.Value))
		} else {
			h.WriteToken(jsontext.String("value_bytes"))
			h.WriteToken(jsontext.String(hex.EncodeToString([]byte(f.Value))))
		}
		h.WriteToken(jsontext.EndObject)
	}
	h.WriteToken(jsontext.EndArray)
}

// A GoAwayFrame is a GOAWAY frame
type GoAwayFrame struct {
	StreamID quic.StreamID
}

func (f *GoAwayFrame) encode(h *encoderHelper) {
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("goaway"))
	h.WriteToken(jsontext.String("id"))
	h.WriteToken(jsontext.Uint(uint64(f.StreamID)))
}

type SettingsFrame struct {
	MaxFieldSectionSize int64 // -1 if not set
	Datagram            int64 // -1 if not set
	ExtendedConnect     int64 // -1 if not set
	Other               map[uint64]uint64
}

func (f *SettingsFrame) encode(h *encoderHelper) {
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("settings"))
	h.WriteToken(jsontext.String("settings"))
	h.WriteToken(jsontext.BeginArray)
	if f.MaxFieldSectionSize >= 0 {
		h.WriteToken(jsontext.BeginObject)
		h.WriteToken(jsontext.String("name"))
		h.WriteToken(jsontext.String("settings_max_field_section_size"))
		h.WriteToken(jsontext.String("value"))
		h.WriteToken(jsontext.Uint(uint64(f.MaxFieldSectionSize)))
		h.WriteToken(jsontext.EndObject)
	}
	if f.Datagram >= 0 {
		h.WriteToken(jsontext.BeginObject)
		h.WriteToken(jsontext.String("name"))
		h.WriteToken(jsontext.String("settings_h3_datagram"))
		h.WriteToken(jsontext.String("value"))
		h.WriteToken(jsontext.Uint(uint64(f.Datagram)))
		h.WriteToken(jsontext.EndObject)
	}
	if f.ExtendedConnect >= 0 {
		h.WriteToken(jsontext.BeginObject)
		h.WriteToken(jsontext.String("name"))
		h.WriteToken(jsontext.String("settings_enable_connect_protocol"))
		h.WriteToken(jsontext.String("value"))
		h.WriteToken(jsontext.Uint(uint64(f.ExtendedConnect)))
		h.WriteToken(jsontext.EndObject)
	}
	if len(f.Other) > 0 {
		for k, v := range f.Other {
			h.WriteToken(jsontext.BeginObject)
			h.WriteToken(jsontext.String("name"))
			h.WriteToken(jsontext.String("unknown"))
			h.WriteToken(jsontext.String("name_bytes"))
			h.WriteToken(jsontext.Uint(k))
			h.WriteToken(jsontext.String("value"))
			h.WriteToken(jsontext.Uint(v))
			h.WriteToken(jsontext.EndObject)
		}
	}
	h.WriteToken(jsontext.EndArray)
}

// A PushPromiseFrame is a PUSH_PROMISE frame
type PushPromiseFrame struct{}

func (f *PushPromiseFrame) encode(h *encoderHelper) {
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("push_promise"))
}

// A CancelPushFrame is a CANCEL_PUSH frame
type CancelPushFrame struct{}

func (f *CancelPushFrame) encode(h *encoderHelper) {
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("cancel_push"))
}

// A MaxPushIDFrame is a MAX_PUSH_ID frame
type MaxPushIDFrame struct{}

func (f *MaxPushIDFrame) encode(h *encoderHelper) {
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("max_push_id"))
}

// A PriorityUpdateFrame is a PRIORITY_UPDATE frame for a request stream.
type PriorityUpdateFrame struct {
	StreamID           quic.StreamID
	PriorityFieldValue string
}

func (f *PriorityUpdateFrame) encode(h *encoderHelper) {
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("priority_update"))
	h.WriteToken(jsontext.String("stream_id"))
	h.WriteToken(jsontext.Uint(uint64(f.StreamID)))
	h.WriteToken(jsontext.String("priority_field_value"))
	h.WriteToken(jsontext.String(f.PriorityFieldValue))
}

// A ReservedFrame is one of the reserved frame types
type ReservedFrame struct {
	Type uint64
}

func (f *ReservedFrame) encode(h *encoderHelper) {
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("reserved"))
	h.WriteToken(jsontext.String("frame_type_bytes"))
	h.WriteToken(jsontext.Uint(f.Type))
}

// An UnknownFrame is an unknown frame type
type UnknownFrame struct {
	Type uint64
}

func (f *UnknownFrame) encode(h *encoderHelper) {
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("unknown"))
	h.WriteToken(jsontext.String("frame_type_bytes"))
	h.WriteToken(jsontext.Uint(f.Type))
}
