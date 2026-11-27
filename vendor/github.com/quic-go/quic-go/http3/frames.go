package http3

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
)

// FrameType is the frame type of a HTTP/3 frame
type FrameType uint64

type frame any

var errPriorityUpdateForPush = errors.New("http3: PRIORITY_UPDATE frame for push")

// The maximum length of an encoded HTTP/3 frame header is 16:
// The frame has a type and length field, both QUIC varints (maximum 8 bytes in length)
const frameHeaderLen = 16

type countingByteReader struct {
	quicvarint.Reader
	NumRead int
}

func (r *countingByteReader) ReadByte() (byte, error) {
	b, err := r.Reader.ReadByte()
	if err == nil {
		r.NumRead++
	}
	return b, err
}

func (r *countingByteReader) Reset() {
	r.NumRead = 0
}

type frameParser struct {
	r         io.Reader
	streamID  quic.StreamID
	closeConn func(quic.ApplicationErrorCode, string) error

	remaining uint64 // payload bytes of the current frame that weren't read yet
	isData    bool   // whether the current frame is a DATA frame
}

// Read reads the payload of the current frame.
// It returns io.EOF at the end of the payload, and io.ErrUnexpectedEOF if the stream ends before.
func (p *frameParser) Read(b []byte) (int, error) {
	if p.remaining == 0 {
		return 0, io.EOF
	}
	n, err := p.r.Read(b[:min(uint64(len(b)), p.remaining)])
	p.remaining -= uint64(n)
	if errors.Is(err, io.EOF) && p.remaining > 0 {
		return n, p.truncated()
	}
	return n, err
}

// HasMoreData reports whether the payload of the current DATA frame wasn't read completely.
func (p *frameParser) HasMoreData() bool {
	return p.isData && p.remaining > 0
}

// truncated closes the connection: when a stream terminates cleanly inside a frame,
// the receiver must close the connection with H3_FRAME_ERROR (RFC 9114, Section 7.1).
func (p *frameParser) truncated() error {
	p.closeConn(quic.ApplicationErrorCode(ErrCodeFrameError), "")
	return io.ErrUnexpectedEOF
}

func (p *frameParser) ParseNext(qlogger qlogwriter.Recorder) (frame, error) {
	p.isData = false
	r := &countingByteReader{Reader: quicvarint.NewReader(p.r)}
	for {
		t, err := quicvarint.Read(r)
		if err != nil {
			// the stream may only end between two frames
			if errors.Is(err, io.EOF) && r.NumRead > 0 {
				return nil, p.truncated()
			}
			return nil, err
		}
		l, err := quicvarint.Read(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, p.truncated()
			}
			return nil, err
		}
		p.remaining = l

		// We don't support server push, so we skip CANCEL_PUSH, PUSH_PROMISE and MAX_PUSH_ID frames,
		// the same way we skip unknown frame types.
		// In some cases, RFC 9114 requires these frames to be treated as a connection error.
		// We deliberately don't implement these checks, since they'd only catch a misbehaving peer.
		switch t {
		case 0x0: // DATA
			p.isData = true
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw: qlog.RawInfo{
						Length:        int(l) + r.NumRead,
						PayloadLength: int(l),
					},
					Frame: qlog.Frame{Frame: qlog.DataFrame{}},
				})
			}
			return &dataFrame{Length: l}, nil
		case 0x1: // HEADERS
			return &headersFrame{
				Length:    l,
				headerLen: r.NumRead,
			}, nil
		case 0x4: // SETTINGS
			return parseSettingsFrame(p, l, r.NumRead, p.streamID, qlogger)
		case 0x3: // unsupported: CANCEL_PUSH
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead + int(l), PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.CancelPushFrame{}},
				})
			}
		case 0x5: // unsupported: PUSH_PROMISE
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead + int(l), PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.PushPromiseFrame{}},
				})
			}
		case 0x7: // GOAWAY
			return parseGoAwayFrame(p, l, r.NumRead, p.streamID, qlogger)
		case 0xf0700: // PRIORITY_UPDATE for a request stream
			return parsePriorityUpdateFrame(p, l, r.NumRead, p.streamID, qlogger)
		case 0xf0701: // PRIORITY_UPDATE for a push stream
			return nil, errPriorityUpdateForPush
		case 0xd: // unsupported: MAX_PUSH_ID
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead + int(l), PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.MaxPushIDFrame{}},
				})
			}
		case 0x2, 0x6, 0x8, 0x9: // reserved frame types
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead + int(l), PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.ReservedFrame{Type: t}},
				})
			}
			p.closeConn(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
			return nil, fmt.Errorf("http3: reserved frame type: %d", t)
		default:
			// unknown frame types
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead + int(l), PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.UnknownFrame{Type: t}},
				})
			}
		}

		// skip over the payload
		if _, err := io.CopyN(io.Discard, p, int64(l)); err != nil {
			return nil, err
		}
		r.Reset()
	}
}

type dataFrame struct {
	Length uint64
}

func (f *dataFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x0)
	return quicvarint.Append(b, f.Length)
}

type headersFrame struct {
	Length    uint64
	headerLen int // number of bytes read for type and length field
}

func (f *headersFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x1)
	return quicvarint.Append(b, f.Length)
}

const (
	// SETTINGS_MAX_FIELD_SECTION_SIZE
	settingMaxFieldSectionSize = 0x6
	// Extended CONNECT, RFC 9220
	settingExtendedConnect = 0x8
	// HTTP Datagrams, RFC 9297
	settingDatagram = 0x33
)

type settingsFrame struct {
	MaxFieldSectionSize int64 // SETTINGS_MAX_FIELD_SECTION_SIZE, -1 if not set

	Datagram        bool              // HTTP Datagrams, RFC 9297
	ExtendedConnect bool              // Extended CONNECT, RFC 9220
	Other           map[uint64]uint64 // all settings that we don't explicitly recognize
}

const maxSettingsFrameSize = 8 << 10

func parseSettingsFrame(r io.Reader, l uint64, headerLen int, streamID quic.StreamID, qlogger qlogwriter.Recorder) (*settingsFrame, error) {
	if l > maxSettingsFrameSize {
		return nil, fmt.Errorf("unexpected size for SETTINGS frame: %d", l)
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	frame := &settingsFrame{MaxFieldSectionSize: -1}
	b := bytes.NewReader(buf)

	datagram := int64(-1)
	extendedConnect := int64(-1)
	for b.Len() > 0 {
		id, err := quicvarint.Read(b)
		if err != nil {
			return nil, errors.New("SETTINGS frame: inconsistent length")
		}
		val, err := quicvarint.Read(b)
		if err != nil {
			return nil, errors.New("SETTINGS frame: inconsistent length")
		}

		switch id {
		case settingMaxFieldSectionSize:
			if frame.MaxFieldSectionSize >= 0 {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			frame.MaxFieldSectionSize = int64(val)
		case settingExtendedConnect:
			if extendedConnect >= 0 {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			if val != 0 && val != 1 {
				return nil, fmt.Errorf("invalid value for SETTINGS_ENABLE_CONNECT_PROTOCOL: %d", val)
			}
			extendedConnect = int64(val)
			frame.ExtendedConnect = val == 1
		case settingDatagram:
			if datagram >= 0 {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			if val != 0 && val != 1 {
				return nil, fmt.Errorf("invalid value for SETTINGS_H3_DATAGRAM: %d", val)
			}
			datagram = int64(val)
			frame.Datagram = val == 1
		default:
			if _, ok := frame.Other[id]; ok {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			if frame.Other == nil {
				frame.Other = make(map[uint64]uint64)
			}
			frame.Other[id] = val
		}
	}
	if qlogger != nil {
		qlogger.RecordEvent(qlog.FrameParsed{
			StreamID: streamID,
			Raw: qlog.RawInfo{
				Length:        headerLen + int(l),
				PayloadLength: int(l),
			},
			Frame: qlog.Frame{Frame: qlog.SettingsFrame{
				MaxFieldSectionSize: frame.MaxFieldSectionSize,
				Datagram:            datagram,
				ExtendedConnect:     extendedConnect,
				Other:               maps.Clone(frame.Other),
			}},
		})
	}
	return frame, nil
}

func (f *settingsFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x4)
	var l int
	if f.MaxFieldSectionSize >= 0 {
		l += quicvarint.Len(settingMaxFieldSectionSize) + quicvarint.Len(uint64(f.MaxFieldSectionSize))
	}
	for id, val := range f.Other {
		l += quicvarint.Len(id) + quicvarint.Len(val)
	}
	if f.Datagram {
		l += quicvarint.Len(settingDatagram) + quicvarint.Len(1)
	}
	if f.ExtendedConnect {
		l += quicvarint.Len(settingExtendedConnect) + quicvarint.Len(1)
	}
	b = quicvarint.Append(b, uint64(l))
	if f.MaxFieldSectionSize >= 0 {
		b = quicvarint.Append(b, settingMaxFieldSectionSize)
		b = quicvarint.Append(b, uint64(f.MaxFieldSectionSize))
	}
	if f.Datagram {
		b = quicvarint.Append(b, settingDatagram)
		b = quicvarint.Append(b, 1)
	}
	if f.ExtendedConnect {
		b = quicvarint.Append(b, settingExtendedConnect)
		b = quicvarint.Append(b, 1)
	}
	for id, val := range f.Other {
		b = quicvarint.Append(b, id)
		b = quicvarint.Append(b, val)
	}
	return b
}

type goAwayFrame struct {
	StreamID quic.StreamID
}

func parseGoAwayFrame(r io.Reader, l uint64, headerLen int, streamID quic.StreamID, qlogger qlogwriter.Recorder) (*goAwayFrame, error) {
	// the payload is a single varint, which is at most 8 bytes long
	if l > 8 {
		return nil, errors.New("GOAWAY frame: inconsistent length")
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	id, n, err := quicvarint.Parse(buf)
	if err != nil || n != len(buf) {
		return nil, errors.New("GOAWAY frame: inconsistent length")
	}
	frame := &goAwayFrame{StreamID: quic.StreamID(id)}
	if qlogger != nil {
		qlogger.RecordEvent(qlog.FrameParsed{
			StreamID: streamID,
			Raw:      qlog.RawInfo{Length: headerLen + int(l), PayloadLength: int(l)},
			Frame:    qlog.Frame{Frame: qlog.GoAwayFrame{StreamID: frame.StreamID}},
		})
	}
	return frame, nil
}

func (f *goAwayFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x7)
	b = quicvarint.Append(b, uint64(quicvarint.Len(uint64(f.StreamID))))
	return quicvarint.Append(b, uint64(f.StreamID))
}

// PRIORITY_UPDATE, RFC 9218
type priorityUpdateFrame struct {
	ElementID          uint64
	PriorityFieldValue string
}

const maxPriorityUpdateFrameSize = 4 << 10

func parsePriorityUpdateFrame(r io.Reader, l uint64, headerLen int, streamID quic.StreamID, qlogger qlogwriter.Recorder) (*priorityUpdateFrame, error) {
	if l > maxPriorityUpdateFrameSize {
		return nil, fmt.Errorf("unexpected size for PRIORITY_UPDATE frame: %d", l)
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	id, n, err := quicvarint.Parse(buf)
	if err != nil {
		return nil, errors.New("PRIORITY_UPDATE frame: inconsistent length")
	}
	frame := &priorityUpdateFrame{
		ElementID:          id,
		PriorityFieldValue: string(buf[n:]),
	}
	if qlogger != nil {
		qlogger.RecordEvent(qlog.FrameParsed{
			StreamID: streamID,
			Raw:      qlog.RawInfo{Length: headerLen + int(l), PayloadLength: int(l)},
			Frame: qlog.Frame{Frame: qlog.PriorityUpdateFrame{
				StreamID:           quic.StreamID(frame.ElementID),
				PriorityFieldValue: frame.PriorityFieldValue,
			}},
		})
	}
	return frame, nil
}
