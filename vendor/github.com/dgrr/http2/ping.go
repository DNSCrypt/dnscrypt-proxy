package http2

import (
	"encoding/binary"
	"time"
)

const FramePing FrameType = 0x6

var _ Frame = &Ping{}

// Ping https://tools.ietf.org/html/rfc7540#section-6.7
type Ping struct {
	ack  bool
	data [8]byte
}

func (p *Ping) IsAck() bool {
	return p.ack
}

func (p *Ping) SetAck(ack bool) {
	p.ack = ack
}

func (p *Ping) Type() FrameType {
	return FramePing
}

func (p *Ping) Reset() {
	p.ack = false
}

func (p *Ping) CopyTo(other *Ping) {
	p.ack = other.ack
}

func (p *Ping) Write(b []byte) (n int, err error) {
	copy(p.data[:], b)
	return
}

func (p *Ping) SetData(b []byte) {
	copy(p.data[:], b)
}

func (p *Ping) SetCurrentTime() {
	ts := time.Now().UnixNano()
	binary.BigEndian.PutUint64(p.data[:], uint64(ts))
}

func (p *Ping) DataAsTime() time.Time {
	return time.Unix(
		0, int64(binary.BigEndian.Uint64(p.data[:])),
	)
}

func (p *Ping) Deserialize(frh *FrameHeader) error {
	p.ack = frh.Flags().Has(FlagAck)
	if len(frh.payload) != 8 {
		return NewGoAwayError(FrameSizeError, "invalid ping payload")
	}
	p.SetData(frh.payload)
	return nil
}

func (p *Ping) Data() []byte {
	return p.data[:]
}

func (p *Ping) Serialize(fr *FrameHeader) {
	if p.ack {
		fr.SetFlags(fr.Flags().Add(FlagAck))
	}

	fr.setPayload(p.data[:])
}
