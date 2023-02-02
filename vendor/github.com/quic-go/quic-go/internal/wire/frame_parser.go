package wire

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
)

type frameParser struct {
	r bytes.Reader // cached bytes.Reader, so we don't have to repeatedly allocate them

	ackDelayExponent uint8

	supportsDatagrams bool
}

var _ FrameParser = &frameParser{}

// NewFrameParser creates a new frame parser.
func NewFrameParser(supportsDatagrams bool) *frameParser {
	return &frameParser{
		r:                 *bytes.NewReader(nil),
		supportsDatagrams: supportsDatagrams,
	}
}

// ParseNext parses the next frame.
// It skips PADDING frames.
func (p *frameParser) ParseNext(data []byte, encLevel protocol.EncryptionLevel, v protocol.VersionNumber) (int, Frame, error) {
	startLen := len(data)
	p.r.Reset(data)
	frame, err := p.parseNext(&p.r, encLevel, v)
	n := startLen - p.r.Len()
	p.r.Reset(nil)
	return n, frame, err
}

func (p *frameParser) parseNext(r *bytes.Reader, encLevel protocol.EncryptionLevel, v protocol.VersionNumber) (Frame, error) {
	for r.Len() != 0 {
		typeByte, _ := p.r.ReadByte()
		if typeByte == 0x0 { // PADDING frame
			continue
		}
		r.UnreadByte()

		f, err := p.parseFrame(r, typeByte, encLevel, v)
		if err != nil {
			return nil, &qerr.TransportError{
				FrameType:    uint64(typeByte),
				ErrorCode:    qerr.FrameEncodingError,
				ErrorMessage: err.Error(),
			}
		}
		return f, nil
	}
	return nil, nil
}

func (p *frameParser) parseFrame(r *bytes.Reader, typeByte byte, encLevel protocol.EncryptionLevel, v protocol.VersionNumber) (Frame, error) {
	var frame Frame
	var err error
	if typeByte&0xf8 == 0x8 {
		frame, err = parseStreamFrame(r, v)
	} else {
		switch typeByte {
		case 0x1:
			frame, err = parsePingFrame(r, v)
		case 0x2, 0x3:
			ackDelayExponent := p.ackDelayExponent
			if encLevel != protocol.Encryption1RTT {
				ackDelayExponent = protocol.DefaultAckDelayExponent
			}
			frame, err = parseAckFrame(r, ackDelayExponent, v)
		case 0x4:
			frame, err = parseResetStreamFrame(r, v)
		case 0x5:
			frame, err = parseStopSendingFrame(r, v)
		case 0x6:
			frame, err = parseCryptoFrame(r, v)
		case 0x7:
			frame, err = parseNewTokenFrame(r, v)
		case 0x10:
			frame, err = parseMaxDataFrame(r, v)
		case 0x11:
			frame, err = parseMaxStreamDataFrame(r, v)
		case 0x12, 0x13:
			frame, err = parseMaxStreamsFrame(r, v)
		case 0x14:
			frame, err = parseDataBlockedFrame(r, v)
		case 0x15:
			frame, err = parseStreamDataBlockedFrame(r, v)
		case 0x16, 0x17:
			frame, err = parseStreamsBlockedFrame(r, v)
		case 0x18:
			frame, err = parseNewConnectionIDFrame(r, v)
		case 0x19:
			frame, err = parseRetireConnectionIDFrame(r, v)
		case 0x1a:
			frame, err = parsePathChallengeFrame(r, v)
		case 0x1b:
			frame, err = parsePathResponseFrame(r, v)
		case 0x1c, 0x1d:
			frame, err = parseConnectionCloseFrame(r, v)
		case 0x1e:
			frame, err = parseHandshakeDoneFrame(r, v)
		case 0x30, 0x31:
			if p.supportsDatagrams {
				frame, err = parseDatagramFrame(r, v)
				break
			}
			fallthrough
		default:
			err = errors.New("unknown frame type")
		}
	}
	if err != nil {
		return nil, err
	}
	if !p.isAllowedAtEncLevel(frame, encLevel) {
		return nil, fmt.Errorf("%s not allowed at encryption level %s", reflect.TypeOf(frame).Elem().Name(), encLevel)
	}
	return frame, nil
}

func (p *frameParser) isAllowedAtEncLevel(f Frame, encLevel protocol.EncryptionLevel) bool {
	switch encLevel {
	case protocol.EncryptionInitial, protocol.EncryptionHandshake:
		switch f.(type) {
		case *CryptoFrame, *AckFrame, *ConnectionCloseFrame, *PingFrame:
			return true
		default:
			return false
		}
	case protocol.Encryption0RTT:
		switch f.(type) {
		case *CryptoFrame, *AckFrame, *ConnectionCloseFrame, *NewTokenFrame, *PathResponseFrame, *RetireConnectionIDFrame:
			return false
		default:
			return true
		}
	case protocol.Encryption1RTT:
		return true
	default:
		panic("unknown encryption level")
	}
}

func (p *frameParser) SetAckDelayExponent(exp uint8) {
	p.ackDelayExponent = exp
}
