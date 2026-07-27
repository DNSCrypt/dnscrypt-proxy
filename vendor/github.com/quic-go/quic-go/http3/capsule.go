package http3

import (
	"errors"
	"io"

	"github.com/quic-go/quic-go/quicvarint"
)

// CapsuleType is the type of the capsule
type CapsuleType uint64

// CapsuleProtocolHeader is the header value used to advertise support for the capsule protocol
const CapsuleProtocolHeader = "Capsule-Protocol"

type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// CapsuleParser parses a sequence of capsules.
// A capsule's contents must be fully consumed or discarded before calling Next again.
type CapsuleParser struct {
	noCopy noCopy

	r quicvarint.Reader

	generation uint64
	remaining  uint64
}

// NewCapsuleParser creates a parser that reads capsules from r.
func NewCapsuleParser(r io.Reader) *CapsuleParser {
	return &CapsuleParser{r: quicvarint.NewReader(r)}
}

var (
	errReaderInvalid      = errors.New("http3: capsule reader is no longer valid")
	errCapsuleNotConsumed = errors.New("http3: previous capsule was not fully consumed")
)

// Next returns the type and contents of the next capsule.
// The previous capsule's contents must be fully consumed or discarded before calling Next.
func (p *CapsuleParser) Next() (CapsuleType, CapsuleReader, error) {
	if p.remaining > 0 {
		return 0, CapsuleReader{}, errCapsuleNotConsumed
	}

	r := &countingByteReader{Reader: p.r}
	ct, err := quicvarint.Read(r)
	if err != nil {
		// If an io.EOF is returned without consuming any bytes, return it unmodified.
		// Otherwise, return an io.ErrUnexpectedEOF.
		if err == io.EOF && r.NumRead > 0 {
			return 0, CapsuleReader{}, io.ErrUnexpectedEOF
		}
		return 0, CapsuleReader{}, err
	}
	r.Reset()
	l, err := quicvarint.Read(r)
	if err != nil {
		if err == io.EOF {
			return 0, CapsuleReader{}, io.ErrUnexpectedEOF
		}
		return 0, CapsuleReader{}, err
	}

	p.generation++
	p.remaining = l
	return CapsuleType(ct), CapsuleReader{parser: p, generation: p.generation}, nil
}

// CapsuleReader reads the contents of a capsule.
// It becomes invalid when the parser advances to the next capsule.
type CapsuleReader struct {
	parser     *CapsuleParser
	generation uint64
}

var _ quicvarint.Reader = CapsuleReader{}

// valid reports whether the reader still refers to the parser's current capsule.
func (r CapsuleReader) valid() bool {
	return r.parser != nil && r.generation == r.parser.generation
}

// Read reads from the capsule contents.
func (r CapsuleReader) Read(b []byte) (int, error) {
	if !r.valid() {
		return 0, errReaderInvalid
	}
	if r.parser.remaining == 0 {
		return 0, io.EOF
	}
	if uint64(len(b)) > r.parser.remaining {
		b = b[:r.parser.remaining]
	}
	n, err := r.parser.r.Read(b)
	r.parser.remaining -= uint64(n)
	if err == io.EOF && r.parser.remaining > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

// ReadByte reads one byte from the capsule contents.
func (r CapsuleReader) ReadByte() (byte, error) {
	if !r.valid() {
		return 0, errReaderInvalid
	}
	if r.parser.remaining == 0 {
		return 0, io.EOF
	}
	b, err := r.parser.r.ReadByte()
	if err == io.EOF {
		return 0, io.ErrUnexpectedEOF
	}
	if err == nil {
		r.parser.remaining--
	}
	return b, err
}

// Remaining returns the number of bytes remaining in the capsule.
func (r CapsuleReader) Remaining() int64 {
	if !r.valid() {
		return 0
	}
	return int64(r.parser.remaining)
}

// Discard consumes the remaining capsule contents.
func (r CapsuleReader) Discard() error {
	_, err := io.Copy(io.Discard, r)
	return err
}

// WriteCapsule writes a capsule
func WriteCapsule(w quicvarint.Writer, ct CapsuleType, value []byte) error {
	b := make([]byte, 0, 16)
	b = quicvarint.Append(b, uint64(ct))
	b = quicvarint.Append(b, uint64(len(value)))
	if _, err := w.Write(b); err != nil {
		return err
	}
	_, err := w.Write(value)
	return err
}
