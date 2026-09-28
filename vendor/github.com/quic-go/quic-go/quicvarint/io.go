package quicvarint

import (
	"bytes"
	"io"
)

// Reader implements both the io.ByteReader and io.Reader interfaces.
type Reader interface {
	io.ByteReader
	io.Reader
}

var _ Reader = &bytes.Reader{}

// A Peeker can peek bytes without consuming them.
type Peeker interface {
	// Peek must return a non-nil error if it copies fewer than len(b) bytes
	Peek(b []byte) (int, error)
}

// Peek reads a number in the QUIC varint format without consuming bytes.
// If an error is returned, the returned number is invalid.
func Peek(p Peeker) (uint64, error) {
	var b [8]byte

	// first peek 1 byte to determine the varint length
	if n, err := p.Peek(b[:1]); n < 1 && err != nil {
		return 0, err
	}

	l := 1 << (b[0] >> 6) // 1, 2, 4, or 8 bytes
	if l == 1 {
		return uint64(b[0] & 0b00111111), nil
	}
	if n, err := p.Peek(b[:l]); n < l && err != nil {
		return 0, err
	}
	val, _, err := Parse(b[:l])
	return val, err
}

type byteReader struct {
	io.Reader
}

var _ Reader = &byteReader{}

// NewReader returns a Reader for r.
// If r already implements both io.ByteReader and io.Reader, NewReader returns r.
// Otherwise, r is wrapped to add the missing interfaces.
func NewReader(r io.Reader) Reader {
	if r, ok := r.(Reader); ok {
		return r
	}
	return &byteReader{r}
}

func (r *byteReader) ReadByte() (byte, error) {
	var b [1]byte
	var n int
	var err error
	// don't turn an empty read into a zero byte
	for n == 0 && err == nil {
		n, err = r.Read(b[:])
	}

	// a byte returned with an error (incl. EOF) is still valid
	if n == 1 {
		err = nil
	}
	return b[0], err
}

// Writer implements both the io.ByteWriter and io.Writer interfaces.
type Writer interface {
	io.ByteWriter
	io.Writer
}

var _ Writer = &bytes.Buffer{}

type byteWriter struct {
	io.Writer
}

var _ Writer = &byteWriter{}

// NewWriter returns a Writer for w.
// If w already implements both io.ByteWriter and io.Writer, NewWriter returns w.
// Otherwise, w is wrapped to add the missing interfaces.
func NewWriter(w io.Writer) Writer {
	if w, ok := w.(Writer); ok {
		return w
	}
	return &byteWriter{w}
}

func (w *byteWriter) WriteByte(c byte) error {
	_, err := w.Write([]byte{c})
	return err
}
