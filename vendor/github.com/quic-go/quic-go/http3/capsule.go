package http3

import (
	"io"

	"github.com/quic-go/quic-go/quicvarint"
)

// CapsuleType is the type of the capsule.
type CapsuleType uint64

type exactReader struct {
	R *io.LimitedReader
}

func (r *exactReader) Read(b []byte) (int, error) {
	n, err := r.R.Read(b)
	if r.R.N > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

type countingByteReader struct {
	io.ByteReader
	Read int
}

func (r *countingByteReader) ReadByte() (byte, error) {
	b, err := r.ByteReader.ReadByte()
	if err == nil {
		r.Read++
	}
	return b, err
}

// ParseCapsule parses the header of a Capsule.
// It returns an io.LimitedReader that can be used to read the Capsule value.
// The Capsule value must be read entirely (i.e. until the io.EOF) before using r again.
func ParseCapsule(r quicvarint.Reader) (CapsuleType, io.Reader, error) {
	cbr := countingByteReader{ByteReader: r}
	ct, err := quicvarint.Read(&cbr)
	if err != nil {
		// If an io.EOF is returned without consuming any bytes, return it unmodified.
		// Otherwise, return an io.ErrUnexpectedEOF.
		if err == io.EOF && cbr.Read > 0 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	l, err := quicvarint.Read(r)
	if err != nil {
		if err == io.EOF {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	return CapsuleType(ct), &exactReader{R: io.LimitReader(r, int64(l)).(*io.LimitedReader)}, nil
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
