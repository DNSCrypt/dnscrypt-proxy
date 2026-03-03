package http2

import (
	"bytes"
	"io"
)

// Byteorder must be big endian
// Values are unsigned unless otherwise indicated

var (
	// http://httpwg.org/specs/rfc7540.html#ConnectionHeader
	http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	prefaceLen   = len(http2Preface)
)

// ReadPreface reads the connection initialisation preface.
func ReadPreface(br io.Reader) bool {
	b := make([]byte, prefaceLen)

	n, err := br.Read(b[:prefaceLen])
	if err == nil && n == prefaceLen {
		if bytes.Equal(b, http2Preface) {
			return true
		}
	}

	return false
}

// WritePreface writes HTTP/2 preface to the wr.
func WritePreface(wr io.Writer) error {
	_, err := wr.Write(http2Preface)
	return err
}
