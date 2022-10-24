package http3

import (
	"bufio"
	"bytes"
	"net/http"
	"strconv"
	"strings"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"
)

type responseWriter struct {
	conn        quic.Connection
	bufferedStr *bufio.Writer
	buf         []byte

	header        http.Header
	status        int // status code passed to WriteHeader
	headerWritten bool

	logger utils.Logger
}

var (
	_ http.ResponseWriter = &responseWriter{}
	_ http.Flusher        = &responseWriter{}
	_ Hijacker            = &responseWriter{}
)

func newResponseWriter(str quic.Stream, conn quic.Connection, logger utils.Logger) *responseWriter {
	return &responseWriter{
		header:      http.Header{},
		buf:         make([]byte, 16),
		conn:        conn,
		bufferedStr: bufio.NewWriter(str),
		logger:      logger,
	}
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) WriteHeader(status int) {
	if w.headerWritten {
		return
	}

	if status < 100 || status >= 200 {
		w.headerWritten = true
	}
	w.status = status

	var headers bytes.Buffer
	enc := qpack.NewEncoder(&headers)
	enc.WriteField(qpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})

	for k, v := range w.header {
		for index := range v {
			enc.WriteField(qpack.HeaderField{Name: strings.ToLower(k), Value: v[index]})
		}
	}

	w.buf = w.buf[:0]
	w.buf = (&headersFrame{Length: uint64(headers.Len())}).Append(w.buf)
	w.logger.Infof("Responding with %d", status)
	if _, err := w.bufferedStr.Write(w.buf); err != nil {
		w.logger.Errorf("could not write headers frame: %s", err.Error())
	}
	if _, err := w.bufferedStr.Write(headers.Bytes()); err != nil {
		w.logger.Errorf("could not write header frame payload: %s", err.Error())
	}
	if !w.headerWritten {
		w.Flush()
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(200)
	}
	if !bodyAllowedForStatus(w.status) {
		return 0, http.ErrBodyNotAllowed
	}
	df := &dataFrame{Length: uint64(len(p))}
	w.buf = w.buf[:0]
	w.buf = df.Append(w.buf)
	if _, err := w.bufferedStr.Write(w.buf); err != nil {
		return 0, err
	}
	return w.bufferedStr.Write(p)
}

func (w *responseWriter) Flush() {
	if err := w.bufferedStr.Flush(); err != nil {
		w.logger.Errorf("could not flush to stream: %s", err.Error())
	}
}

func (w *responseWriter) StreamCreator() StreamCreator {
	return w.conn
}

// copied from http2/http2.go
// bodyAllowedForStatus reports whether a given response status code
// permits a body. See RFC 2616, section 4.4.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}
