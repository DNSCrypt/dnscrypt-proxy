package http3

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/quic-go/qpack"
)

type responseWriter struct {
	conn        quic.Connection
	str         quic.Stream
	bufferedStr *bufio.Writer
	buf         []byte

	header        http.Header
	status        int // status code passed to WriteHeader
	headerWritten bool
	contentLen    int64 // if handler set valid Content-Length header
	numWritten    int64 // bytes written

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
		str:         str,
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

	// http status must be 3 digits
	if status < 100 || status > 999 {
		panic(fmt.Sprintf("invalid WriteHeader code %v", status))
	}

	if status >= 200 {
		w.headerWritten = true
		// Add Date header.
		// This is what the standard library does.
		// Can be disabled by setting the Date header to nil.
		if _, ok := w.header["Date"]; !ok {
			w.header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		}
		// Content-Length checking
		// use ParseUint instead of ParseInt, as negative values are invalid
		if clen := w.header.Get("Content-Length"); clen != "" {
			if cl, err := strconv.ParseUint(clen, 10, 63); err == nil {
				w.contentLen = int64(cl)
			} else {
				// emit a warning for malformed Content-Length and remove it
				w.logger.Errorf("Malformed Content-Length %s", clen)
				w.header.Del("Content-Length")
			}
		}
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
	bodyAllowed := bodyAllowedForStatus(w.status)
	if !w.headerWritten {
		// If body is not allowed, we don't need to (and we can't) sniff the content type.
		if bodyAllowed {
			// If no content type, apply sniffing algorithm to body.
			// We can't use `w.header.Get` here since if the Content-Type was set to nil, we shoundn't do sniffing.
			_, haveType := w.header["Content-Type"]

			// If the Transfer-Encoding or Content-Encoding was set and is non-blank,
			// we shouldn't sniff the body.
			hasTE := w.header.Get("Transfer-Encoding") != ""
			hasCE := w.header.Get("Content-Encoding") != ""
			if !hasCE && !haveType && !hasTE && len(p) > 0 {
				w.header.Set("Content-Type", http.DetectContentType(p))
			}
		}
		w.WriteHeader(http.StatusOK)
		bodyAllowed = true
	}
	if !bodyAllowed {
		return 0, http.ErrBodyNotAllowed
	}

	w.numWritten += int64(len(p))
	if w.contentLen != 0 && w.numWritten > w.contentLen {
		return 0, http.ErrContentLength
	}

	df := &dataFrame{Length: uint64(len(p))}
	w.buf = w.buf[:0]
	w.buf = df.Append(w.buf)
	if _, err := w.bufferedStr.Write(w.buf); err != nil {
		return 0, err
	}
	return w.bufferedStr.Write(p)
}

func (w *responseWriter) FlushError() error {
	return w.bufferedStr.Flush()
}

func (w *responseWriter) Flush() {
	if err := w.FlushError(); err != nil {
		w.logger.Errorf("could not flush to stream: %s", err.Error())
	}
}

func (w *responseWriter) StreamCreator() StreamCreator {
	return w.conn
}

func (w *responseWriter) SetReadDeadline(deadline time.Time) error {
	return w.str.SetReadDeadline(deadline)
}

func (w *responseWriter) SetWriteDeadline(deadline time.Time) error {
	return w.str.SetWriteDeadline(deadline)
}

// copied from http2/http2.go
// bodyAllowedForStatus reports whether a given response status code
// permits a body. See RFC 2616, section 4.4.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == http.StatusNoContent:
		return false
	case status == http.StatusNotModified:
		return false
	}
	return true
}
