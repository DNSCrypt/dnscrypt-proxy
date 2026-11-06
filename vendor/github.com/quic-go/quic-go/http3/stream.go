package http3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/quic-go/qpack"
)

type datagramStream interface {
	io.ReadWriteCloser
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	StreamID() quic.StreamID
	Context() context.Context
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SetPriority(urgency int8, incremental bool)
	TryWriteAll([]byte) error
	SendDatagram(b []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)

	QUICStream() *quic.Stream
}

// A Stream is an HTTP/3 stream.
//
// When writing to and reading from the stream, data is framed in HTTP/3 DATA frames.
type Stream struct {
	datagramStream
	conn        *rawConn
	frameParser *frameParser

	bytesRemainingInFrame uint64

	// the DATA frame being written: the unwritten part of its header, and the payload bytes still to write
	frameHeader           []byte
	bytesUnwrittenInFrame uint64

	qlogger qlogwriter.Recorder

	parseTrailer  func(io.Reader, *headersFrame) error
	parsedTrailer bool

	missingHeader bool // set if the stream was taken over before the response header was sent
}

func newStream(
	str datagramStream,
	conn *rawConn,
	trace *httptrace.ClientTrace,
	parseTrailer func(io.Reader, *headersFrame) error,
	qlogger qlogwriter.Recorder,
) *Stream {
	return &Stream{
		datagramStream: str,
		conn:           conn,
		qlogger:        qlogger,
		parseTrailer:   parseTrailer,
		frameParser: &frameParser{
			r:         &tracingReader{Reader: str, trace: trace},
			streamID:  str.StreamID(),
			closeConn: conn.CloseWithError,
		},
	}
}

func (s *Stream) Read(b []byte) (int, error) {
	s.addQlogProducer()
	defer s.removeQlogProducer()

	if s.bytesRemainingInFrame == 0 {
	parseLoop:
		for {
			frame, err := s.frameParser.ParseNext(s.qlogger)
			if err != nil {
				if errors.Is(err, errPriorityUpdateForPush) {
					s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
				}
				return 0, maybeReplaceError(err)
			}
			switch f := frame.(type) {
			case *dataFrame:
				if s.parsedTrailer {
					return 0, errors.New("DATA frame received after trailers")
				}
				s.bytesRemainingInFrame = f.Length
				break parseLoop
			case *headersFrame:
				if s.parsedTrailer {
					maybeQlogInvalidHeadersFrame(s.qlogger, s.StreamID(), f.Length)
					return 0, errors.New("additional HEADERS frame received after trailers")
				}
				s.parsedTrailer = true
				return 0, maybeReplaceError(s.parseTrailer(s.datagramStream, f))
			default:
				s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
				// parseNextFrame skips over unknown frame types
				// Therefore, this condition is only entered when we parsed another known frame type.
				return 0, fmt.Errorf("peer sent an unexpected frame: %T", f)
			}
		}
	}

	var n int
	var err error
	if s.bytesRemainingInFrame < uint64(len(b)) {
		n, err = s.datagramStream.Read(b[:s.bytesRemainingInFrame])
	} else {
		n, err = s.datagramStream.Read(b)
	}
	s.bytesRemainingInFrame -= uint64(n)
	return n, maybeReplaceError(err)
}

func (s *Stream) hasMoreData() bool {
	return s.bytesRemainingInFrame > 0
}

// hasUnfinishedFrame reports whether a Write failed partway through a DATA frame.
func (s *Stream) hasUnfinishedFrame() bool {
	return s.bytesUnwrittenInFrame > 0
}

// Write writes data to the stream.
//
// It can only be used after the response header has been sent.
func (s *Stream) Write(b []byte) (int, error) {
	if !s.addQlogProducer() {
		return s.writeUnframed(nil)
	}
	defer s.removeQlogProducer()

	if s.missingHeader {
		return 0, errors.New("http3: invalid use of Stream.Write before sending the response header")
	}
	// complete the DATA frame left unfinished by a Write that failed partway (e.g. when the write deadline expired)
	var n int
	if s.bytesUnwrittenInFrame > 0 {
		var err error
		if n, err = s.continueDataFrame(b); err != nil {
			return n, err
		}
	}
	if n == len(b) {
		return n, nil
	}

	l := len(b) - n
	s.frameHeader = (&dataFrame{Length: uint64(l)}).Append(s.frameHeader[:0])
	s.bytesUnwrittenInFrame = uint64(l)
	if s.qlogger != nil {
		s.qlogger.RecordEvent(qlog.FrameCreated{
			StreamID: s.StreamID(),
			Raw: qlog.RawInfo{
				Length:        len(s.frameHeader) + l,
				PayloadLength: l,
			},
			Frame: qlog.Frame{Frame: qlog.DataFrame{}},
		})
	}
	m, err := s.continueDataFrame(b[n:])
	return n + m, err
}

// continueDataFrame writes the unwritten part of the DATA frame header,
// followed by as much of b as fits into the frame's payload.
func (s *Stream) continueDataFrame(b []byte) (int, error) {
	if len(s.frameHeader) > 0 {
		n, err := s.writeUnframed(s.frameHeader)
		if err != nil {
			s.frameHeader = s.frameHeader[n:]
			return 0, err
		}
		s.frameHeader = s.frameHeader[:0]
	}
	n, err := s.writeUnframed(b[:min(uint64(len(b)), s.bytesUnwrittenInFrame)])
	s.bytesUnwrittenInFrame -= uint64(n)
	return n, err
}

// TryWriteAll writes b in a DATA frame if the entire frame can be queued immediately.
// It returns [quic.ErrWouldBlock] without queueing anything otherwise.
// It can only be used after the response header has been sent.
func (s *Stream) TryWriteAll(b []byte) error {
	s.addQlogProducer()
	defer s.removeQlogProducer()

	if s.missingHeader {
		return errors.New("http3: invalid use of Stream.TryWriteAll before sending the response header")
	}
	// complete the DATA frame left unfinished by a failed Write, then start a new one
	completed := min(uint64(len(b)), s.bytesUnwrittenInFrame)
	data := make([]byte, 0, len(s.frameHeader)+frameHeaderLen+len(b))
	data = append(data, s.frameHeader...)
	data = append(data, b[:completed]...)
	frameStart := len(data)
	rest := b[completed:]
	if len(rest) > 0 {
		data = (&dataFrame{Length: uint64(len(rest))}).Append(data)
		data = append(data, rest...)
	}
	if err := s.datagramStream.TryWriteAll(data); err != nil {
		return maybeReplaceError(err)
	}
	s.frameHeader = s.frameHeader[:0]
	s.bytesUnwrittenInFrame -= completed
	if s.qlogger != nil && len(rest) > 0 {
		s.qlogger.RecordEvent(qlog.FrameCreated{
			StreamID: s.StreamID(),
			Raw: qlog.RawInfo{
				Length:        len(data) - frameStart,
				PayloadLength: len(rest),
			},
			Frame: qlog.Frame{Frame: qlog.DataFrame{}},
		})
	}
	return nil
}

func (s *Stream) writeUnframed(b []byte) (int, error) {
	n, err := s.datagramStream.Write(b)
	return n, maybeReplaceError(err)
}

// addQlogProducer registers a call that may produce qlog events.
// The application can make these calls at any time, also after the connection was closed.
// It returns false once the qlogger was closed. All streams were shut down by then,
// so a call that logs a frame before writing it must not create the frame.
func (s *Stream) addQlogProducer() bool {
	if s.qlogger == nil {
		return true
	}
	return s.conn.AddQlogProducer()
}

func (s *Stream) removeQlogProducer() {
	if s.qlogger != nil {
		s.conn.RemoveQlogProducer()
	}
}

func (s *Stream) StreamID() quic.StreamID {
	return s.datagramStream.StreamID()
}

// QlogTrace returns the qlog trace of the underlying QUIC connection.
// It is nil if qlog is not enabled.
func (s *Stream) QlogTrace() qlogwriter.Trace {
	return s.conn.conn.QlogTrace()
}

func (s *Stream) SendDatagram(b []byte) error {
	s.addQlogProducer()
	defer s.removeQlogProducer()

	// TODO: reject if datagrams are not negotiated (yet)
	return maybeReplaceError(s.datagramStream.SendDatagram(b))
}

func (s *Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	// TODO: reject if datagrams are not negotiated (yet)
	b, err := s.datagramStream.ReceiveDatagram(ctx)
	return b, maybeReplaceError(err)
}

// A RequestStream is a low-level abstraction representing an HTTP/3 request stream.
// It decouples sending of the HTTP request from reading the HTTP response, allowing
// the application to optimistically use the stream (and, for example, send datagrams)
// before receiving the response.
//
// This is only needed for advanced use case, e.g. WebTransport and the various
// MASQUE proxying protocols.
// Stream and application errors are returned as *[Error], possibly wrapped.
type RequestStream struct {
	str *Stream

	responseBody io.ReadCloser // set by ReadResponse

	decoder            *qpack.Decoder
	requestWriter      *requestWriter
	maxHeaderBytes     int
	reqDone            chan<- struct{}
	disableCompression bool
	response           *http.Response

	sentRequest   bool
	requestedGzip bool
	isConnect     bool
	isHead        bool
}

func newRequestStream(
	str *Stream,
	requestWriter *requestWriter,
	reqDone chan<- struct{},
	decoder *qpack.Decoder,
	disableCompression bool,
	maxHeaderBytes int,
	rsp *http.Response,
) *RequestStream {
	return &RequestStream{
		str:                str,
		requestWriter:      requestWriter,
		reqDone:            reqDone,
		decoder:            decoder,
		disableCompression: disableCompression,
		maxHeaderBytes:     maxHeaderBytes,
		response:           rsp,
	}
}

// Read reads data from the underlying stream.
//
// It can only be used after the request has been sent using [RequestStream.SendRequestHeader]
// and [RequestStream.ReadResponse] has returned the response.
func (s *RequestStream) Read(b []byte) (int, error) {
	if s.responseBody == nil {
		return 0, errors.New("http3: invalid use of RequestStream.Read before ReadResponse")
	}
	return s.responseBody.Read(b)
}

// StreamID returns the QUIC stream ID of the underlying QUIC stream.
func (s *RequestStream) StreamID() quic.StreamID {
	return s.str.StreamID()
}

// QlogTrace returns the qlog trace of the underlying QUIC connection.
// It is nil if qlog is not enabled.
func (s *RequestStream) QlogTrace() qlogwriter.Trace {
	return s.str.QlogTrace()
}

// Write writes data to the stream.
//
// It can only be used after the request has been sent using [RequestStream.SendRequestHeader].
func (s *RequestStream) Write(b []byte) (int, error) {
	if !s.sentRequest {
		return 0, errors.New("http3: invalid use of RequestStream.Write before SendRequestHeader")
	}
	return s.str.Write(b)
}

// TryWriteAll writes b if the entire DATA frame can be queued immediately.
// It can only be used after the request has been sent using [RequestStream.SendRequestHeader].
func (s *RequestStream) TryWriteAll(b []byte) error {
	if !s.sentRequest {
		return errors.New("http3: invalid use of RequestStream.TryWriteAll before SendRequestHeader")
	}
	return s.str.TryWriteAll(b)
}

// Close closes the send-direction of the stream.
// It does not close the receive-direction of the stream.
func (s *RequestStream) Close() error {
	return s.str.Close()
}

// CancelRead aborts receiving on this stream.
// See [quic.Stream.CancelRead] for more details.
func (s *RequestStream) CancelRead(errorCode quic.StreamErrorCode) {
	s.str.CancelRead(errorCode)
}

// CancelWrite aborts sending on this stream.
// See [quic.Stream.CancelWrite] for more details.
func (s *RequestStream) CancelWrite(errorCode quic.StreamErrorCode) {
	s.str.CancelWrite(errorCode)
}

// Context returns a context derived from the underlying QUIC stream's context.
// See [quic.Stream.Context] for more details.
func (s *RequestStream) Context() context.Context {
	return s.str.Context()
}

// SetReadDeadline sets the deadline for [RequestStream.Read] calls.
func (s *RequestStream) SetReadDeadline(t time.Time) error {
	return s.str.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for [RequestStream.Write] calls.
func (s *RequestStream) SetWriteDeadline(t time.Time) error {
	return s.str.SetWriteDeadline(t)
}

// SetDeadline sets the read and write deadlines associated with the stream.
// It is equivalent to calling both [RequestStream.SetReadDeadline] and [RequestStream.SetWriteDeadline].
func (s *RequestStream) SetDeadline(t time.Time) error {
	return s.str.SetDeadline(t)
}

// SendDatagram sends a new HTTP Datagram (RFC 9297).
//
// It is only possible to send datagrams if the server enabled support for this extension.
// It is recommended (though not required) to send the request before calling this method,
// as the server might drop datagrams which it can't associate with an existing request.
func (s *RequestStream) SendDatagram(b []byte) error {
	return s.str.SendDatagram(b)
}

// ReceiveDatagram receives HTTP Datagrams (RFC 9297).
//
// It is only possible if HTTP Datagram support was enabled using [Transport.EnableDatagrams].
func (s *RequestStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.str.ReceiveDatagram(ctx)
}

// SendRequestHeader sends the HTTP request.
//
// It can only be used for requests that don't have a request body.
// It is invalid to call it more than once.
func (s *RequestStream) SendRequestHeader(req *http.Request) error {
	if !s.str.addQlogProducer() {
		_, err := s.str.writeUnframed(nil)
		return err
	}
	defer s.str.removeQlogProducer()

	if req.Body != nil && req.Body != http.NoBody {
		return errors.New("http3: invalid use of RequestStream.SendRequestHeader with a request that has a request body")
	}
	return s.sendRequestHeader(req)
}

func (s *RequestStream) sendRequestHeader(req *http.Request) error {
	if s.sentRequest {
		return errors.New("http3: invalid duplicate use of RequestStream.SendRequestHeader")
	}
	if !s.disableCompression && req.Method != http.MethodHead &&
		req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" {
		s.requestedGzip = true
	}
	s.isConnect = req.Method == http.MethodConnect
	s.isHead = req.Method == http.MethodHead
	s.sentRequest = true
	return maybeReplaceError(s.requestWriter.WriteRequestHeader(s.str.datagramStream, req, s.requestedGzip, s.str.StreamID(), s.str.qlogger))
}

// sendRequestTrailer sends request trailers to the stream.
// It should be called after the request body has been fully written.
func (s *RequestStream) sendRequestTrailer(req *http.Request) error {
	if !s.str.addQlogProducer() {
		_, err := s.str.writeUnframed(nil)
		return err
	}
	defer s.str.removeQlogProducer()

	return maybeReplaceError(s.requestWriter.WriteRequestTrailer(s.str.datagramStream, req, s.str.StreamID(), s.str.qlogger))
}

// ReadResponse reads the HTTP response from the stream.
//
// It must be called after sending the request using [RequestStream.SendRequestHeader].
// It is invalid to call it more than once.
// It doesn't set [http.Response.Request] or [http.Response.TLS].
func (s *RequestStream) ReadResponse() (*http.Response, error) {
	s.str.addQlogProducer()
	defer s.str.removeQlogProducer()

	if !s.sentRequest {
		return nil, errors.New("http3: invalid use of RequestStream.ReadResponse before SendRequestHeader")
	}
	frame, err := s.str.frameParser.ParseNext(s.str.qlogger)
	if err != nil {
		if errors.Is(err, errPriorityUpdateForPush) {
			s.str.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
			return nil, err
		}
		s.str.CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
		s.str.CancelWrite(quic.StreamErrorCode(ErrCodeFrameError))
		return nil, fmt.Errorf("http3: parsing frame failed: %w", maybeReplaceError(err))
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		s.str.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "expected first frame to be a HEADERS frame")
		return nil, errors.New("http3: expected first frame to be a HEADERS frame")
	}
	if hf.Length > uint64(s.maxHeaderBytes) {
		maybeQlogInvalidHeadersFrame(s.str.qlogger, s.str.StreamID(), hf.Length)
		s.str.CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
		s.str.CancelWrite(quic.StreamErrorCode(ErrCodeFrameError))
		return nil, fmt.Errorf("http3: HEADERS frame too large: %d bytes (max: %d)", hf.Length, s.maxHeaderBytes)
	}
	headerBlock, err := readHeaderBlock(s.str.datagramStream, hf.Length)
	if err != nil {
		maybeQlogInvalidHeadersFrame(s.str.qlogger, s.str.StreamID(), hf.Length)
		s.str.CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		s.str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		return nil, fmt.Errorf("http3: failed to read response headers: %w", maybeReplaceError(err))
	}
	decodeFn := s.decoder.Decode(headerBlock)
	var hfs []qpack.HeaderField
	if s.str.qlogger != nil {
		hfs = make([]qpack.HeaderField, 0, 16)
	}
	res := s.response
	err = updateResponseFromHeaders(res, decodeFn, s.maxHeaderBytes, &hfs)
	if s.str.qlogger != nil {
		qlogParsedHeadersFrame(s.str.qlogger, s.str.StreamID(), hf, hfs, err)
	}
	if err != nil {
		errCode := ErrCodeMessageError
		if _, ok := errors.AsType[*qpackError](err); ok {
			errCode = ErrCodeQPACKDecompressionFailed
		}
		s.str.CancelRead(quic.StreamErrorCode(errCode))
		s.str.CancelWrite(quic.StreamErrorCode(errCode))
		return nil, fmt.Errorf("http3: invalid response: %w", err)
	}

	isInformational := res.StatusCode >= 100 && res.StatusCode < 200
	isNoContent := res.StatusCode == http.StatusNoContent
	isSuccessfulConnect := s.isConnect && res.StatusCode >= 200 && res.StatusCode < 300

	// Enforce the Content-Length (section 4.1.2 of RFC 9114).
	contentLength := res.ContentLength
	// Responses without content may declare a non-zero Content-Length.
	if isInformational || isNoContent || res.StatusCode == http.StatusNotModified || s.isHead {
		contentLength = 0
	}
	// A successful CONNECT response starts a tunnel, even if it's a 204.
	if isSuccessfulConnect {
		contentLength = res.ContentLength
	}
	respBody := newResponseBody(s.str, contentLength, s.reqDone)

	// Rules for when to set Content-Length are defined in https://tools.ietf.org/html/rfc7230#section-3.3.2.
	if (isInformational || isNoContent || isSuccessfulConnect) && res.ContentLength == -1 {
		res.ContentLength = 0
	}
	if s.requestedGzip && !isSuccessfulConnect && res.Header.Get("Content-Encoding") == "gzip" {
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		s.responseBody = newGzipReader(respBody)
		res.Uncompressed = true
	} else {
		s.responseBody = respBody
	}
	res.Body = s.responseBody
	return res, nil
}

type tracingReader struct {
	io.Reader
	readFirst bool
	trace     *httptrace.ClientTrace
}

func (r *tracingReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if n > 0 && !r.readFirst {
		traceGotFirstResponseByte(r.trace)
		r.readFirst = true
	}
	return n, err
}
