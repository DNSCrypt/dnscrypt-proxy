package http3

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
)

// RawServerConn is an HTTP/3 server connection.
// It can be used for advanced use cases where the application wants to manage the QUIC connection lifecycle.
type RawServerConn struct {
	rawConn *rawConn

	idleTimeout       time.Duration
	idleTimer         *time.Timer
	readHeaderTimeout time.Duration

	serverContext  context.Context
	requestHandler http.Handler

	priorityAware atomic.Bool // whether the client sent an RFC 9218 priority signal

	qlogger qlogwriter.Recorder
	logger  *slog.Logger
}

func newRawServerConn(
	conn *quic.Conn,
	enableDatagrams bool,
	idleTimeout time.Duration,
	qlogger qlogwriter.Recorder,
	logger *slog.Logger,
	serverContext context.Context,
	requestHandler http.Handler,
	maxHeaderBytes int,
) *RawServerConn {
	c := &RawServerConn{
		idleTimeout:    idleTimeout,
		serverContext:  serverContext,
		requestHandler: requestHandler,
		qlogger:        qlogger,
		logger:         logger,
	}
	c.rawConn = newRawConn(conn, enableDatagrams, maxHeaderBytes, c.onStreamsEmpty, c.handleControlStream, qlogger, logger)
	if idleTimeout > 0 {
		c.idleTimer = time.AfterFunc(idleTimeout, func() {
			conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeNoError), "idle timeout")
		})
	}
	return c
}

func (c *RawServerConn) onStreamsEmpty() {
	if c.idleTimeout > 0 {
		c.idleTimer.Reset(c.idleTimeout)
	}
}

// CloseWithError closes the connection with the given error code and message.
func (c *RawServerConn) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	if c.idleTimer != nil {
		c.idleTimer.Stop()
	}
	return c.rawConn.CloseWithError(code, msg)
}

// HandleRequestStream handles an HTTP/3 request on a bidirectional request stream.
// The stream can either be obtained by calling [quic.Conn.AcceptStream] on the underlying QUIC connection,
// or (internally) by using the server's stream accept loop.
func (c *RawServerConn) HandleRequestStream(str *quic.Stream) {
	// HTTP/3 handles this stream, so the peer can replace it as soon as it completes.
	str.ReleaseStreamCredit()
	// the handler can produce qlog events until it returns, even after the connection was closed
	c.rawConn.AddQlogProducer()
	defer c.rawConn.RemoveQlogProducer()
	hstr := c.rawConn.TrackStream(str)
	c.handleRequestStream(hstr)
}

func (c *RawServerConn) openControlStream(settings *settingsFrame) (*quic.SendStream, error) {
	return c.rawConn.openControlStream(settings)
}

func (c *RawServerConn) handleRequestStream(str *stateTrackingStream) {
	if c.readHeaderTimeout > 0 {
		_ = str.SetReadDeadline(time.Now().Add(c.readHeaderTimeout))
	}
	if c.idleTimeout > 0 {
		// This only applies if the stream is the first active stream,
		// but it's ok to stop a stopped timer.
		c.idleTimer.Stop()
	}

	conn := c.rawConn
	connCtx := c.serverContext

	hstr := newServerStream(str, conn, c.qlogger)
	req, err := hstr.readRequestHeader()
	if err != nil {
		if errors.Is(err, errHeaderTooLarge) {
			c.rejectWithHeaderFieldsTooLarge(hstr)
		}
		return
	}
	// The header timeout must not limit reads of the request body.
	if c.readHeaderTimeout > 0 {
		_ = str.SetReadDeadline(time.Time{})
	}

	connState := conn.ConnectionState().TLS
	req.TLS = &connState
	req.RemoteAddr = conn.RemoteAddr().String()

	// Enforce the Content-Length, if set (section 4.1.2 of RFC 9114).
	contentLength := int64(-1)
	if _, ok := req.Header["Content-Length"]; ok && req.ContentLength >= 0 {
		contentLength = req.ContentLength
	}
	ctx, cancel := context.WithCancel(connCtx)
	req = req.WithContext(ctx)
	context.AfterFunc(str.Context(), cancel)

	// Only DATA frames are allowed after a CONNECT request (RFC 9114, Section 4.4).
	if req.Method == http.MethodConnect {
		hstr.rejectTrailer()
	}
	// HTTP Datagrams received for a request without datagram semantics abort the request (RFC 9297, Section 2).
	// Only Extended CONNECT requests can define such semantics.
	// For these, req.Proto is the :protocol value, otherwise it's "HTTP/3.0".
	if req.Proto == "HTTP/3.0" {
		str.RejectDatagrams()
	}

	// We only use the client's priority for local scheduling.
	// A Priority response header is only transmitted so that potential intermediaries can use it,
	// it doesn't affect local scheduling.
	// This mirrors the behavior of HTTP/2, see https://github.com/golang/go/issues/75500.
	var urgency int8
	var incremental bool
	if values, ok := req.Header["Priority"]; !ok {
		urgency, incremental = defaultPriorityUrgency, !c.priorityAware.Load()
	} else {
		c.priorityAware.Store(true)
		urgency, incremental = parsePriority(strings.Join(values, ","))
	}
	hstr.SetPriority(urgency, incremental)

	// The body stores the trailers in the request passed to the handler.
	body := newRequestBody(hstr, contentLength, &req.Trailer, connCtx, conn.ReceivedSettings(), conn.Settings)
	req.Body = body

	if c.logger != nil {
		c.logger.Debug("handling request", "method", req.Method, "host", req.Host, "uri", req.RequestURI)
	}

	r := newResponseWriter(hstr, conn, req.Method, c.logger)
	handler := c.requestHandler
	if handler == nil {
		handler = http.DefaultServeMux
	}

	// It's the client's responsibility to decide which requests are eligible for 0-RTT.
	var panicked bool
	func() {
		defer func() {
			if p := recover(); p != nil {
				panicked = true
				if p == http.ErrAbortHandler {
					return
				}
				// Copied from net/http/server.go
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				logger := c.logger
				if logger == nil {
					logger = slog.Default()
				}
				logger.Error("http3: panic serving", "arg", p, "trace", string(buf))
			}
		}()
		handler.ServeHTTP(r, req)
	}()

	if r.wasStreamHijacked() {
		return
	}

	// abort the stream when there is a panic
	if panicked {
		str.CancelRead(quic.StreamErrorCode(ErrCodeInternalError))
		str.CancelWrite(quic.StreamErrorCode(ErrCodeInternalError))
		return
	}

	// Abort the stream if the response is incomplete: flushing failed, or the handler returned
	// after a write failed partway through a DATA frame, which would leave the frame truncated.
	if err := r.Finish(); err != nil || hstr.hasUnfinishedFrame() {
		str.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))
		str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
		return
	}
	r.flushTrailers()

	// If the EOF was read by the handler, CancelRead() is a no-op.
	str.CancelRead(quic.StreamErrorCode(ErrCodeNoError))
	str.Close()
}

func (c *RawServerConn) handleControlStream(_ *quic.ReceiveStream, fp *frameParser) {
	for {
		f, err := fp.ParseNext(c.qlogger)
		if err != nil {
			if errors.Is(err, errPriorityUpdateForPush) {
				// Server push is not supported. Since we never send PUSH_PROMISE frames,
				// the client can't reference a valid push ID.
				c.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
				return
			}
			_, isStreamError := errors.AsType[*quic.StreamError](err)
			if err == io.EOF || isStreamError {
				c.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), "")
				return
			}
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "")
			return
		}
		switch frame := f.(type) {
		case *priorityUpdateFrame:
			if frame.ElementID%4 != 0 {
				c.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
				return
			}
			c.priorityAware.Store(true)
			urgency, incremental := parsePriority(frame.PriorityFieldValue)
			c.rawConn.UpdateStreamPriority(quic.StreamID(frame.ElementID), urgency, incremental)
		case *goAwayFrame:
			// Server push is not supported, so we ignore the push ID.
			// We don't close the connection if it increased since the last GOAWAY frame,
			// although RFC 9114, Section 5.2 requires it.
		default:
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
			return
		}
	}
}

func (c *RawServerConn) rejectWithHeaderFieldsTooLarge(str *Stream) {
	// stop the client from sending more data
	str.CancelRead(quic.StreamErrorCode(ErrCodeExcessiveLoad))
	defer str.Close()
	r := newResponseWriter(str, c.rawConn, "", c.logger)
	r.WriteHeader(http.StatusRequestHeaderFieldsTooLarge)
	r.Flush()
}

// HandleUnidirectionalStream handles an incoming unidirectional stream.
func (c *RawServerConn) HandleUnidirectionalStream(str *quic.ReceiveStream) {
	c.rawConn.handleUnidirectionalStream(str, true)
}
