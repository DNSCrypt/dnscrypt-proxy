package http3

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/quic-go/qpack"
)

// Connection is an HTTP/3 connection.
// It has all methods from the quic.Connection expect for AcceptStream, AcceptUniStream,
// SendDatagram and ReceiveDatagram.
type Connection interface {
	OpenStream() (quic.Stream, error)
	OpenStreamSync(context.Context) (quic.Stream, error)
	OpenUniStream() (quic.SendStream, error)
	OpenUniStreamSync(context.Context) (quic.SendStream, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	CloseWithError(quic.ApplicationErrorCode, string) error
	Context() context.Context
	ConnectionState() quic.ConnectionState

	// ReceivedSettings returns a channel that is closed once the client's SETTINGS frame was received.
	ReceivedSettings() <-chan struct{}
	// Settings returns the settings received on this connection.
	Settings() *Settings
}

type connection struct {
	quic.Connection
	ctx context.Context

	perspective protocol.Perspective
	logger      *slog.Logger

	enableDatagrams bool

	decoder *qpack.Decoder

	streamMx sync.Mutex
	streams  map[protocol.StreamID]*datagrammer

	settings         *Settings
	receivedSettings chan struct{}

	idleTimeout time.Duration
	idleTimer   *time.Timer
}

func newConnection(
	ctx context.Context,
	quicConn quic.Connection,
	enableDatagrams bool,
	perspective protocol.Perspective,
	logger *slog.Logger,
	idleTimeout time.Duration,
) *connection {
	c := &connection{
		ctx:              ctx,
		Connection:       quicConn,
		perspective:      perspective,
		logger:           logger,
		idleTimeout:      idleTimeout,
		enableDatagrams:  enableDatagrams,
		decoder:          qpack.NewDecoder(func(hf qpack.HeaderField) {}),
		receivedSettings: make(chan struct{}),
		streams:          make(map[protocol.StreamID]*datagrammer),
	}
	if idleTimeout > 0 {
		c.idleTimer = time.AfterFunc(idleTimeout, c.onIdleTimer)
	}
	return c
}

func (c *connection) onIdleTimer() {
	c.CloseWithError(quic.ApplicationErrorCode(ErrCodeNoError), "idle timeout")
}

func (c *connection) clearStream(id quic.StreamID) {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()

	delete(c.streams, id)
	if c.idleTimeout > 0 && len(c.streams) == 0 {
		c.idleTimer.Reset(c.idleTimeout)
	}
}

func (c *connection) openRequestStream(
	ctx context.Context,
	requestWriter *requestWriter,
	reqDone chan<- struct{},
	disableCompression bool,
	maxHeaderBytes uint64,
) (*requestStream, error) {
	str, err := c.Connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	datagrams := newDatagrammer(func(b []byte) error { return c.sendDatagram(str.StreamID(), b) })
	c.streamMx.Lock()
	c.streams[str.StreamID()] = datagrams
	c.streamMx.Unlock()
	qstr := newStateTrackingStream(str, c, datagrams)
	rsp := &http.Response{}
	hstr := newStream(qstr, c, datagrams, func(r io.Reader, l uint64) error {
		hdr, err := c.decodeTrailers(r, l, maxHeaderBytes)
		if err != nil {
			return err
		}
		rsp.Trailer = hdr
		return nil
	})
	return newRequestStream(hstr, requestWriter, reqDone, c.decoder, disableCompression, maxHeaderBytes, rsp), nil
}

func (c *connection) decodeTrailers(r io.Reader, l, maxHeaderBytes uint64) (http.Header, error) {
	if l > maxHeaderBytes {
		return nil, fmt.Errorf("HEADERS frame too large: %d bytes (max: %d)", l, maxHeaderBytes)
	}

	b := make([]byte, l)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	fields, err := c.decoder.DecodeFull(b)
	if err != nil {
		return nil, err
	}
	return parseTrailers(fields)
}

func (c *connection) acceptStream(ctx context.Context) (quic.Stream, *datagrammer, error) {
	str, err := c.AcceptStream(ctx)
	if err != nil {
		return nil, nil, err
	}
	datagrams := newDatagrammer(func(b []byte) error { return c.sendDatagram(str.StreamID(), b) })
	if c.perspective == protocol.PerspectiveServer {
		strID := str.StreamID()
		c.streamMx.Lock()
		c.streams[strID] = datagrams
		if c.idleTimeout > 0 {
			if len(c.streams) == 1 {
				c.idleTimer.Stop()
			}
		}
		c.streamMx.Unlock()
		str = newStateTrackingStream(str, c, datagrams)
	}
	return str, datagrams, nil
}

func (c *connection) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	if c.idleTimer != nil {
		c.idleTimer.Stop()
	}
	return c.Connection.CloseWithError(code, msg)
}

func (c *connection) handleUnidirectionalStreams(hijack func(StreamType, quic.ConnectionTracingID, quic.ReceiveStream, error) (hijacked bool)) {
	var (
		rcvdControlStr      atomic.Bool
		rcvdQPACKEncoderStr atomic.Bool
		rcvdQPACKDecoderStr atomic.Bool
	)

	for {
		str, err := c.Connection.AcceptUniStream(context.Background())
		if err != nil {
			if c.logger != nil {
				c.logger.Debug("accepting unidirectional stream failed", "error", err)
			}
			return
		}

		go func(str quic.ReceiveStream) {
			streamType, err := quicvarint.Read(quicvarint.NewReader(str))
			if err != nil {
				id := c.Connection.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
				if hijack != nil && hijack(StreamType(streamType), id, str, err) {
					return
				}
				if c.logger != nil {
					c.logger.Debug("reading stream type on stream failed", "stream ID", str.StreamID(), "error", err)
				}
				return
			}
			// We're only interested in the control stream here.
			switch streamType {
			case streamTypeControlStream:
			case streamTypeQPACKEncoderStream:
				if isFirst := rcvdQPACKEncoderStr.CompareAndSwap(false, true); !isFirst {
					c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK encoder stream")
				}
				// Our QPACK implementation doesn't use the dynamic table yet.
				return
			case streamTypeQPACKDecoderStream:
				if isFirst := rcvdQPACKDecoderStr.CompareAndSwap(false, true); !isFirst {
					c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK decoder stream")
				}
				// Our QPACK implementation doesn't use the dynamic table yet.
				return
			case streamTypePushStream:
				switch c.perspective {
				case protocol.PerspectiveClient:
					// we never increased the Push ID, so we don't expect any push streams
					c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
				case protocol.PerspectiveServer:
					// only the server can push
					c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "")
				}
				return
			default:
				if hijack != nil {
					if hijack(
						StreamType(streamType),
						c.Connection.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID),
						str,
						nil,
					) {
						return
					}
				}
				str.CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError))
				return
			}
			// Only a single control stream is allowed.
			if isFirstControlStr := rcvdControlStr.CompareAndSwap(false, true); !isFirstControlStr {
				c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate control stream")
				return
			}
			fp := &frameParser{conn: c.Connection, r: str}
			f, err := fp.ParseNext()
			if err != nil {
				c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "")
				return
			}
			sf, ok := f.(*settingsFrame)
			if !ok {
				c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeMissingSettings), "")
				return
			}
			c.settings = &Settings{
				EnableDatagrams:       sf.Datagram,
				EnableExtendedConnect: sf.ExtendedConnect,
				Other:                 sf.Other,
			}
			close(c.receivedSettings)
			if !sf.Datagram {
				return
			}
			// If datagram support was enabled on our side as well as on the server side,
			// we can expect it to have been negotiated both on the transport and on the HTTP/3 layer.
			// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
			if c.enableDatagrams && !c.Connection.ConnectionState().SupportsDatagrams {
				c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeSettingsError), "missing QUIC Datagram support")
				return
			}
			go func() {
				if err := c.receiveDatagrams(); err != nil {
					if c.logger != nil {
						c.logger.Debug("receiving datagrams failed", "error", err)
					}
				}
			}()
		}(str)
	}
}

func (c *connection) sendDatagram(streamID protocol.StreamID, b []byte) error {
	// TODO: this creates a lot of garbage and an additional copy
	data := make([]byte, 0, len(b)+8)
	data = quicvarint.Append(data, uint64(streamID/4))
	data = append(data, b...)
	return c.Connection.SendDatagram(data)
}

func (c *connection) receiveDatagrams() error {
	for {
		b, err := c.Connection.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		quarterStreamID, n, err := quicvarint.Parse(b)
		if err != nil {
			c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
			return fmt.Errorf("could not read quarter stream id: %w", err)
		}
		if quarterStreamID > maxQuarterStreamID {
			c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
			return fmt.Errorf("invalid quarter stream id: %w", err)
		}
		streamID := protocol.StreamID(4 * quarterStreamID)
		c.streamMx.Lock()
		dg, ok := c.streams[streamID]
		if !ok {
			c.streamMx.Unlock()
			return nil
		}
		c.streamMx.Unlock()
		dg.enqueue(b[n:])
	}
}

// ReceivedSettings returns a channel that is closed once the peer's SETTINGS frame was received.
// Settings can be optained from the Settings method after the channel was closed.
func (c *connection) ReceivedSettings() <-chan struct{} { return c.receivedSettings }

// Settings returns the settings received on this connection.
// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
func (c *connection) Settings() *Settings { return c.settings }

// Context returns the context of the underlying QUIC connection.
func (c *connection) Context() context.Context { return c.ctx }
