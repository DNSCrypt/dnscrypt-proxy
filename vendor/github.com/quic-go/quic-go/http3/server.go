package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/quic-go/qpack"
)

// allows mocking of quic.Listen and quic.ListenAddr
var (
	quicListen = func(conn net.PacketConn, tlsConf *tls.Config, config *quic.Config) (QUICEarlyListener, error) {
		return quic.ListenEarly(conn, tlsConf, config)
	}
	quicListenAddr = func(addr string, tlsConf *tls.Config, config *quic.Config) (QUICEarlyListener, error) {
		return quic.ListenAddrEarly(addr, tlsConf, config)
	}
)

// NextProtoH3 is the ALPN protocol negotiated during the TLS handshake, for QUIC v1 and v2.
const NextProtoH3 = "h3"

// StreamType is the stream type of a unidirectional stream.
type StreamType uint64

const (
	streamTypeControlStream      = 0
	streamTypePushStream         = 1
	streamTypeQPACKEncoderStream = 2
	streamTypeQPACKDecoderStream = 3
)

const goawayTimeout = 5 * time.Second

// A QUICEarlyListener listens for incoming QUIC connections.
type QUICEarlyListener interface {
	Accept(context.Context) (quic.EarlyConnection, error)
	Addr() net.Addr
	io.Closer
}

var _ QUICEarlyListener = &quic.EarlyListener{}

func versionToALPN(v protocol.Version) string {
	//nolint:exhaustive // These are all the versions we care about.
	switch v {
	case protocol.Version1, protocol.Version2:
		return NextProtoH3
	default:
		return ""
	}
}

// ConfigureTLSConfig creates a new tls.Config which can be used
// to create a quic.Listener meant for serving http3. The created
// tls.Config adds the functionality of detecting the used QUIC version
// in order to set the correct ALPN value for the http3 connection.
func ConfigureTLSConfig(tlsConf *tls.Config) *tls.Config {
	// The tls.Config used to setup the quic.Listener needs to have the GetConfigForClient callback set.
	// That way, we can get the QUIC version and set the correct ALPN value.
	return &tls.Config{
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			// determine the ALPN from the QUIC version used
			proto := NextProtoH3
			val := ch.Context().Value(quic.QUICVersionContextKey)
			if v, ok := val.(quic.Version); ok {
				proto = versionToALPN(v)
			}
			config := tlsConf
			if tlsConf.GetConfigForClient != nil {
				getConfigForClient := tlsConf.GetConfigForClient
				var err error
				conf, err := getConfigForClient(ch)
				if err != nil {
					return nil, err
				}
				if conf != nil {
					config = conf
				}
			}
			if config == nil {
				return nil, nil
			}
			// Workaround for https://github.com/golang/go/issues/60506.
			// This initializes the session tickets _before_ cloning the config.
			_, _ = config.DecryptTicket(nil, tls.ConnectionState{})

			config = config.Clone()
			config.NextProtos = []string{proto}
			return config, nil
		},
	}
}

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation.
type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "quic-go/http3 context value " + k.name }

// ServerContextKey is a context key. It can be used in HTTP
// handlers with Context.Value to access the server that
// started the handler. The associated value will be of
// type *http3.Server.
var ServerContextKey = &contextKey{"http3-server"}

// RemoteAddrContextKey is a context key. It can be used in
// HTTP handlers with Context.Value to access the remote
// address of the connection. The associated value will be of
// type net.Addr.
//
// Use this value instead of [http.Request.RemoteAddr] if you
// require access to the remote address of the connection rather
// than its string representation.
var RemoteAddrContextKey = &contextKey{"remote-addr"}

// listenerInfo contains info about specific listener added with addListener
type listenerInfo struct {
	port int // 0 means that no info about port is available
}

// Server is a HTTP/3 server.
type Server struct {
	// Addr optionally specifies the UDP address for the server to listen on,
	// in the form "host:port".
	//
	// When used by ListenAndServe and ListenAndServeTLS methods, if empty,
	// ":https" (port 443) is used. See net.Dial for details of the address
	// format.
	//
	// Otherwise, if Port is not set and underlying QUIC listeners do not
	// have valid port numbers, the port part is used in Alt-Svc headers set
	// with SetQUICHeaders.
	Addr string

	// Port is used in Alt-Svc response headers set with SetQUICHeaders. If
	// needed Port can be manually set when the Server is created.
	//
	// This is useful when a Layer 4 firewall is redirecting UDP traffic and
	// clients must use a port different from the port the Server is
	// listening on.
	Port int

	// TLSConfig provides a TLS configuration for use by server. It must be
	// set for ListenAndServe and Serve methods.
	TLSConfig *tls.Config

	// QUICConfig provides the parameters for QUIC connection created with Serve.
	// If nil, it uses reasonable default values.
	//
	// Configured versions are also used in Alt-Svc response header set with SetQUICHeaders.
	QUICConfig *quic.Config

	// Handler is the HTTP request handler to use. If not set, defaults to
	// http.NotFound.
	Handler http.Handler

	// EnableDatagrams enables support for HTTP/3 datagrams (RFC 9297).
	// If set to true, QUICConfig.EnableDatagrams will be set.
	EnableDatagrams bool

	// MaxHeaderBytes controls the maximum number of bytes the server will
	// read parsing the request HEADERS frame. It does not limit the size of
	// the request body. If zero or negative, http.DefaultMaxHeaderBytes is
	// used.
	MaxHeaderBytes int

	// AdditionalSettings specifies additional HTTP/3 settings.
	// It is invalid to specify any settings defined by RFC 9114 (HTTP/3) and RFC 9297 (HTTP Datagrams).
	AdditionalSettings map[uint64]uint64

	// StreamHijacker, when set, is called for the first unknown frame parsed on a bidirectional stream.
	// It is called right after parsing the frame type.
	// If parsing the frame type fails, the error is passed to the callback.
	// In that case, the frame type will not be set.
	// Callers can either ignore the frame and return control of the stream back to HTTP/3
	// (by returning hijacked false).
	// Alternatively, callers can take over the QUIC stream (by returning hijacked true).
	StreamHijacker func(FrameType, quic.ConnectionTracingID, quic.Stream, error) (hijacked bool, err error)

	// UniStreamHijacker, when set, is called for unknown unidirectional stream of unknown stream type.
	// If parsing the stream type fails, the error is passed to the callback.
	// In that case, the stream type will not be set.
	UniStreamHijacker func(StreamType, quic.ConnectionTracingID, quic.ReceiveStream, error) (hijacked bool)

	// IdleTimeout specifies how long until idle clients connection should be
	// closed. Idle refers only to the HTTP/3 layer, activity at the QUIC layer
	// like PING frames are not considered.
	// If zero or negative, there is no timeout.
	IdleTimeout time.Duration

	// ConnContext optionally specifies a function that modifies the context used for a new connection c.
	// The provided ctx has a ServerContextKey value.
	ConnContext func(ctx context.Context, c quic.Connection) context.Context

	Logger *slog.Logger

	mutex     sync.RWMutex
	listeners map[*QUICEarlyListener]listenerInfo

	closed           bool
	closeCtx         context.Context    // canceled when the server is closed
	closeCancel      context.CancelFunc // cancels the closeCtx
	graceCtx         context.Context    // canceled when the server is closed or gracefully closed
	graceCancel      context.CancelFunc // cancels the graceCtx
	connCount        atomic.Int64
	connHandlingDone chan struct{}

	altSvcHeader string
}

// ListenAndServe listens on the UDP address s.Addr and calls s.Handler to handle HTTP/3 requests on incoming connections.
//
// If s.Addr is blank, ":https" is used.
func (s *Server) ListenAndServe() error {
	ln, err := s.setupListenerForConn(s.TLSConfig, nil)
	if err != nil {
		return err
	}
	defer s.removeListener(&ln)

	return s.serveListener(ln)
}

// ListenAndServeTLS listens on the UDP address s.Addr and calls s.Handler to handle HTTP/3 requests on incoming connections.
//
// If s.Addr is blank, ":https" is used.
func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	var err error
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.
	ln, err := s.setupListenerForConn(&tls.Config{Certificates: certs}, nil)
	if err != nil {
		return err
	}
	defer s.removeListener(&ln)

	return s.serveListener(ln)
}

// Serve an existing UDP connection.
// It is possible to reuse the same connection for outgoing connections.
// Closing the server does not close the connection.
func (s *Server) Serve(conn net.PacketConn) error {
	ln, err := s.setupListenerForConn(s.TLSConfig, conn)
	if err != nil {
		return err
	}
	defer s.removeListener(&ln)

	return s.serveListener(ln)
}

// init initializes the contexts used for shutting down the server.
// It must be called with the mutex held.
func (s *Server) init() {
	if s.closeCtx == nil {
		s.closeCtx, s.closeCancel = context.WithCancel(context.Background())
		s.graceCtx, s.graceCancel = context.WithCancel(s.closeCtx)
	}
	s.connHandlingDone = make(chan struct{}, 1)
}

func (s *Server) decreaseConnCount() {
	if s.connCount.Add(-1) == 0 && s.graceCtx.Err() != nil {
		close(s.connHandlingDone)
	}
}

// ServeQUICConn serves a single QUIC connection.
func (s *Server) ServeQUICConn(conn quic.Connection) error {
	s.mutex.Lock()
	s.init()
	s.mutex.Unlock()

	s.connCount.Add(1)
	defer s.decreaseConnCount()

	return s.handleConn(conn)
}

// ServeListener serves an existing QUIC listener.
// Make sure you use http3.ConfigureTLSConfig to configure a tls.Config
// and use it to construct a http3-friendly QUIC listener.
// Closing the server does close the listener.
// ServeListener always returns a non-nil error. After Shutdown or Close, the returned error is http.ErrServerClosed.
func (s *Server) ServeListener(ln QUICEarlyListener) error {
	s.mutex.Lock()
	if err := s.addListener(&ln); err != nil {
		s.mutex.Unlock()
		return err
	}
	s.mutex.Unlock()
	defer s.removeListener(&ln)

	return s.serveListener(ln)
}

func (s *Server) serveListener(ln QUICEarlyListener) error {
	for {
		conn, err := ln.Accept(s.graceCtx)
		// server closed
		if errors.Is(err, quic.ErrServerClosed) || s.graceCtx.Err() != nil {
			return http.ErrServerClosed
		}
		if err != nil {
			return err
		}
		s.connCount.Add(1)
		go func() {
			defer s.decreaseConnCount()
			if err := s.handleConn(conn); err != nil {
				if s.Logger != nil {
					s.Logger.Debug("handling connection failed", "error", err)
				}
			}
		}()
	}
}

var errServerWithoutTLSConfig = errors.New("use of http3.Server without TLSConfig")

func (s *Server) setupListenerForConn(tlsConf *tls.Config, conn net.PacketConn) (QUICEarlyListener, error) {
	if tlsConf == nil {
		return nil, errServerWithoutTLSConfig
	}

	baseConf := ConfigureTLSConfig(tlsConf)
	quicConf := s.QUICConfig
	if quicConf == nil {
		quicConf = &quic.Config{Allow0RTT: true}
	} else {
		quicConf = s.QUICConfig.Clone()
	}
	if s.EnableDatagrams {
		quicConf.EnableDatagrams = true
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	closed := s.closed
	if closed {
		return nil, http.ErrServerClosed
	}

	var ln QUICEarlyListener
	var err error
	if conn == nil {
		addr := s.Addr
		if addr == "" {
			addr = ":https"
		}
		ln, err = quicListenAddr(addr, baseConf, quicConf)
	} else {
		ln, err = quicListen(conn, baseConf, quicConf)
	}
	if err != nil {
		return nil, err
	}
	if err := s.addListener(&ln); err != nil {
		return nil, err
	}
	return ln, nil
}

func extractPort(addr string) (int, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}

	portInt, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return 0, err
	}
	return portInt, nil
}

func (s *Server) generateAltSvcHeader() {
	if len(s.listeners) == 0 {
		// Don't announce any ports since no one is listening for connections
		s.altSvcHeader = ""
		return
	}

	// This code assumes that we will use protocol.SupportedVersions if no quic.Config is passed.
	supportedVersions := protocol.SupportedVersions
	if s.QUICConfig != nil && len(s.QUICConfig.Versions) > 0 {
		supportedVersions = s.QUICConfig.Versions
	}

	// keep track of which have been seen so we don't yield duplicate values
	seen := make(map[string]struct{}, len(supportedVersions))
	var versionStrings []string
	for _, version := range supportedVersions {
		if v := versionToALPN(version); len(v) > 0 {
			if _, ok := seen[v]; !ok {
				versionStrings = append(versionStrings, v)
				seen[v] = struct{}{}
			}
		}
	}

	var altSvc []string
	addPort := func(port int) {
		for _, v := range versionStrings {
			altSvc = append(altSvc, fmt.Sprintf(`%s=":%d"; ma=2592000`, v, port))
		}
	}

	if s.Port != 0 {
		// if Port is specified, we must use it instead of the
		// listener addresses since there's a reason it's specified.
		addPort(s.Port)
	} else {
		// if we have some listeners assigned, try to find ports
		// which we can announce, otherwise nothing should be announced
		validPortsFound := false
		for _, info := range s.listeners {
			if info.port != 0 {
				addPort(info.port)
				validPortsFound = true
			}
		}
		if !validPortsFound {
			if port, err := extractPort(s.Addr); err == nil {
				addPort(port)
			}
		}
	}

	s.altSvcHeader = strings.Join(altSvc, ",")
}

// We store a pointer to interface in the map set. This is safe because we only
// call trackListener via Serve and can track+defer untrack the same pointer to
// local variable there. We never need to compare a Listener from another caller.
func (s *Server) addListener(l *QUICEarlyListener) error {
	if s.closed {
		return http.ErrServerClosed
	}
	if s.listeners == nil {
		s.listeners = make(map[*QUICEarlyListener]listenerInfo)
	}
	s.init()

	laddr := (*l).Addr()
	if port, err := extractPort(laddr.String()); err == nil {
		s.listeners[l] = listenerInfo{port}
	} else {
		logger := s.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("Unable to extract port from listener, will not be announced using SetQUICHeaders", "local addr", laddr, "error", err)
		s.listeners[l] = listenerInfo{}
	}
	s.generateAltSvcHeader()
	return nil
}

func (s *Server) removeListener(l *QUICEarlyListener) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.listeners, l)
	s.generateAltSvcHeader()
}

// handleConn handles the HTTP/3 exchange on a QUIC connection.
// It blocks until all HTTP handlers for all streams have returned.
func (s *Server) handleConn(conn quic.Connection) error {
	// open the control stream and send a SETTINGS frame, it's also used to send a GOAWAY frame later
	// when the server is gracefully closed
	ctrlStr, err := conn.OpenUniStream()
	if err != nil {
		return fmt.Errorf("opening the control stream failed: %w", err)
	}
	b := make([]byte, 0, 64)
	b = quicvarint.Append(b, streamTypeControlStream) // stream type
	b = (&settingsFrame{
		Datagram:        s.EnableDatagrams,
		ExtendedConnect: true,
		Other:           s.AdditionalSettings,
	}).Append(b)
	ctrlStr.Write(b)

	ctx := conn.Context()
	ctx = context.WithValue(ctx, ServerContextKey, s)
	ctx = context.WithValue(ctx, http.LocalAddrContextKey, conn.LocalAddr())
	ctx = context.WithValue(ctx, RemoteAddrContextKey, conn.RemoteAddr())
	if s.ConnContext != nil {
		ctx = s.ConnContext(ctx, conn)
		if ctx == nil {
			panic("http3: ConnContext returned nil")
		}
	}

	hconn := newConnection(
		ctx,
		conn,
		s.EnableDatagrams,
		protocol.PerspectiveServer,
		s.Logger,
		s.IdleTimeout,
	)
	go hconn.handleUnidirectionalStreams(s.UniStreamHijacker)

	var nextStreamID quic.StreamID
	var wg sync.WaitGroup
	var handleErr error
	// Process all requests immediately.
	// It's the client's responsibility to decide which requests are eligible for 0-RTT.
	for {
		str, datagrams, err := hconn.acceptStream(s.graceCtx)
		if err != nil {
			// server (not gracefully) closed, close the connection immediately
			if s.closeCtx.Err() != nil {
				conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeNoError), "")
				handleErr = http.ErrServerClosed
				break
			}

			// gracefully closed, send GOAWAY frame and wait for requests to complete or grace period to end
			// new requests will be rejected and shouldn't be sent
			if s.graceCtx.Err() != nil {
				b = (&goAwayFrame{StreamID: nextStreamID}).Append(b[:0])
				// set a deadline to send the GOAWAY frame
				ctrlStr.SetWriteDeadline(time.Now().Add(goawayTimeout))
				ctrlStr.Write(b)

				select {
				case <-hconn.Context().Done():
					// we expect the client to eventually close the connection after receiving the GOAWAY
				case <-s.closeCtx.Done():
					// close the connection after graceful period
					conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeNoError), "")
				}
				handleErr = http.ErrServerClosed
				break
			}

			var appErr *quic.ApplicationError
			if !errors.As(err, &appErr) || appErr.ErrorCode != quic.ApplicationErrorCode(ErrCodeNoError) {
				handleErr = fmt.Errorf("accepting stream failed: %w", err)
			}
			break
		}

		nextStreamID = str.StreamID() + 4
		wg.Add(1)
		go func() {
			// handleRequest will return once the request has been handled,
			// or the underlying connection is closed
			defer wg.Done()
			s.handleRequest(hconn, str, datagrams, hconn.decoder)
		}()
	}
	wg.Wait()
	return handleErr
}

func (s *Server) maxHeaderBytes() uint64 {
	if s.MaxHeaderBytes <= 0 {
		return http.DefaultMaxHeaderBytes
	}
	return uint64(s.MaxHeaderBytes)
}

func (s *Server) handleRequest(conn *connection, str quic.Stream, datagrams *datagrammer, decoder *qpack.Decoder) {
	var ufh unknownFrameHandlerFunc
	if s.StreamHijacker != nil {
		ufh = func(ft FrameType, e error) (processed bool, err error) {
			return s.StreamHijacker(
				ft,
				conn.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID),
				str,
				e,
			)
		}
	}
	fp := &frameParser{conn: conn, r: str, unknownFrameHandler: ufh}
	frame, err := fp.ParseNext()
	if err != nil {
		if !errors.Is(err, errHijacked) {
			str.CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
			str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		}
		return
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "expected first frame to be a HEADERS frame")
		return
	}
	if hf.Length > s.maxHeaderBytes() {
		str.CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
		str.CancelWrite(quic.StreamErrorCode(ErrCodeFrameError))
		return
	}
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(str, headerBlock); err != nil {
		str.CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		return
	}
	hfs, err := decoder.DecodeFull(headerBlock)
	if err != nil {
		// TODO: use the right error code
		conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeGeneralProtocolError), "expected first frame to be a HEADERS frame")
		return
	}
	req, err := requestFromHeaders(hfs)
	if err != nil {
		str.CancelRead(quic.StreamErrorCode(ErrCodeMessageError))
		str.CancelWrite(quic.StreamErrorCode(ErrCodeMessageError))
		return
	}

	connState := conn.ConnectionState().TLS
	req.TLS = &connState
	req.RemoteAddr = conn.RemoteAddr().String()

	// Check that the client doesn't send more data in DATA frames than indicated by the Content-Length header (if set).
	// See section 4.1.2 of RFC 9114.
	contentLength := int64(-1)
	if _, ok := req.Header["Content-Length"]; ok && req.ContentLength >= 0 {
		contentLength = req.ContentLength
	}
	hstr := newStream(str, conn, datagrams, nil)
	body := newRequestBody(hstr, contentLength, conn.Context(), conn.ReceivedSettings(), conn.Settings)
	req.Body = body

	if s.Logger != nil {
		s.Logger.Debug("handling request", "method", req.Method, "host", req.Host, "uri", req.RequestURI)
	}

	ctx, cancel := context.WithCancel(conn.Context())
	req = req.WithContext(ctx)
	context.AfterFunc(str.Context(), cancel)

	r := newResponseWriter(hstr, conn, req.Method == http.MethodHead, s.Logger)
	handler := s.Handler
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
				logger := s.Logger
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

	// response not written to the client yet, set Content-Length
	if !r.headerWritten {
		if _, haveCL := r.header["Content-Length"]; !haveCL {
			r.header.Set("Content-Length", strconv.FormatInt(r.numWritten, 10))
		}
	}
	r.Flush()
	r.flushTrailers()

	// If the EOF was read by the handler, CancelRead() is a no-op.
	str.CancelRead(quic.StreamErrorCode(ErrCodeNoError))
	str.Close()
}

// Close the server immediately, aborting requests and sending CONNECTION_CLOSE frames to connected clients.
// Close in combination with ListenAndServe() (instead of Serve()) may race if it is called before a UDP socket is established.
// It is the caller's responsibility to close any connection passed to ServeQUICConn.
func (s *Server) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.closed = true
	// server is never used
	if s.closeCtx == nil {
		return nil
	}
	s.closeCancel()

	var err error
	for ln := range s.listeners {
		if cerr := (*ln).Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	if s.connCount.Load() == 0 {
		return err
	}
	// wait for all connections to be closed
	<-s.connHandlingDone
	return err
}

// Shutdown shuts down the server gracefully.
// The server sends a GOAWAY frame first, then or for all running requests to complete.
// Shutdown in combination with ListenAndServe() (instead of Serve()) may race if it is called before a UDP socket is established.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mutex.Lock()
	s.closed = true
	// server is never used
	if s.closeCtx == nil {
		s.mutex.Unlock()
		return nil
	}
	s.graceCancel()
	s.mutex.Unlock()

	if s.connCount.Load() == 0 {
		return s.Close()
	}
	select {
	case <-s.connHandlingDone: // all connections were closed
		// When receiving a GOAWAY frame, HTTP/3 clients are expected to close the connection
		// once all requests were successfully handled...
		return s.Close()
	case <-ctx.Done():
		// ... however, clients handling long-lived requests (and misbehaving clients),
		// might not do so before the context is cancelled.
		// In this case, we close the server, which closes all existing connections
		// (expect those passed to ServeQUICConn).
		_ = s.Close()
		return ctx.Err()
	}
}

// ErrNoAltSvcPort is the error returned by SetQUICHeaders when no port was found
// for Alt-Svc to announce. This can happen if listening on a PacketConn without a port
// (UNIX socket, for example) and no port is specified in Server.Port or Server.Addr.
var ErrNoAltSvcPort = errors.New("no port can be announced, specify it explicitly using Server.Port or Server.Addr")

// SetQUICHeaders can be used to set the proper headers that announce that this server supports HTTP/3.
// The values set by default advertise all the ports the server is listening on, but can be
// changed to a specific port by setting Server.Port before launching the server.
// If no listener's Addr().String() returns an address with a valid port, Server.Addr will be used
// to extract the port, if specified.
// For example, a server launched using ListenAndServe on an address with port 443 would set:
//
//	Alt-Svc: h3=":443"; ma=2592000
func (s *Server) SetQUICHeaders(hdr http.Header) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if s.altSvcHeader == "" {
		return ErrNoAltSvcPort
	}
	// use the map directly to avoid constant canonicalization since the key is already canonicalized
	hdr["Alt-Svc"] = append(hdr["Alt-Svc"], s.altSvcHeader)
	return nil
}

// ListenAndServeQUIC listens on the UDP network address addr and calls the
// handler for HTTP/3 requests on incoming connections. http.DefaultServeMux is
// used when handler is nil.
func ListenAndServeQUIC(addr, certFile, keyFile string, handler http.Handler) error {
	server := &Server{
		Addr:    addr,
		Handler: handler,
	}
	return server.ListenAndServeTLS(certFile, keyFile)
}

// ListenAndServeTLS listens on the given network address for both TLS/TCP and QUIC
// connections in parallel. It returns if one of the two returns an error.
// http.DefaultServeMux is used when handler is nil.
// The correct Alt-Svc headers for QUIC are set.
func ListenAndServeTLS(addr, certFile, keyFile string, handler http.Handler) error {
	// Load certs
	var err error
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.
	config := &tls.Config{
		Certificates: certs,
	}

	if addr == "" {
		addr = ":https"
	}

	// Open the listeners
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	if handler == nil {
		handler = http.DefaultServeMux
	}
	// Start the servers
	quicServer := &Server{
		TLSConfig: config,
		Handler:   handler,
	}

	hErr := make(chan error, 1)
	qErr := make(chan error, 1)
	go func() {
		hErr <- http.ListenAndServeTLS(addr, certFile, keyFile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			quicServer.SetQUICHeaders(w.Header())
			handler.ServeHTTP(w, r)
		}))
	}()
	go func() {
		qErr <- quicServer.Serve(udpConn)
	}()

	select {
	case err := <-hErr:
		quicServer.Close()
		return err
	case err := <-qErr:
		// Cannot close the HTTP server or wait for requests to complete properly :/
		return err
	}
}
