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
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/net/http/httpguts"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
)

// Settings are HTTP/3 settings that apply to the underlying connection.
type Settings struct {
	// Support for HTTP/3 datagrams (RFC 9297)
	EnableDatagrams bool
	// Extended CONNECT, RFC 9220
	EnableExtendedConnect bool
	// Other settings, defined by the application
	Other map[uint64]uint64
}

// RoundTripOpt are options for the Transport.RoundTripOpt method.
type RoundTripOpt struct {
	// OnlyCachedConn controls whether the Transport may create a new QUIC connection.
	// If set true and no cached connection is available, RoundTripOpt will return ErrNoCachedConn.
	OnlyCachedConn bool
}

type singleRoundTripper interface {
	OpenRequestStream(context.Context) (RequestStream, error)
	RoundTrip(*http.Request) (*http.Response, error)
}

type roundTripperWithCount struct {
	cancel  context.CancelFunc
	dialing chan struct{} // closed as soon as quic.Dial(Early) returned
	dialErr error
	conn    quic.EarlyConnection
	rt      singleRoundTripper

	useCount atomic.Int64
}

func (r *roundTripperWithCount) Close() error {
	r.cancel()
	<-r.dialing
	if r.conn != nil {
		return r.conn.CloseWithError(0, "")
	}
	return nil
}

// Transport implements the http.RoundTripper interface
type Transport struct {
	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client. If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	// QUICConfig is the quic.Config used for dialing new connections.
	// If nil, reasonable default values will be used.
	QUICConfig *quic.Config

	// Dial specifies an optional dial function for creating QUIC
	// connections for requests.
	// If Dial is nil, a UDPConn will be created at the first request
	// and will be reused for subsequent connections to other servers.
	Dial func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error)

	// Enable support for HTTP/3 datagrams (RFC 9297).
	// If a QUICConfig is set, datagram support also needs to be enabled on the QUIC layer by setting EnableDatagrams.
	EnableDatagrams bool

	// Additional HTTP/3 settings.
	// It is invalid to specify any settings defined by RFC 9114 (HTTP/3) and RFC 9297 (HTTP Datagrams).
	AdditionalSettings map[uint64]uint64

	// MaxResponseHeaderBytes specifies a limit on how many response bytes are
	// allowed in the server's response header.
	// Zero means to use a default limit.
	MaxResponseHeaderBytes int64

	// DisableCompression, if true, prevents the Transport from requesting compression with an
	// "Accept-Encoding: gzip" request header when the Request contains no existing Accept-Encoding value.
	// If the Transport requests gzip on its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body.
	// However, if the user explicitly requested gzip it is not automatically uncompressed.
	DisableCompression bool

	StreamHijacker    func(FrameType, quic.ConnectionTracingID, quic.Stream, error) (hijacked bool, err error)
	UniStreamHijacker func(StreamType, quic.ConnectionTracingID, quic.ReceiveStream, error) (hijacked bool)

	Logger *slog.Logger

	mutex sync.Mutex

	initOnce sync.Once
	initErr  error

	newClient func(quic.EarlyConnection) singleRoundTripper

	clients   map[string]*roundTripperWithCount
	transport *quic.Transport
}

var (
	_ http.RoundTripper = &Transport{}
	_ io.Closer         = &Transport{}
)

// Deprecated: RoundTripper was renamed to Transport.
type RoundTripper = Transport

// ErrNoCachedConn is returned when Transport.OnlyCachedConn is set
var ErrNoCachedConn = errors.New("http3: no cached connection was available")

func (t *Transport) init() error {
	if t.newClient == nil {
		t.newClient = func(conn quic.EarlyConnection) singleRoundTripper {
			return newClientConn(
				conn,
				t.EnableDatagrams,
				t.AdditionalSettings,
				t.StreamHijacker,
				t.UniStreamHijacker,
				t.MaxResponseHeaderBytes,
				t.DisableCompression,
				t.Logger,
			)
		}
	}
	if t.QUICConfig == nil {
		t.QUICConfig = defaultQuicConfig.Clone()
		t.QUICConfig.EnableDatagrams = t.EnableDatagrams
	}
	if t.EnableDatagrams && !t.QUICConfig.EnableDatagrams {
		return errors.New("HTTP Datagrams enabled, but QUIC Datagrams disabled")
	}
	if len(t.QUICConfig.Versions) == 0 {
		t.QUICConfig = t.QUICConfig.Clone()
		t.QUICConfig.Versions = []quic.Version{protocol.SupportedVersions[0]}
	}
	if len(t.QUICConfig.Versions) != 1 {
		return errors.New("can only use a single QUIC version for dialing a HTTP/3 connection")
	}
	if t.QUICConfig.MaxIncomingStreams == 0 {
		t.QUICConfig.MaxIncomingStreams = -1 // don't allow any bidirectional streams
	}
	return nil
}

// RoundTripOpt is like RoundTrip, but takes options.
func (t *Transport) RoundTripOpt(req *http.Request, opt RoundTripOpt) (*http.Response, error) {
	t.initOnce.Do(func() { t.initErr = t.init() })
	if t.initErr != nil {
		return nil, t.initErr
	}

	if req.URL == nil {
		closeRequestBody(req)
		return nil, errors.New("http3: nil Request.URL")
	}
	if req.URL.Scheme != "https" {
		closeRequestBody(req)
		return nil, fmt.Errorf("http3: unsupported protocol scheme: %s", req.URL.Scheme)
	}
	if req.URL.Host == "" {
		closeRequestBody(req)
		return nil, errors.New("http3: no Host in request URL")
	}
	if req.Header == nil {
		closeRequestBody(req)
		return nil, errors.New("http3: nil Request.Header")
	}
	for k, vv := range req.Header {
		if !httpguts.ValidHeaderFieldName(k) {
			return nil, fmt.Errorf("http3: invalid http header field name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, fmt.Errorf("http3: invalid http header field value %q for key %v", v, k)
			}
		}
	}

	if req.Method != "" && !validMethod(req.Method) {
		closeRequestBody(req)
		return nil, fmt.Errorf("http3: invalid method %q", req.Method)
	}

	hostname := authorityAddr(hostnameFromURL(req.URL))
	cl, isReused, err := t.getClient(req.Context(), hostname, opt.OnlyCachedConn)
	if err != nil {
		return nil, err
	}

	select {
	case <-cl.dialing:
	case <-req.Context().Done():
		return nil, context.Cause(req.Context())
	}

	if cl.dialErr != nil {
		t.removeClient(hostname)
		return nil, cl.dialErr
	}
	defer cl.useCount.Add(-1)
	rsp, err := cl.rt.RoundTrip(req)
	if err != nil {
		// non-nil errors on roundtrip are likely due to a problem with the connection
		// so we remove the client from the cache so that subsequent trips reconnect
		// context cancelation is excluded as is does not signify a connection error
		if !errors.Is(err, context.Canceled) {
			t.removeClient(hostname)
		}

		if isReused {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				return t.RoundTripOpt(req, opt)
			}
		}
	}
	return rsp, err
}

// RoundTrip does a round trip.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.RoundTripOpt(req, RoundTripOpt{})
}

func (t *Transport) getClient(ctx context.Context, hostname string, onlyCached bool) (rtc *roundTripperWithCount, isReused bool, err error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.clients == nil {
		t.clients = make(map[string]*roundTripperWithCount)
	}

	cl, ok := t.clients[hostname]
	if !ok {
		if onlyCached {
			return nil, false, ErrNoCachedConn
		}
		ctx, cancel := context.WithCancel(ctx)
		cl = &roundTripperWithCount{
			dialing: make(chan struct{}),
			cancel:  cancel,
		}
		go func() {
			defer close(cl.dialing)
			defer cancel()
			conn, rt, err := t.dial(ctx, hostname)
			if err != nil {
				cl.dialErr = err
				return
			}
			cl.conn = conn
			cl.rt = rt
		}()
		t.clients[hostname] = cl
	}
	select {
	case <-cl.dialing:
		if cl.dialErr != nil {
			delete(t.clients, hostname)
			return nil, false, cl.dialErr
		}
		select {
		case <-cl.conn.HandshakeComplete():
			isReused = true
		default:
		}
	default:
	}
	cl.useCount.Add(1)
	return cl, isReused, nil
}

func (t *Transport) dial(ctx context.Context, hostname string) (quic.EarlyConnection, singleRoundTripper, error) {
	var tlsConf *tls.Config
	if t.TLSClientConfig == nil {
		tlsConf = &tls.Config{}
	} else {
		tlsConf = t.TLSClientConfig.Clone()
	}
	if tlsConf.ServerName == "" {
		sni, _, err := net.SplitHostPort(hostname)
		if err != nil {
			// It's ok if net.SplitHostPort returns an error - it could be a hostname/IP address without a port.
			sni = hostname
		}
		tlsConf.ServerName = sni
	}
	// Replace existing ALPNs by H3
	tlsConf.NextProtos = []string{versionToALPN(t.QUICConfig.Versions[0])}

	dial := t.Dial
	if dial == nil {
		if t.transport == nil {
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, nil, err
			}
			t.transport = &quic.Transport{Conn: udpConn}
		}
		dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			return t.transport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
		}
	}

	conn, err := dial(ctx, hostname, tlsConf, t.QUICConfig)
	if err != nil {
		return nil, nil, err
	}
	return conn, t.newClient(conn), nil
}

func (t *Transport) removeClient(hostname string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	if t.clients == nil {
		return
	}
	delete(t.clients, hostname)
}

// NewClientConn creates a new HTTP/3 client connection on top of a QUIC connection.
// Most users should use RoundTrip instead of creating a connection directly.
// Specifically, it is not needed to perform GET, POST, HEAD and CONNECT requests.
//
// Obtaining a ClientConn is only needed for more advanced use cases, such as
// using Extended CONNECT for WebTransport or the various MASQUE protocols.
func (t *Transport) NewClientConn(conn quic.Connection) *ClientConn {
	return newClientConn(
		conn,
		t.EnableDatagrams,
		t.AdditionalSettings,
		t.StreamHijacker,
		t.UniStreamHijacker,
		t.MaxResponseHeaderBytes,
		t.DisableCompression,
		t.Logger,
	)
}

// Close closes the QUIC connections that this Transport has used.
func (t *Transport) Close() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	for _, cl := range t.clients {
		if err := cl.Close(); err != nil {
			return err
		}
	}
	t.clients = nil
	if t.transport != nil {
		if err := t.transport.Close(); err != nil {
			return err
		}
		if err := t.transport.Conn.Close(); err != nil {
			return err
		}
		t.transport = nil
	}
	return nil
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}

func validMethod(method string) bool {
	/*
				     Method         = "OPTIONS"                ; Section 9.2
		   		                    | "GET"                    ; Section 9.3
		   		                    | "HEAD"                   ; Section 9.4
		   		                    | "POST"                   ; Section 9.5
		   		                    | "PUT"                    ; Section 9.6
		   		                    | "DELETE"                 ; Section 9.7
		   		                    | "TRACE"                  ; Section 9.8
		   		                    | "CONNECT"                ; Section 9.9
		   		                    | extension-method
		   		   extension-method = token
		   		     token          = 1*<any CHAR except CTLs or separators>
	*/
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

// copied from net/http/http.go
func isNotToken(r rune) bool {
	return !httpguts.IsTokenRune(r)
}

// CloseIdleConnections closes any QUIC connections in the transport's pool that are currently idle.
// An idle connection is one that was previously used for requests but is now sitting unused.
// This method does not interrupt any connections currently in use.
// It also does not affect connections obtained via NewClientConn.
func (t *Transport) CloseIdleConnections() {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	for hostname, cl := range t.clients {
		if cl.useCount.Load() == 0 {
			cl.Close()
			delete(t.clients, hostname)
		}
	}
}
