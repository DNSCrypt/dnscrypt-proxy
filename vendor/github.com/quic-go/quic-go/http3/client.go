package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qtls"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/quic-go/qpack"
)

// MethodGet0RTT allows a GET request to be sent using 0-RTT.
// Note that 0-RTT data doesn't provide replay protection.
const MethodGet0RTT = "GET_0RTT"

const (
	defaultUserAgent              = "quic-go HTTP/3"
	defaultMaxResponseHeaderBytes = 10 * 1 << 20 // 10 MB
)

var defaultQuicConfig = &quic.Config{
	MaxIncomingStreams: -1, // don't allow the server to create bidirectional streams
	KeepAlivePeriod:    10 * time.Second,
	Versions:           []protocol.VersionNumber{protocol.VersionTLS},
}

type dialFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error)

var dialAddr = quic.DialAddrEarlyContext

type roundTripperOpts struct {
	DisableCompression bool
	EnableDatagram     bool
	MaxHeaderBytes     int64
	AdditionalSettings map[uint64]uint64
	StreamHijacker     func(FrameType, quic.Connection, quic.Stream, error) (hijacked bool, err error)
	UniStreamHijacker  func(StreamType, quic.Connection, quic.ReceiveStream, error) (hijacked bool)
}

// client is a HTTP3 client doing requests
type client struct {
	tlsConf *tls.Config
	config  *quic.Config
	opts    *roundTripperOpts

	dialOnce     sync.Once
	dialer       dialFunc
	handshakeErr error

	requestWriter *requestWriter

	decoder *qpack.Decoder

	hostname string
	conn     atomic.Pointer[quic.EarlyConnection]

	logger utils.Logger
}

var _ roundTripCloser = &client{}

func newClient(hostname string, tlsConf *tls.Config, opts *roundTripperOpts, conf *quic.Config, dialer dialFunc) (roundTripCloser, error) {
	if conf == nil {
		conf = defaultQuicConfig.Clone()
	} else if len(conf.Versions) == 0 {
		conf = conf.Clone()
		conf.Versions = []quic.VersionNumber{defaultQuicConfig.Versions[0]}
	}
	if len(conf.Versions) != 1 {
		return nil, errors.New("can only use a single QUIC version for dialing a HTTP/3 connection")
	}
	if conf.MaxIncomingStreams == 0 {
		conf.MaxIncomingStreams = -1 // don't allow any bidirectional streams
	}
	conf.EnableDatagrams = opts.EnableDatagram
	logger := utils.DefaultLogger.WithPrefix("h3 client")

	if tlsConf == nil {
		tlsConf = &tls.Config{}
	} else {
		tlsConf = tlsConf.Clone()
	}
	// Replace existing ALPNs by H3
	tlsConf.NextProtos = []string{versionToALPN(conf.Versions[0])}

	return &client{
		hostname:      authorityAddr("https", hostname),
		tlsConf:       tlsConf,
		requestWriter: newRequestWriter(logger),
		decoder:       qpack.NewDecoder(func(hf qpack.HeaderField) {}),
		config:        conf,
		opts:          opts,
		dialer:        dialer,
		logger:        logger,
	}, nil
}

func (c *client) dial(ctx context.Context) error {
	var err error
	var conn quic.EarlyConnection
	if c.dialer != nil {
		conn, err = c.dialer(ctx, c.hostname, c.tlsConf, c.config)
	} else {
		conn, err = dialAddr(ctx, c.hostname, c.tlsConf, c.config)
	}
	if err != nil {
		return err
	}
	c.conn.Store(&conn)

	// send the SETTINGs frame, using 0-RTT data, if possible
	go func() {
		if err := c.setupConn(conn); err != nil {
			c.logger.Debugf("Setting up connection failed: %s", err)
			conn.CloseWithError(quic.ApplicationErrorCode(errorInternalError), "")
		}
	}()

	if c.opts.StreamHijacker != nil {
		go c.handleBidirectionalStreams(conn)
	}
	go c.handleUnidirectionalStreams(conn)
	return nil
}

func (c *client) setupConn(conn quic.EarlyConnection) error {
	// open the control stream
	str, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
	b := make([]byte, 0, 64)
	b = quicvarint.Append(b, streamTypeControlStream)
	// send the SETTINGS frame
	b = (&settingsFrame{Datagram: c.opts.EnableDatagram, Other: c.opts.AdditionalSettings}).Append(b)
	_, err = str.Write(b)
	return err
}

func (c *client) handleBidirectionalStreams(conn quic.EarlyConnection) {
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			c.logger.Debugf("accepting bidirectional stream failed: %s", err)
			return
		}
		go func(str quic.Stream) {
			_, err := parseNextFrame(str, func(ft FrameType, e error) (processed bool, err error) {
				return c.opts.StreamHijacker(ft, conn, str, e)
			})
			if err == errHijacked {
				return
			}
			if err != nil {
				c.logger.Debugf("error handling stream: %s", err)
			}
			conn.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), "received HTTP/3 frame on bidirectional stream")
		}(str)
	}
}

func (c *client) handleUnidirectionalStreams(conn quic.EarlyConnection) {
	for {
		str, err := conn.AcceptUniStream(context.Background())
		if err != nil {
			c.logger.Debugf("accepting unidirectional stream failed: %s", err)
			return
		}

		go func(str quic.ReceiveStream) {
			streamType, err := quicvarint.Read(quicvarint.NewReader(str))
			if err != nil {
				if c.opts.UniStreamHijacker != nil && c.opts.UniStreamHijacker(StreamType(streamType), conn, str, err) {
					return
				}
				c.logger.Debugf("reading stream type on stream %d failed: %s", str.StreamID(), err)
				return
			}
			// We're only interested in the control stream here.
			switch streamType {
			case streamTypeControlStream:
			case streamTypeQPACKEncoderStream, streamTypeQPACKDecoderStream:
				// Our QPACK implementation doesn't use the dynamic table yet.
				// TODO: check that only one stream of each type is opened.
				return
			case streamTypePushStream:
				// We never increased the Push ID, so we don't expect any push streams.
				conn.CloseWithError(quic.ApplicationErrorCode(errorIDError), "")
				return
			default:
				if c.opts.UniStreamHijacker != nil && c.opts.UniStreamHijacker(StreamType(streamType), conn, str, nil) {
					return
				}
				str.CancelRead(quic.StreamErrorCode(errorStreamCreationError))
				return
			}
			f, err := parseNextFrame(str, nil)
			if err != nil {
				conn.CloseWithError(quic.ApplicationErrorCode(errorFrameError), "")
				return
			}
			sf, ok := f.(*settingsFrame)
			if !ok {
				conn.CloseWithError(quic.ApplicationErrorCode(errorMissingSettings), "")
				return
			}
			if !sf.Datagram {
				return
			}
			// If datagram support was enabled on our side as well as on the server side,
			// we can expect it to have been negotiated both on the transport and on the HTTP/3 layer.
			// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
			if c.opts.EnableDatagram && !conn.ConnectionState().SupportsDatagrams {
				conn.CloseWithError(quic.ApplicationErrorCode(errorSettingsError), "missing QUIC Datagram support")
			}
		}(str)
	}
}

func (c *client) Close() error {
	conn := c.conn.Load()
	if conn == nil {
		return nil
	}
	return (*conn).CloseWithError(quic.ApplicationErrorCode(errorNoError), "")
}

func (c *client) maxHeaderBytes() uint64 {
	if c.opts.MaxHeaderBytes <= 0 {
		return defaultMaxResponseHeaderBytes
	}
	return uint64(c.opts.MaxHeaderBytes)
}

// RoundTripOpt executes a request and returns a response
func (c *client) RoundTripOpt(req *http.Request, opt RoundTripOpt) (*http.Response, error) {
	if authorityAddr("https", hostnameFromRequest(req)) != c.hostname {
		return nil, fmt.Errorf("http3 client BUG: RoundTripOpt called for the wrong client (expected %s, got %s)", c.hostname, req.Host)
	}

	c.dialOnce.Do(func() {
		c.handshakeErr = c.dial(req.Context())
	})
	if c.handshakeErr != nil {
		return nil, c.handshakeErr
	}

	// At this point, c.conn is guaranteed to be set.
	conn := *c.conn.Load()

	// Immediately send out this request, if this is a 0-RTT request.
	if req.Method == MethodGet0RTT {
		req.Method = http.MethodGet
	} else {
		// wait for the handshake to complete
		select {
		case <-conn.HandshakeComplete().Done():
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	str, err := conn.OpenStreamSync(req.Context())
	if err != nil {
		return nil, err
	}

	// Request Cancellation:
	// This go routine keeps running even after RoundTripOpt() returns.
	// It is shut down when the application is done processing the body.
	reqDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-req.Context().Done():
			str.CancelWrite(quic.StreamErrorCode(errorRequestCanceled))
			str.CancelRead(quic.StreamErrorCode(errorRequestCanceled))
		case <-reqDone:
		}
	}()

	doneChan := reqDone
	if opt.DontCloseRequestStream {
		doneChan = nil
	}
	rsp, rerr := c.doRequest(req, conn, str, opt, doneChan)
	if rerr.err != nil { // if any error occurred
		close(reqDone)
		<-done
		if rerr.streamErr != 0 { // if it was a stream error
			str.CancelWrite(quic.StreamErrorCode(rerr.streamErr))
		}
		if rerr.connErr != 0 { // if it was a connection error
			var reason string
			if rerr.err != nil {
				reason = rerr.err.Error()
			}
			conn.CloseWithError(quic.ApplicationErrorCode(rerr.connErr), reason)
		}
		return nil, rerr.err
	}
	if opt.DontCloseRequestStream {
		close(reqDone)
		<-done
	}
	return rsp, rerr.err
}

func (c *client) sendRequestBody(str Stream, body io.ReadCloser) error {
	defer body.Close()
	b := make([]byte, bodyCopyBufferSize)
	for {
		n, rerr := body.Read(b)
		if n == 0 {
			if rerr == nil {
				continue
			}
			if rerr == io.EOF {
				break
			}
		}
		if _, err := str.Write(b[:n]); err != nil {
			return err
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			str.CancelWrite(quic.StreamErrorCode(errorRequestCanceled))
			return rerr
		}
	}
	return nil
}

func (c *client) doRequest(req *http.Request, conn quic.EarlyConnection, str quic.Stream, opt RoundTripOpt, reqDone chan<- struct{}) (*http.Response, requestError) {
	var requestGzip bool
	if !c.opts.DisableCompression && req.Method != "HEAD" && req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" {
		requestGzip = true
	}
	if err := c.requestWriter.WriteRequestHeader(str, req, requestGzip); err != nil {
		return nil, newStreamError(errorInternalError, err)
	}

	if req.Body == nil && !opt.DontCloseRequestStream {
		str.Close()
	}

	hstr := newStream(str, func() { conn.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), "") })
	if req.Body != nil {
		// send the request body asynchronously
		go func() {
			if err := c.sendRequestBody(hstr, req.Body); err != nil {
				c.logger.Errorf("Error writing request: %s", err)
			}
			if !opt.DontCloseRequestStream {
				hstr.Close()
			}
		}()
	}

	frame, err := parseNextFrame(str, nil)
	if err != nil {
		return nil, newStreamError(errorFrameError, err)
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		return nil, newConnError(errorFrameUnexpected, errors.New("expected first frame to be a HEADERS frame"))
	}
	if hf.Length > c.maxHeaderBytes() {
		return nil, newStreamError(errorFrameError, fmt.Errorf("HEADERS frame too large: %d bytes (max: %d)", hf.Length, c.maxHeaderBytes()))
	}
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(str, headerBlock); err != nil {
		return nil, newStreamError(errorRequestIncomplete, err)
	}
	hfs, err := c.decoder.DecodeFull(headerBlock)
	if err != nil {
		// TODO: use the right error code
		return nil, newConnError(errorGeneralProtocolError, err)
	}

	connState := qtls.ToTLSConnectionState(conn.ConnectionState().TLS)
	res := &http.Response{
		Proto:      "HTTP/3.0",
		ProtoMajor: 3,
		Header:     http.Header{},
		TLS:        &connState,
		Request:    req,
	}
	for _, hf := range hfs {
		switch hf.Name {
		case ":status":
			status, err := strconv.Atoi(hf.Value)
			if err != nil {
				return nil, newStreamError(errorGeneralProtocolError, errors.New("malformed non-numeric status pseudo header"))
			}
			res.StatusCode = status
			res.Status = hf.Value + " " + http.StatusText(status)
		default:
			res.Header.Add(hf.Name, hf.Value)
		}
	}
	respBody := newResponseBody(hstr, conn, reqDone)

	// Rules for when to set Content-Length are defined in https://tools.ietf.org/html/rfc7230#section-3.3.2.
	_, hasTransferEncoding := res.Header["Transfer-Encoding"]
	isInformational := res.StatusCode >= 100 && res.StatusCode < 200
	isNoContent := res.StatusCode == http.StatusNoContent
	isSuccessfulConnect := req.Method == http.MethodConnect && res.StatusCode >= 200 && res.StatusCode < 300
	if !hasTransferEncoding && !isInformational && !isNoContent && !isSuccessfulConnect {
		res.ContentLength = -1
		if clens, ok := res.Header["Content-Length"]; ok && len(clens) == 1 {
			if clen64, err := strconv.ParseInt(clens[0], 10, 64); err == nil {
				res.ContentLength = clen64
			}
		}
	}

	if requestGzip && res.Header.Get("Content-Encoding") == "gzip" {
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		res.Body = newGzipReader(respBody)
		res.Uncompressed = true
	} else {
		res.Body = respBody
	}

	return res, requestError{}
}

func (c *client) HandshakeComplete() bool {
	conn := c.conn.Load()
	if conn == nil {
		return false
	}
	select {
	case <-(*conn).HandshakeComplete().Done():
		return true
	default:
		return false
	}
}
