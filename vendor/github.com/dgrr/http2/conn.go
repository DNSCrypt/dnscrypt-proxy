package http2

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
)

// ConnOpts defines the connection options.
type ConnOpts struct {
	// PingInterval defines the interval in which the client will ping the server.
	//
	// An interval of <=0 will make the library to use DefaultPingInterval. Because ping intervals can't be disabled
	PingInterval time.Duration

	// DisablePingChecking ...
	DisablePingChecking bool

	// OnDisconnect is a callback that fires when the Conn disconnects.
	OnDisconnect func(c *Conn)
}

// Handshake performs an HTTP/2 handshake. That means, it will send
// the preface if `preface` is true, send a settings frame and a
// window update frame (for the connection's window).
// TODO: explain more
func Handshake(preface bool, bw *bufio.Writer, st *Settings, maxWin int32) error {
	if preface {
		err := WritePreface(bw)
		if err != nil {
			return err
		}
	}

	fr := AcquireFrameHeader()
	defer ReleaseFrameHeader(fr)

	// write the settings
	st2 := &Settings{}
	st.CopyTo(st2)

	fr.SetBody(st2)

	_, err := fr.WriteTo(bw)
	if err == nil {
		// then send a window update
		fr := AcquireFrameHeader()
		wu := AcquireFrame(FrameWindowUpdate).(*WindowUpdate)
		wu.SetIncrement(int(maxWin))

		fr.SetBody(wu)

		_, err = fr.WriteTo(bw)
		if err == nil {
			err = bw.Flush()
		}

		ReleaseFrameHeader(fr)
	}

	return err
}

// Conn represents a raw HTTP/2 connection over TLS + TCP.
type Conn struct {
	c net.Conn

	br *bufio.Reader
	bw *bufio.Writer

	enc *HPACK
	dec *HPACK

	nextID uint32

	serverWindow       int32
	serverStreamWindow int32

	maxWindow     int32
	currentWindow int32

	openStreams int32

	current Settings
	serverS Settings

	state    connState
	closeRef uint32

	reqQueued sync.Map

	in  chan *Ctx
	out chan *FrameHeader

	pingInterval time.Duration

	unacks      int
	disableAcks bool

	lastErr      error
	onDisconnect func(*Conn)

	closed uint64
}

// NewConn returns a new HTTP/2 connection.
// To start using the connection you need to call Handshake.
func NewConn(c net.Conn, opts ConnOpts) *Conn {
	nc := &Conn{
		c:             c,
		br:            bufio.NewReaderSize(c, 4096),
		bw:            bufio.NewWriterSize(c, maxFrameSize),
		enc:           AcquireHPACK(),
		dec:           AcquireHPACK(),
		nextID:        1,
		maxWindow:     1 << 20,
		currentWindow: 1 << 20,
		in:            make(chan *Ctx, 128),
		out:           make(chan *FrameHeader, 128),
		pingInterval:  opts.PingInterval,
		disableAcks:   opts.DisablePingChecking,
		onDisconnect:  opts.OnDisconnect,
	}

	nc.current.SetMaxWindowSize(1 << 20)
	nc.current.SetPush(false)

	return nc
}

// Dialer allows creating HTTP/2 connections by specifying an address and tls configuration.
type Dialer struct {
	// Addr is the server's address in the form: `host:port`.
	Addr string

	// TLSConfig is the tls configuration.
	//
	// If TLSConfig is nil, a default one will be defined on the Dial call.
	TLSConfig *tls.Config

	// PingInterval defines the interval in which the client will ping the server.
	//
	// An interval of 0 will make the library to use DefaultPingInterval. Because ping intervals can't be disabled.
	PingInterval time.Duration

	// NetDial defines the callback for establishing new connection to the host.
	// Default Dial is used if not set.
	NetDial fasthttp.DialFunc
}

func (d *Dialer) tryDial() (net.Conn, error) {
	if d.TLSConfig == nil || !func() bool {
		for _, proto := range d.TLSConfig.NextProtos {
			if proto == "h2" {
				return true
			}
		}

		return false
	}() {
		configureDialer(d)
	}

	var c net.Conn
	var err error

	if d.NetDial != nil {
		c, err = d.NetDial(d.Addr)
		if err != nil {
			return nil, err
		}
	} else {
		tcpAddr, err := net.ResolveTCPAddr("tcp", d.Addr)
		if err != nil {
			return nil, err
		}
		c, err = net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			return nil, err
		}
	}

	tlsConn := tls.Client(c, d.TLSConfig)

	if err := tlsConn.Handshake(); err != nil {
		_ = c.Close()
		return nil, err
	}

	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = c.Close()
		return nil, ErrServerSupport
	}

	return tlsConn, nil
}

// Dial creates an HTTP/2 connection or returns an error.
//
// An expected error is ErrServerSupport.
func (d *Dialer) Dial(opts ConnOpts) (*Conn, error) {
	c, err := d.tryDial()
	if err != nil {
		return nil, err
	}

	nc := NewConn(c, opts)

	err = nc.Handshake()
	return nc, err
}

// SetOnDisconnect sets the callback that will fire when the HTTP/2 connection is closed.
func (c *Conn) SetOnDisconnect(cb func(*Conn)) {
	c.onDisconnect = cb
}

// LastErr returns the last registered error in case the connection was closed by the server.
func (c *Conn) LastErr() error {
	return c.lastErr
}

// Handshake will perform the necessary handshake to establish the connection
// with the server. If an error is returned you can assume the TCP connection has been closed.
func (c *Conn) Handshake() error {
	err := c.doHandshake()
	if err == nil {
		go c.writeLoop()
		go c.readLoop()
	}

	return err
}

func (c *Conn) doHandshake() error {
	var err error

	if err = Handshake(true, c.bw, &c.current, c.maxWindow-65535); err != nil {
		_ = c.c.Close()
		return err
	}

	var fr *FrameHeader

	if fr, err = ReadFrameFrom(c.br); err == nil && fr.Type() != FrameSettings {
		_ = c.c.Close()
		return fmt.Errorf("unexpected frame, expected settings, got %s", fr.Type())
	} else if err == nil {
		st := fr.Body().(*Settings)
		if !st.IsAck() {
			st.CopyTo(&c.serverS)

			c.serverStreamWindow += int32(c.serverS.MaxWindowSize())
			if st.HeaderTableSize() <= defaultHeaderTableSize {
				c.enc.SetMaxTableSize(st.HeaderTableSize())
			}

			// reply back
			fr := AcquireFrameHeader()

			stRes := AcquireFrame(FrameSettings).(*Settings)
			stRes.SetAck(true)

			fr.SetBody(stRes)

			if _, err = fr.WriteTo(c.bw); err == nil {
				err = c.bw.Flush()
			}

			ReleaseFrameHeader(fr)
		}
	}

	if err != nil {
		_ = c.c.Close()
	} else {
		ReleaseFrameHeader(fr)
	}

	return err
}

// CanOpenStream returns whether the client will be able to open a new stream or not.
func (c *Conn) CanOpenStream() bool {
	return atomic.LoadInt32(&c.openStreams) < int32(c.serverS.maxStreams)
}

// Closed indicates whether the connection is closed or not.
func (c *Conn) Closed() bool {
	return atomic.LoadUint64(&c.closed) == 1
}

// Close closes the connection gracefully, sending a GoAway message
// and then closing the underlying TCP connection.
func (c *Conn) Close() error {
	if !atomic.CompareAndSwapUint64(&c.closed, 0, 1) {
		return io.EOF
	}

	close(c.in)

	fr := AcquireFrameHeader()
	defer ReleaseFrameHeader(fr)

	ga := AcquireFrame(FrameGoAway).(*GoAway)
	ga.SetStream(0)
	ga.SetCode(NoError)

	fr.SetBody(ga)

	_, err := fr.WriteTo(c.bw)
	if err == nil {
		err = c.bw.Flush()
	}

	_ = c.c.Close()

	if c.onDisconnect != nil {
		c.onDisconnect(c)
	}

	return err
}

// Write queues the request to be sent to the server.
//
// Check if `c` has been previously closed before accessing this function.
func (c *Conn) Write(r *Ctx) {
	c.in <- r
}

var ErrStreamNotReady = errors.New("stream hasn't been created")

// Cancel will try to cancel the request.
//
// Cancel can only return ErrStreamNotReady when the cancel is performed before the stream is created.
func (c *Conn) Cancel(ctx *Ctx) error {
	if atomic.LoadUint32(&ctx.streamID) == 0 {
		return ErrStreamNotReady
	}

	c.cancel(ctx)

	return nil
}

func (c *Conn) cancel(ctx *Ctx) {
	h := AcquireFrameHeader()
	h.SetStream( // TODO: use atomic here??
		atomic.LoadUint32(&ctx.streamID))

	fr := AcquireFrame(FrameResetStream).(*RstStream)
	fr.SetCode(StreamCanceled)

	h.SetBody(fr)

	c.out <- h
}

type WriteError struct {
	err error
}

func (we WriteError) Error() string {
	return fmt.Sprintf("writing error: %s", we.err)
}

func (we WriteError) Unwrap() error {
	return we.err
}

func (we WriteError) Is(target error) bool {
	return errors.Is(we.err, target)
}

func (we WriteError) As(target interface{}) bool {
	return errors.As(we.err, target)
}

func (c *Conn) writeLoop() {
	var lastErr error

	defer func() { _ = c.Close() }()

	defer func() {
		if err := recover(); err != nil {
			if lastErr == nil {
				switch errn := err.(type) {
				case error:
					lastErr = errn
				case string:
					lastErr = errors.New(errn)
				}
			}
		}

		if lastErr == nil {
			lastErr = io.ErrUnexpectedEOF
		}

		c.reqQueued.Range(func(_, v interface{}) bool {
			r := v.(*Ctx)
			r.resolve(lastErr)

			return true
		})
	}()

	if c.pingInterval <= 0 {
		c.pingInterval = DefaultPingInterval
	}

	ticker := time.NewTicker(c.pingInterval)
	defer ticker.Stop()

loop:
	for {
		select {
		case ctx, ok := <-c.in: // sending requests
			if !ok {
				break loop
			}

			err := c.writeRequest(ctx)
			if err != nil {
				ctx.resolve(err)

				if errors.Is(err, ErrNotAvailableStreams) {
					continue
				}

				lastErr = WriteError{err}

				break loop
			}
		case fr, ok := <-c.out: // generic output
			if !ok {
				break loop
			}

			err := c.writeFrame(fr)
			if err != nil {
				lastErr = WriteError{err}
				break loop
			}

			ReleaseFrameHeader(fr)
		case <-ticker.C: // ping
			if err := c.writePing(); err != nil {
				lastErr = WriteError{err}
				break loop
			}
		}

		if !c.disableAcks && c.unacks >= 3 {
			lastErr = ErrTimeout
			break loop
		}
	}
}

func (c *Conn) writeFrame(fr *FrameHeader) error {
	_, err := fr.WriteTo(c.bw)
	if err == nil {
		if err = c.bw.Flush(); err != nil {
			return err
		}
	}

	return err
}

func (c *Conn) finish(r *Ctx, stream uint32, err error) {
	atomic.AddInt32(&c.openStreams, -1)

	r.resolve(err)

	c.reqQueued.Delete(stream)
}

func (c *Conn) readLoop() {
	defer func() { _ = c.Close() }()

	for {
		fr, err := c.readNext()
		if err != nil {
			c.lastErr = err
			break
		}

		// TODO: panic otherwise?
		if ri, ok := c.reqQueued.Load(fr.Stream()); ok {
			r := ri.(*Ctx)

			err := c.readStream(fr, r.Response)
			if err == nil {
				if fr.Flags().Has(FlagEndStream) {
					c.finish(r, fr.Stream(), nil)
				}
			} else {
				c.finish(r, fr.Stream(), err)

				fmt.Fprintf(os.Stderr, "%s. payload=%v\n", err, fr.payload)

				if errors.Is(err, FlowControlError) {
					break
				}
			}

			if c.state == connStateClosed {
				if fr.Stream() == c.closeRef {
					break
				}
			}
		}

		ReleaseFrameHeader(fr)
	}
}

func (c *Conn) writeRequest(ctx *Ctx) error {
	if !c.CanOpenStream() {
		return ErrNotAvailableStreams
	}

	req := ctx.Request

	hasBody := len(req.Body()) != 0

	enc := c.enc

	id := c.nextID
	c.nextID += 2

	fr := AcquireFrameHeader()
	defer ReleaseFrameHeader(fr)

	fr.SetStream(id)

	h := AcquireFrame(FrameHeaders).(*Headers)
	fr.SetBody(h)

	hf := AcquireHeaderField()

	hf.SetBytes(StringAuthority, req.URI().Host())
	enc.AppendHeaderField(h, hf, true)

	hf.SetBytes(StringMethod, req.Header.Method())
	enc.AppendHeaderField(h, hf, true)

	hf.SetBytes(StringPath, req.URI().RequestURI())
	enc.AppendHeaderField(h, hf, true)

	hf.SetBytes(StringScheme, req.URI().Scheme())
	enc.AppendHeaderField(h, hf, true)

	hf.SetBytes(StringUserAgent, req.Header.UserAgent())
	enc.AppendHeaderField(h, hf, true)

	req.Header.VisitAll(func(k, v []byte) {
		if bytes.EqualFold(k, StringUserAgent) {
			return
		}

		hf.SetBytes(ToLower(k), v)
		enc.AppendHeaderField(h, hf, false)
	})

	h.SetPadding(false)
	h.SetEndStream(!hasBody)
	h.SetEndHeaders(true)

	// store the ctx before sending the request
	atomic.StoreUint32(&ctx.streamID, id)
	c.reqQueued.Store(id, ctx)

	_, err := fr.WriteTo(c.bw)
	if err == nil && hasBody {
		// release headers bc it's going to get replaced by the data frame
		ReleaseFrame(h)

		err = writeData(c.bw, fr, req.Body())
	}

	if err == nil {
		err = c.bw.Flush()
		if err == nil {
			atomic.AddInt32(&c.openStreams, 1)
		}
	}

	if err != nil {
		c.lastErr = err
		// if we had any error, remove it from the reqQueued.
		c.reqQueued.Delete(id)
	}

	ReleaseHeaderField(hf)

	return err
}

func writeData(bw *bufio.Writer, fh *FrameHeader, body []byte) (err error) {
	step := 1 << 14

	data := AcquireFrame(FrameData).(*Data)
	fh.SetBody(data)

	for i := 0; err == nil && i < len(body); i += step {
		if i+step >= len(body) {
			step = len(body) - i
		}

		data.SetEndStream(i+step == len(body))
		data.SetPadding(false)
		data.SetData(body[i : step+i])

		_, err = fh.WriteTo(bw)
	}

	return err
}

func (c *Conn) readNext() (fr *FrameHeader, err error) {
loop:
	for err == nil {
		fr, err = ReadFrameFrom(c.br)
		if err != nil {
			break
		}

		if fr.Stream() != 0 {
			break
		}

		switch fr.Type() {
		case FrameSettings:
			st := fr.Body().(*Settings)
			if !st.IsAck() { // if it has ack, just ignore
				c.handleSettings(st)
			}
		case FrameWindowUpdate:
			win := int32(fr.Body().(*WindowUpdate).Increment())

			atomic.AddInt32(&c.serverWindow, win)
		case FramePing:
			ping := fr.Body().(*Ping)
			if !ping.IsAck() {
				c.handlePing(ping)
			} else {
				c.unacks--
			}
		case FrameGoAway:
			ga := fr.Body().(*GoAway)
			if ga.stream == 0 {
				_ = c.c.Close()
				err = ga
			} else {
				// wait for the streams to complete
				c.closeRef = ga.stream
				c.state = connStateClosed
			}

			break loop
		}

		ReleaseFrameHeader(fr)
	}

	return
}

var ErrTimeout = errors.New("server is not replying to pings")

func (c *Conn) writePing() error {
	fr := AcquireFrameHeader()
	defer ReleaseFrameHeader(fr)

	ping := AcquireFrame(FramePing).(*Ping)
	ping.SetCurrentTime()

	fr.SetBody(ping)

	_, err := fr.WriteTo(c.bw)
	if err == nil {
		err = c.bw.Flush()
		if err == nil {
			c.unacks++
		}
	}

	return err
}

func (c *Conn) handleSettings(st *Settings) {
	st.CopyTo(&c.serverS)

	c.serverStreamWindow += int32(c.serverS.MaxWindowSize())
	c.enc.SetMaxTableSize(st.HeaderTableSize())

	// reply back
	fr := AcquireFrameHeader()

	stRes := AcquireFrame(FrameSettings).(*Settings)
	stRes.SetAck(true)

	fr.SetBody(stRes)

	c.out <- fr
}

func (c *Conn) handlePing(ping *Ping) {
	// reply back
	fr := AcquireFrameHeader()

	ping.SetAck(true)

	fr.SetBody(ping)

	c.out <- fr
}

func (c *Conn) readStream(fr *FrameHeader, res *fasthttp.Response) (err error) {
	switch fr.Type() {
	case FrameHeaders, FrameContinuation:
		h := fr.Body().(FrameWithHeaders)
		err = c.readHeader(h.Headers(), res)
	case FrameData:
		c.currentWindow -= int32(fr.Len())
		currentWin := c.currentWindow

		c.serverWindow -= int32(fr.Len())

		data := fr.Body().(*Data)
		if data.Len() != 0 {
			res.AppendBody(data.Data())

			// let's send the window update
			c.updateWindow(fr.Stream(), fr.Len())
		}

		if currentWin < c.maxWindow/2 {
			nValue := c.maxWindow - currentWin

			c.currentWindow = c.maxWindow

			c.updateWindow(0, int(nValue))
		}
	}

	return
}

func (c *Conn) updateWindow(streamID uint32, size int) {
	fr := AcquireFrameHeader()

	fr.SetStream(streamID)

	wu := AcquireFrame(FrameWindowUpdate).(*WindowUpdate)
	wu.SetIncrement(size)

	fr.SetBody(wu)

	c.out <- fr
}

func (c *Conn) readHeader(b []byte, res *fasthttp.Response) error {
	var err error
	hf := AcquireHeaderField()
	defer ReleaseHeaderField(hf)

	dec := c.dec

	for len(b) > 0 {
		b, err = dec.Next(hf, b)
		if err != nil {
			return err
		}

		if hf.IsPseudo() {
			if hf.KeyBytes()[1] == 's' { // status
				n, err := strconv.ParseInt(hf.Value(), 10, 64)
				if err != nil {
					return err
				}

				res.SetStatusCode(int(n))
				continue
			}
		}

		if bytes.Equal(hf.KeyBytes(), StringContentLength) {
			n, _ := strconv.Atoi(hf.Value())
			res.Header.SetContentLength(n)
		} else {
			res.Header.AddBytesKV(hf.KeyBytes(), hf.ValueBytes())
		}
	}

	return nil
}
