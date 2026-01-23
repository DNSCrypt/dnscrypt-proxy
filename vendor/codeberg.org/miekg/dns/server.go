package dns

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	"codeberg.org/miekg/dns/pkg/pool"
)

// Default maximum number of TCP queries before we close the socket.
const MaxTCPQueries = 1024

// ListenAndServe Starts a server on address and network specified and invokes handler for incoming queries.
func ListenAndServe(addr, network string, handler Handler) error {
	server := NewServer()
	server.Addr = addr
	server.Net = network
	server.Handler = handler
	return server.ListenAndServe()
}

// MsgAcceptAction represents the action to be taken.
type MsgAcceptAction int

// Allowed returned values from a MsgAcceptFunc.
const (
	MsgAccept               MsgAcceptAction = iota // Accept the message.
	MsgReject                                      // Reject the message with a RcodeFormatError.
	MsgRejectNotImplemented                        // Reject the message with a RcodeNotImplemented.
	MsgIgnore                                      // Ignore the message and send nothing back.
)

// MsgAcceptFunc is used early in the server code to accept or reject a message with RcodeFormatError.
// It returns a MsgAcceptAction to indicate what should happen with the message. Only the header of the
// message is unpacked when this function is called.
type MsgAcceptFunc func(m *Msg) MsgAcceptAction

// DefaultMsgAcceptFunc checks the request and will reject if:
//
//   - Isn't a request, returns [MsgIgnore].
//   - Has an opcode that isn't recognized, returns [MsgIgnore].
//   - Has more than a single "RR" in the question section, return [MsgReject].
func DefaultMsgAcceptFunc(m *Msg) MsgAcceptAction {
	// see dnshttp.DefaultMsgAcceptFunc where this code is duplicated.
	if m.Response {
		return MsgIgnore
	}
	if _, ok := OpcodeToString[m.Opcode]; !ok {
		return MsgRejectNotImplemented
	}
	if len(m.Question) != 1 {
		return MsgReject
	}
	return MsgAccept
}

// InvalidMsgFunc is a listener hook for observing incoming messages that were discarded
// because they could not be parsed or an earlier error in the server.
// Every message that is read by a Reader will eventually be provided to the Handler, or passed to this function.
type InvalidMsgFunc func(m *Msg, err error)

// DefaultMsgInvalidFunc is the default function used in case no InvalidMsgFunc is set. It is defined to be a noop.
func DefaultMsgInvalidFunc(m *Msg, err error) {}

// A Server defines parameters for running an DNS server.
type Server struct {
	// Address to listen on, ":domain" if empty.
	Addr string
	// If "tcp" it will invoke a TCP listener, otherwise an UDP one. If TLSConfig is not nil and Net is "tcp" a TLS server is
	// started.
	Net string
	// TCP Listener that is used. If Listener is set before Serve is called, its value will be used and no
	// new Listener will be created. Note in that case ListenFunc isn't ran either.
	Listener net.Listener
	// ListenFunc takes a *Server and modifies it. This function is called after the listener is set up, but
	// before it is used, as such this can be used to wrap the listeners.
	ListenFunc func(*Server)
	// TLS connection configuration. Use for DOT (DNS over TCP). Not NextProtos must have "dot", for this to
	// work with DOT clients. See [NextProtos].
	TLSConfig *tls.Config
	// UDP "Listener" that is used. If PacketConn is set before Serve is called, its value will be used a no
	// new PacketConn will be created. Note in that case ListenFunc isn't ran either.
	PacketConn net.PacketConn
	// Handler to invoke, dns.DefaultServeMux if nil.
	Handler Handler
	// Default buffer size to use to read incoming UDP messages. If not set it defaults to MinMsgSize (512 B).
	UDPSize int
	// The read timeout vaule for new connections, defaults to 2 * time.Second.
	ReadTimeout time.Duration
	// TCP idle timeout for multiple queries, if nil, defaults to 8 * time.Second (RFC 5966).
	IdleTimeout time.Duration
	// Maximum number of TCP queries before we close the socket. Default is [MaxTCPQueries], unlimited if -1.
	// See [ResponseWriter.Hijack] on how a handler can bypass this.
	MaxTCPQueries int

	// AcceptMsgFunc will check the incoming message and will reject it early in the process. Defaults to
	// [DefaultMsgAcceptFunc].
	MsgAcceptFunc MsgAcceptFunc
	// MsgInvalidFunc is optional, it will be called if a message is received but cannot be parsed.
	MsgInvalidFunc InvalidMsgFunc
	// If NotifyStartedFunc is set it is called once the server has started listening. Both NotifyStartedFunc
	// and NotifyStartedFunc get a copy of the server's context.
	NotifyStartedFunc func(context.Context)
	// If NotifyShutdownFunc is set is is called when a server shutdown is initiated. The server will wait for
	// this function to return before stopping the server.
	NotifyShutdownFunc func(context.Context)

	// MsgPool is the default [Pooler] used for allocation.
	MsgPool pool.Pooler

	ctx      context.Context // server wide context to signal shutdown to running handlers
	cancel   context.CancelFunc
	exited   chan struct{}
	shutdown chan bool

	once sync.Once

	// Whether to set the SO_REUSEPORT socket option, allowing multiple listeners to be bound to a single address.
	// It is only supported on certain GOOSes and when using ListenAndServe.
	ReusePort bool
	// Whether to set the SO_REUSEADDR socket option, allowing multiple listeners to be bound to a single address.
	// Crucially this allows binding when an existing server is listening on `0.0.0.0` or `::`.
	// It is only supported on certain GOOSes and when using ListenAndServe.
	ReuseAddr bool
}

// NewServer return a new server initialized with some defaults
func NewServer() *Server {
	srv := new(Server)
	srv.init()
	return srv
}

func (srv *Server) init() {
	if srv.UDPSize == 0 {
		srv.UDPSize = MinMsgSize
	}
	if srv.MsgInvalidFunc == nil {
		srv.MsgInvalidFunc = DefaultMsgInvalidFunc
	}
	if srv.MsgAcceptFunc == nil {
		srv.MsgAcceptFunc = DefaultMsgAcceptFunc
	}
	if srv.Handler == nil {
		srv.Handler = DefaultServeMux
	}
	if srv.ReadTimeout == 0 {
		srv.ReadTimeout = 2 * time.Second
	}
	if srv.IdleTimeout == 0 {
		srv.IdleTimeout = 8 * time.Second
	}
	if srv.MsgPool == nil {
		srv.MsgPool = pool.New(srv.UDPSize)
	}

	srv.ctx, srv.cancel = context.WithCancel(context.Background())
	srv.exited = make(chan struct{})
	srv.shutdown = make(chan bool)
}

// ListenAndServe starts a nameserver on the configured address in *Server. If TLS config is available a TLS
// listener will be started.
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":domain"
	}
	srv.init()

	if srv.Listener != nil {
		srv.listenTCP(srv.Listener)
		return nil
	}
	if srv.PacketConn != nil {
		srv.listenUDP(srv.PacketConn)
		return nil
	}

	switch srv.Net {
	case "tcp", "tcp4", "tcp6":
		l, err := listenTCP(srv.Net, addr, srv.ReusePort, srv.ReuseAddr)
		if err != nil {
			return err
		}
		if srv.TLSConfig != nil {
			l = tls.NewListener(l, srv.TLSConfig)
		}
		srv.Listener = l
		if srv.ListenFunc != nil {
			srv.ListenFunc(srv)
		}
		srv.listenTCP(l)
		return nil
	case "udp", "udp4", "udp6":
		l, err := listenUDP(srv.Net, addr, srv.ReusePort, srv.ReuseAddr)
		if err != nil {
			return err
		}
		u := l.(*net.UDPConn)
		if err := setUDPSocketOptions(u); err != nil {
			u.Close()
			return err
		}
		srv.PacketConn = l
		if srv.ListenFunc != nil {
			srv.ListenFunc(srv)
		}
		srv.listenUDP(u)
		return nil
	}
	return &Error{err: "bad network"}
}

// Shutdown shuts down a server. After a call to Shutdown, ListenAndServe will return.
// A context.Context may be passed to limit how long to wait for connections to terminate. Not used at the moment.
func (srv *Server) Shutdown(ctx context.Context) {
	srv.cancel()
	if srv.Listener != nil {
		srv.Listener.Close()
	}
	if srv.PacketConn != nil {
		srv.PacketConn.Close()
	}

	if f := srv.NotifyShutdownFunc; f != nil {
		f(srv.ctx)
	}

	close(srv.shutdown)
	<-srv.exited
}

// listenTCP starts a TCP listener for the server.
func (srv *Server) listenTCP(ln net.Listener) {
	if f := srv.NotifyStartedFunc; f != nil {
		f(srv.ctx)
	}
	var wg sync.WaitGroup

	for {
		select {
		case <-srv.shutdown:
			ln.Close()
			wg.Wait() // this has a data race because we slump &wg in the server... this _only_ this on shutdown though...
			srv.once.Do(func() { close(srv.exited) })
			return
		default:
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			go srv.serveTCP(&wg, conn)
		}
	}
}

// If this is a not a const, but var, or worse a field in [Server] it's about 10k qps *slower*.
// cd cmd/reflect; go test -v -count=1 # check the perf values, 15 does 360K on my M2 8-core with Asahi Linux

// BatchSize controls the maximum of packets we should read using recvmmsg(2), via ReadBatch, a tradeoff
// needs to be made with how much memory needs to be pre-allocated and how fast things should go. It is
// experimentally set to 20.
const BatchSize = 20

// Serve a new TCP connection. ServeUDP is split out in server_no_recvmmsg.go and server_recvmmsg.go.
func (srv *Server) serveTCP(wg *sync.WaitGroup, conn net.Conn) {
	w := &response{conn: conn}

	limit := srv.MaxTCPQueries
	if limit == 0 {
		limit = MaxTCPQueries
	}

	readtimeout := srv.ReadTimeout
	hijacked := false

	for q := 0; q < limit || limit == -1; q++ {
		conn.SetReadDeadline(time.Now().Add(readtimeout))

		r := &Msg{Data: srv.MsgPool.Get()}
		if _, err := r.ReadFrom(conn); err != nil {
			if isEOFOrClosedNetwork(err) {
				srv.MsgPool.Put(r.Data)
				break
			}
			srv.MsgInvalidFunc(r, err)
			srv.MsgPool.Put(r.Data)
			continue
		}

		wg.Add(1)
		go func() {
			srv.serveDNS(w, r)
			wg.Done()
		}()

		hijacked = hijacked || w.hijacked.Load()
		if hijacked {
			limit = -1 // when hijacked disregard any limits
		}
		// The first read uses the read timeout, the rest use the idle timeout.
		readtimeout = srv.IdleTimeout
	}

	if !hijacked {
		w.Close()
	}
}

// serveDNS serves the message it skip the message handling if the received message has the response bit set.
func (srv *Server) serveDNS(w *response, r *Msg) {
	r.msgPool = srv.MsgPool
	r.Options = MsgOptionUnpackQuestion

	if err := r.Unpack(); err != nil {
		srv.MsgInvalidFunc(r, err)
		return
	}

	switch action := srv.MsgAcceptFunc(r); action {
	case MsgIgnore:
		return

	case MsgReject, MsgRejectNotImplemented:
		r.Opcode = OpcodeQuery
		r.Rcode = RcodeFormatError
		if action == MsgRejectNotImplemented {
			r.Rcode = RcodeNotImplemented
		}
		r.Authoritative = false
		r.Response = true
		r.Zero = false
		r.Reset()
		r.Pack()

		io.Copy(w, r)
		return
	}

	r.Options = MsgOptionUnpack
	srv.Handler.ServeDNS(srv.ctx, w, r)
}

// NextProtos is the configuration a tls.Config must carry to be compatible with DNS over TLS (DOT).
var NextProtos = []string{"dot"}
