package dns

import (
	"crypto/tls"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// A ResponseWriter interface is used by an DNS handler to construct an DNS response. Note that a response
// writer may be used concurrently with TCP pipelining, so be aware that writes need to be atomic. If a write
// is attmpted an the Data buffer in the message is empty the write methods will call m.Pack().
//
// If a ResponseWriter also implements [ResponseController] a write deadline can be set, there is no default.
// The default ResponseWriter used a timeout 2s.
type ResponseWriter interface {
	// LocalAddr returns the net.Addr of the server.
	LocalAddr() net.Addr
	// RemoteAddr returns the net.Addr of the client that sent the current request.
	RemoteAddr() net.Addr
	// Conn returns the underlaying connection. You can get the connection's TLS state via
	// Conn().(*tls.Conn).ConnectionState().
	Conn() net.Conn
	// ResponseWriter must also implement the io.Writer interface.
	Write([]byte) (int, error)
	// And the io.Closer interface.
	Close() error
	// Session returns the UDP oob session data to correctly route UDP packets.
	Session() *Session
	// Hijack lets the caller take over the TCP connection. For UDP this has no effect. The handler is then
	// responsible for the connection. Packets will still be read and given to the handler, MaxTCPQueries will
	// be ignored, and the client needs to call Close. Use Conn to check the connection's state.
	Hijack()
}

// A ResponseController is used by an DNS handler to control the DNS response.
type ResponseController interface {
	//  SetWriteDeadline sets the deadline for writing the response.
	SetWriteDeadline() error
}

// response implements response.Writer. This struct is read-only execpt for hijacked.
type response struct {
	session  *Session // used for UDP reply routing.
	conn     net.Conn
	hijacked atomic.Bool
}

// SetWriteDeadline implements the ResponseController interface.
func (w *response) SetWriteDeadline() error {
	return w.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
}
func (w *response) Conn() net.Conn                    { return w.conn }
func (w *response) Session() *Session                 { return w.session }
func (w *response) Write(p []byte) (n int, err error) { return w.conn.Write(p) }
func (w *response) Read(p []byte) (n int, err error)  { return w.conn.Read(p) }

// LocalAddr implements the ResponseWriter.LocalAddr method.
func (w *response) LocalAddr() net.Addr {
	switch sock := w.conn.(type) {
	case *net.UDPConn:
		return sock.LocalAddr()
	case *net.TCPConn:
		return sock.LocalAddr()
	case *tls.Conn:
		return sock.LocalAddr()
	case *net.UnixConn:
		return sock.LocalAddr()
	default:
		panic("dns: internal error: no sock 🧦 in response")
	}
}

// RemoteAddr implements the ResponseWriter.RemoteAddr method.
func (w *response) RemoteAddr() net.Addr {
	if w.conn == nil {
		panic("dns: internal error, no writer in response")
	}
	switch sock := w.conn.(type) {
	case *net.UDPConn:
		return w.Session().Addr
	case *net.TCPConn:
		return sock.RemoteAddr()
	case *tls.Conn:
		return sock.RemoteAddr()
	case *net.UnixConn:
		return sock.RemoteAddr()
	default:
		panic("dns: internal error: no sock 🧦 in response")
	}
}

// Hijack implements the ResponseWriter.Hijack method.
func (w *response) Hijack() { w.hijacked.Store(true) }

func (w *response) Close() error {
	if sock, ok := w.conn.(io.Closer); ok {
		return sock.Close()
	}
	return nil
}
