package dns

import (
	"io"
	"net"
	"sync/atomic"
	"time"
)

// A ResponseWriter interface is used by a DNS [Handler] to construct a DNS response. Note that a response
// writer may be used concurrently with TCP pipelining, so be aware that writes need to be atomic. If a write
// is attmpted an the Data buffer in the message is empty the write method will call [Pack].
//
// If a ResponseWriter also implements [ResponseController] a write deadline can be set, there is no default.
// The default ResponseWriter uses a timeout of 2s.
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
	// And the io.Closer interface, for use when hijacking a TCP connection.
	Close() error
	// Session returns the UDP oob session data to correctly route UDP packets.
	Session() *Session
	// Hijack lets the caller take over a TCP connection. For UDP this has no effect. The [Handler] is then
	// responsible for the connection. Packets will still be read and given to the handler, [MaxTCPQueries] will
	// be ignored, and the client needs to call [Close]. Use [Conn] to check the connection's state.
	Hijack()
}

// A ResponseController is used by an DNS handler to control the DNS response.
type ResponseController interface {
	SetWriteDeadline() error //  SetWriteDeadline sets the deadline for writing the response.
}

// response implements response.Writer. This struct is read-only execpt for hijacked.
type response struct {
	session  *Session // used for UDP reply routing.
	conn     net.Conn
	hijacked atomic.Bool
}

// SetWriteDeadline implements the [ResponseController] interface.
func (w *response) SetWriteDeadline() error {
	return w.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
}
func (w *response) Conn() net.Conn                    { return w.conn }
func (w *response) Session() *Session                 { return w.session }
func (w *response) Write(p []byte) (n int, err error) { return w.conn.Write(p) }
func (w *response) Read(p []byte) (n int, err error)  { return w.conn.Read(p) }
func (w *response) LocalAddr() net.Addr               { return w.conn.LocalAddr() }
func (w *response) Hijack()                           { w.hijacked.Store(true) }

// RemoteAddr implements the [ResponseWriter] interface.
func (w *response) RemoteAddr() net.Addr {
	if _, ok := w.conn.(*net.UDPConn); ok {
		return w.Session().Addr
	}
	return w.conn.RemoteAddr()
}

// Close implements the [ResponseWriter] interface. For UDP this is a noop.
func (w *response) Close() error {
	if _, ok := w.conn.(*net.UDPConn); ok {
		return nil
	}
	sock, ok := w.conn.(io.Closer)
	if !ok {
		return nil
	}
	return sock.Close()
}
