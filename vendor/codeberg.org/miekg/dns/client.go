package dns

// A DNS client implementation, modelled after http.Client

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// A Client is a DNS client. It is safe to use a client from multiple goroutines. It supports TCP query
// pipelining and keeps track of in-flight requests on per ID, per connection basis. Use [Client.Err] to check
// if there are still messages in-flight.
type Client struct {
	*Transport // If Transport is nil it gets a [NewTransport].

	mu sync.Mutex

	// f tracks the ID we've have sent, but not seen a reply for.
	f map[local]struct{}
}

// local tracks the oustanding message ID *and* the local address.
type local struct {
	id   uint16
	addr net.Addr
}

// NewClient returns a client with the transport set to [NewTransport].
func NewClient() *Client {
	return &Client{Transport: NewTransport(), f: make(map[local]struct{})}
}

// add must called under a lock. It adds an outstanding request to track.
func (c *Client) inflight(id uint16, r ResponseWriter) {
	l := local{id, r.LocalAddr()} // use addr as-is, it is different for a conn.
	c.f[l] = struct{}{}
}

// done must called under a lock. It removes an outstanding request to track.
func (c *Client) done(id uint16, r ResponseWriter) bool {
	l := local{id, r.LocalAddr()}
	_, ok := c.f[l]
	if ok {
		delete(c.f, l)
	}
	return ok
}

// Err returns an error if there are still responses considered in-flight. After this call the internal cache
// is cleared.
func (c *Client) Err() error {
	ids := []uint16{}
	c.mu.Lock()
	for l := range c.f {
		ids = append(ids, l.id)
	}
	clear(c.f)
	c.mu.Unlock()
	if l := len(ids); l > 0 {
		return fmt.Errorf("%d in-flight requests remaining: %v", l, ids)
	}
	return nil
}

// Exchange performs a synchronous query over "network". It sends the message m to the address
// and waits for a reply. Exchange does not retry a failed query, nor
// will it fall back to TCP in case of truncation. If the Data buffer in m is empty, Exchange calls m.Pack().
//
// See [Client.Exchange] for more information on setting larger buffer sizes.
func Exchange(ctx context.Context, m *Msg, network, address string) (r *Msg, err error) {
	client := &Client{}
	r, _, err = client.Exchange(ctx, m, network, address)
	return r, err
}

// Exchange performs a synchronous query. It sends the message m to the address contained in a and waits for
// a reply. Basic use pattern with a *dns.Client:
//
//	c := new(dns.Client)
//	resp, rtt, err := c.Exchange(ctx, m, "udp", "127.0.0.1:53")
//
// If client does not have a transport set [NewTransport] is set and used. Exchange does not retry a failed query,
// nor will it fall back to TCP in case of truncation when UDP is used.
//
// If the TLS config is set in the transport a (TCP) connection with TLS is attempted.
//
// It is up to the caller to create a message that allows for larger responses to be returned. Specifically
// this means setting [Msg.UDPSize] that will advertise a larger buffer. Messages without a UDPSize will
// fall back to the historic limit of 512 octets (bytes).
//
// The full binary data is included in the (decoded) message as r.Data. If the Data buffer in m is empty
// client.Exchange calls m.Pack(), the buffer (in m) will be reset.
//
// An error is returned if:
//   - if the message returned does not have the same ID as the message sent.
//   - the response bit is not set on the reply.
//
// Use [Client.Err] to see if there are still outstanding queries in the in-flight cache.
//
// See [CompareName] for checking the question name the point to another possible check. See
// [codeberg.org/miekg/dns/dnsutil.Randomize] to randomize the question name.
func (c *Client) Exchange(ctx context.Context, m *Msg, network, address string) (r *Msg, rtt time.Duration, err error) {
	if c.Transport == nil {
		c.Transport = NewTransport()
	}
	if c.f == nil {
		c.f = make(map[local]struct{})
	}

	conn, err := c.dial(ctx, network, address)
	if err != nil {
		return nil, 0, err
	}
	if r, rtt, err = c.ExchangeWithConn(ctx, m, conn); err != nil {
		conn.Close()
		return r, rtt, err
	}
	conn.Close()
	return r, rtt, nil
}

// ExchangeWithConn behaves like [client.Exchange], but with a supplied connection. See [client.Err] how to
// check if all responses sent are received.
func (c *Client) ExchangeWithConn(ctx context.Context, m *Msg, conn net.Conn) (r *Msg, rtt time.Duration, err error) {
	if c.f == nil {
		c.f = make(map[local]struct{})
	}
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return nil, 0, err
		}
	}

	w := &response{conn: conn} // for Session() call in msg.go
	t := time.Now()

	_, err = io.Copy(w, m)
	if err != nil {
		return nil, time.Since(t), err
	}

	if err := ctx.Err(); err != nil {
		return nil, time.Since(t), err
	}

	c.mu.Lock()
	c.inflight(m.ID, w)
	c.mu.Unlock()

	r = &Msg{Data: m.Data}
	m.Data = m.Data[:0]
	if len(r.Data) < int(m.UDPSize) {
		r.Data = append(r.Data, make([]byte, (int(m.UDPSize)-len(r.Data)))...)
	}
	if len(r.Data) < MinMsgSize {
		r.Data = append(r.Data, make([]byte, MinMsgSize-len(r.Data))...)
	}

	conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	_, err = io.Copy(r, conn)
	if err != nil {
		// failed, remove m.ID from outstanding, we return an error anyway
		c.mu.Lock()
		c.done(m.ID, w)
		c.mu.Unlock()

		return nil, time.Since(t), err
	}

	if err := ctx.Err(); err != nil {
		// failed, remove m.ID from outstanding, we return an error anyway
		c.mu.Lock()
		c.done(m.ID, w)
		c.mu.Unlock()

		return nil, time.Since(t), err
	}

	if err = r.Unpack(); err != nil {
		// failed, remove m.ID from outstanding, we return an error anyway
		c.mu.Lock()
		c.done(m.ID, w)
		c.mu.Unlock()

		return r, time.Since(t), err
	}
	if !r.Response {
		// failed, remove m.ID from outstanding, we return an error anyway
		c.mu.Lock()
		c.done(m.ID, w)
		c.mu.Unlock()
		return r, time.Since(t), &Error{err: "response bit is not set"}
	}

	// Only here we check the ID from r, it should match.
	c.mu.Lock()
	ok := c.done(r.ID, w)
	c.mu.Unlock()

	if !ok {
		return r, time.Since(t), fmt.Errorf("%w: response ID %d does not match", ErrID, r.ID)
	}
	return r, time.Since(t), nil
}
