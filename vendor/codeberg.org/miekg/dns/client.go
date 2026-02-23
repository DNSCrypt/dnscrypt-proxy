package dns

// A DNS client implementation, modelled after http.Client

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// A Client is a DNS client. It is safe to use a client from multiple goroutines.
type Client struct {
	*Transport // If Transport is nil it gets a [NewTransport].

	*Transfer // If a transfer is attempted, this holds the optional signing settings.
}

// NewClient returns a client with the transport set to [NewTransport].
func NewClient() *Client {
	return &Client{Transport: NewTransport()}
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
// this means setting [Msg.Bufsize] that will advertise a larger buffer. Messages without an Bufsize will
// fall back to the historic limit of 512 octets (bytes).
//
// The full binary data is included in the (decoded) message as r.Data. If the Data buffer in m is empty
// client.Exchange calls m.Pack().
//
// An error is returned if:
//   - if the message returned does not have the same ID as the message sent.
//   - the response bit is not set on the reply.
//
// See [CompareName] for checking the question name the point to another possible check. See
// [codeberg.org/miekg/dns/dnsutil.Randomize] to randomize the question name.
func (c *Client) Exchange(ctx context.Context, m *Msg, network, address string) (r *Msg, rtt time.Duration, err error) {
	if c.Transport == nil {
		c.Transport = NewTransport()
	}

	conn, err := c.dial(ctx, network, address)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	return c.ExchangeWithConn(ctx, m, conn)
}

// ExchangeWithConn behaves like [client.Exchange], but with a supplied connection.
func (c *Client) ExchangeWithConn(ctx context.Context, m *Msg, conn net.Conn) (r *Msg, rtt time.Duration, err error) {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return nil, 0, err
		}
	}

	t := time.Now()
	remote := &response{conn: conn} // for Session() call in msg.go#L750
	if _, err := io.Copy(remote, m); err != nil {
		return nil, time.Since(t), err
	}

	if err := ctx.Err(); err != nil {
		return nil, time.Since(t), err
	}

	r = new(Msg)
	r.Data = m.Data
	if len(r.Data) < int(m.UDPSize) {
		r.Data = append(r.Data, make([]byte, (int(m.UDPSize)-len(r.Data)))...)
	}
	if len(r.Data) < MinMsgSize {
		r.Data = append(r.Data, make([]byte, MinMsgSize-len(r.Data))...)
	}

	conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	if _, err := io.Copy(r, conn); err != nil {
		return nil, time.Since(t), err
	}

	if err := ctx.Err(); err != nil {
		return nil, time.Since(t), err
	}

	if err = r.Unpack(); err != nil {
		return r, time.Since(t), err
	}
	if !r.Response {
		return r, time.Since(t), &Error{err: "response bit is not set"}
	}
	if r.ID != m.ID {
		return r, time.Since(t), fmt.Errorf("%w: %d != %d", ErrID, r.ID, m.ID)
	}

	return r, time.Since(t), nil
}
