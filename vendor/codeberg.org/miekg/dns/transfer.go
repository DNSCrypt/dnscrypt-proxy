package dns

import (
	"context"
	"io"
	"net"
	"time"
)

// Envelope is used when doing a zone transfer with a remote server.
type Envelope struct {
	Answer []RR  // The RRs as returned by the remote server, or the ones to be send to the remote.
	Error  error // If something went wrong, this contains the error.
}

// TransferIn performs a zone transfer with address over network, the message m is used to ask for the transfer and
// should have an [AXFR] or [IXFR] RR in the question section.  For doing an IXFR a SOA record needs to be
// present in the [Ns] section of the [Msg], see RFC 1995.
//
// If the pseudo section contains a (stub) TSIG or in the future.
// SIG0 record, TSIG or SIG0 signing is performed, see [NewTSIG] and [NewSIG0] on how create such RRs. For
// this the client also need a [TSIGSigner] or [SIG0Signer].
//
// On the returned channel the received RRs are returned (and a non-nil erorr in case of an error). These RRs
// are as they were found, i.e. including the starting and ending SOA RRs.
//
// If m's buffer is empty TransferIn will call m.Pack(). If the clients's transport is nil [NewDefaultTransport] will
// be set and used.
//
// Setting up a transfer is done as follows:
//
//	c := dns.NewClient()
//	c.Transfer = &dns.Transfer{TSIGSigner: dns.HmacTSIG{[]byte("secret")}} // optionally set up TSIG with hmac
//	m := dns.NewMsg("example.org.", dns.TypeAXFR)
//	env, err := c.TransferIn(context.TODO(), m, "tcp", addr)
//	if err != nil {
//	   return fmt.Errorf("failed to setup zone transfer in", err)
//	}
//
//	for e := range env {
//		if e.Error != nil {
//			// ...
//		}
//		// do things with e.Answer
//	}
func (c *Client) TransferIn(ctx context.Context, m *Msg, network, address string) (<-chan *Envelope, error) {
	if c.Transport == nil {
		c.Transport = NewTransport()
	}
	conn, err := c.dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return c.TransferInWithConn(ctx, m, conn)
}

// TransferInWithConn behaves like [client.TransferIn], but with a supplied connection.
func (c *Client) TransferInWithConn(ctx context.Context, m *Msg, conn net.Conn) (<-chan *Envelope, error) {
	_, axfr := m.Question[0].(*AXFR)
	_, ixfr := m.Question[0].(*IXFR)
	if !axfr && !ixfr {
		return nil, &Error{"unsupported transfer type"}
	}
	if ixfr {
		if len(m.Ns) == 0 {
			return nil, ErrSOA.Fmt(": empty Ns")
		}
		if _, ok := m.Ns[0].(*SOA); !ok {
			return nil, ErrSOA.Fmt(": bad Ns")
		}
	}

	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return nil, err
		}
	}

	if c.Transfer != nil && c.TSIGSigner != nil && hasTSIG(m) != nil {
		if err := TSIGSign(m, c.TSIGSigner, &TSIGOption{}); err != nil {
			return nil, err
		}
	}
	// if.SIG0Signer != nil {} // TODO(miek): implement the whole SIG0 dance

	remote := &response{conn: conn} // for Session() call in msg.go#L926
	if _, err := io.Copy(remote, m); err != nil {
		return nil, err
	}

	ch := make(chan *Envelope)
	if axfr {
		go c.transferInAXFR(ctx, m, ch, conn)
	}
	if ixfr {
		go c.transferInIXFR(ctx, m, ch, conn)
	}
	return ch, nil
}

func (c *Client) transferInAXFR(ctx context.Context, m *Msg, ch chan<- *Envelope, conn net.Conn) {
	defer func() {
		// First close the connection, then the channel. This allows functions blocked on the channel to
		// assume that the connection is closed and no further operations are pending when they resume.
		conn.Close()
		close(ch)
	}()

	options := TSIGOption{}
	t := hasTSIG(m)
	if t != nil {
		options.RequestMAC = t.MAC
	}

	r := &Msg{}
	for {
		r.Options = MsgOptionUnpackHeader
		conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
		if _, err := io.Copy(r, conn); err != nil {
			// the response writer or actual conn is closed, just return, or some other error, we may
			// not be sure someone is still listening on this channel.
			return
		}
		if err := ctx.Err(); err != nil {
			ch <- &Envelope{Error: err}
			return
		}

		if err := r.Unpack(); err != nil {
			ch <- &Envelope{Error: err}
			return
		}

		if m.ID != r.ID {
			ch <- &Envelope{Error: ErrID.Fmt(": %d != %d", m.ID, r.ID)}
			return
		}

		if r.Rcode != RcodeSuccess {
			ch <- &Envelope{Error: ErrRcode.Fmt(": %s", rcodeToString(r.Rcode))}
			return
		}

		r.Options = MsgOptionUnpack
		err := r.Unpack()
		if err != nil {
			ch <- &Envelope{Answer: r.Answer, Error: err}
		}

		// On first loop first be need to see a SOA RR.
		if !options.TimersOnly {
			if len(r.Answer) == 0 {
				ch <- &Envelope{Error: ErrSOA.Fmt(": empty answer")}
				return
			}
			if _, ok := r.Answer[0].(*SOA); !ok {
				ch <- &Envelope{Error: ErrSOA}
				return
			}
		}

		if c.Transfer != nil && c.TSIGSigner != nil && t != nil { // original request had tsig, so we need to check that.
			if err := TSIGVerify(r, c.TSIGSigner, &options); err != nil {
				ch <- &Envelope{Answer: r.Answer, Error: err}
			}
		}

		ch <- &Envelope{Answer: r.Answer}

		// If there is a SOA RR as the last we're done
		if options.TimersOnly {
			if len(r.Answer) > 0 {
				if _, ok := r.Answer[len(r.Answer)-1].(*SOA); ok {
					return
				}
			}
		}

		options.TimersOnly = true
		if t != nil {
			// r must have tsig, otherwise errored out above
			options.RequestMAC = hasTSIG(r).MAC
		}
	}
}

// ixfr is similar, but different enough to warrant its own function. Doing this in the axfr-loop is possible,
// but make that more brittle. Although ifxr also needs to support axfr...
func (c *Client) transferInIXFR(ctx context.Context, m *Msg, ch chan<- *Envelope, conn net.Conn) {
	defer func() {
		conn.Close()
		close(ch)
	}()

	options := TSIGOption{}
	t := hasTSIG(m)
	if t != nil {
		options.RequestMAC = t.MAC
	}
	// serial is the serial of the first SOA, it used to determine when we seen all the RRs.
	serial := uint32(0)
	// assume incremental transfer, which implies seeing the 2n SOA with serial 'serial',
	expectSOA := 1 // we ignore the first one and assume we get an axfr instead of ixfr, if the first msg indicates we do ifxr with +1 this.

	r := &Msg{}
	for {
		r.Options = MsgOptionUnpackHeader
		conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
		if _, err := io.Copy(r, conn); err != nil {
			return
		}
		if err := ctx.Err(); err != nil {
			ch <- &Envelope{Error: err}
			return
		}

		if err := r.Unpack(); err != nil {
			ch <- &Envelope{Error: err}
			return
		}

		if m.ID != r.ID {
			ch <- &Envelope{Error: ErrID.Fmt(": %d != %d", m.ID, r.ID)}
			return
		}

		if r.Rcode != RcodeSuccess {
			ch <- &Envelope{Error: ErrRcode.Fmt(": %s", rcodeToString(r.Rcode))}
			return
		}

		r.Options = MsgOptionUnpack
		err := r.Unpack()
		if err != nil {
			ch <- &Envelope{Answer: r.Answer, Error: err}
		}

		// On first loop first be need to see a SOA RR and check that with the request serial.
		if !options.TimersOnly {
			if len(r.Answer) == 0 {
				ch <- &Envelope{Error: ErrSOA.Fmt(": empty answer")}
				return
			}
			if _, ok := r.Answer[0].(*SOA); !ok {
				ch <- &Envelope{Error: ErrSOA}
				return
			}
			serial := r.Answer[0].(*SOA).Serial
			// If we requested a higher serial, we are already up to date.
			if r.Ns[0].(*SOA).Serial < serial { // TODO(miek): serial arithmetic
				ch <- &Envelope{Answer: r.Answer}
				return
			}
			if len(r.Answer) > 2 {
				if _, ok := r.Ns[1].(*SOA); ok {
					expectSOA++
				}
			}
		}

		if c.Transfer != nil && c.TSIGSigner != nil && t != nil { // original request had tsig, so we need to check that.
			if err := TSIGVerify(r, c.TSIGSigner, &options); err != nil {
				ch <- &Envelope{Answer: r.Answer, Error: err}
			}
		}

		ch <- &Envelope{Answer: r.Answer}

		// If we see the first SOA's serial expectSOA times we need to stop.
		if options.TimersOnly {
			for _, rr := range r.Answer {
				if s, ok := rr.(*SOA); ok && s.Serial == serial {
					expectSOA--
					if expectSOA == 0 {
						ch <- &Envelope{r.Answer, nil}
						return
					}
				}
			}
		}

		options.TimersOnly = true
		if t != nil {
			// r must have tsig, otherwise errored out above
			options.RequestMAC = hasTSIG(r).MAC
		}
	}
}

// TransferOut performs an outgoing transfer with the client connecting in w, r is the request
// that initiates the transfer and is used for TSIG/SIG0.
//
// Example setup from within a dns.HandleFunc:
//
//	r.Unpack()
//	w.Hijack() // hijack the connection as we should close when done
//	env := make(chan *dns.Envelope)
//	c := dns.NewClient()
//	var wg sync.WaitGroup
//	wg.Go(func() {
//	    c.TransferOut(w, r, env)
//	    w.Close()
//	})
//	env <- &dns.Envelope{Answer: []dns.RR{...}}
//	close(env)
//
// The server is responsible for sending the correct sequence of RRs through the channel env.
// If the clients's transport is nil [NewDefaultTransport] will be set and used.
func (c *Client) TransferOut(w ResponseWriter, r *Msg, env <-chan *Envelope) (err error) {
	if c.Transport == nil {
		c.Transport = NewTransport()
	}
	defer func() {
		// drain channel reads
		for range env {
		}
	}()

	options := TSIGOption{}
	t := hasTSIG(r)
	if t != nil {
		options.RequestMAC = t.MAC
	}
	for e := range env {
		m := new(Msg) // TODO(miek): Msg can be lifted out of for loop?
		m.Authoritative = true

		// dnsutil.SetReply as used here, but led to all kinds of cyclic imports, just use that very static code here.
		m.ID, m.Rcode = r.ID, RcodeSuccess
		m.Response, m.Opcode = true, r.Opcode
		m.RecursionDesired = r.RecursionDesired
		m.CheckingDisabled = r.CheckingDisabled
		m.Security = r.Security
		m.Question = r.Question
		m.Answer, m.Ns, m.Extra, m.Pseudo = nil, nil, nil, nil

		m.Answer = e.Answer
		if t != nil {
			m.Pseudo = []RR{t} // will overwrite the bits that matter
		}
		if err = m.Pack(); err != nil {
			return err
		}
		if c.Transfer != nil && c.TSIGSigner != nil && t != nil {
			if err = TSIGSign(m, c.TSIGSigner, &options); err != nil {
				return err
			}
		}

		if _, err = io.Copy(w, m); err != nil {
			return err
		}

		options.TimersOnly = true
		if t != nil {
			// m must have tsig, otherwise errored out above
			options.RequestMAC = hasTSIG(m).MAC
		}
	}
	return nil
}
