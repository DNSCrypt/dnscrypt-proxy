package http2

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/valyala/fasthttp"
)

// ErrServerSupport indicates whether the server supports HTTP/2 or not.
var ErrServerSupport = errors.New("server doesn't support HTTP/2")

func configureDialer(d *Dialer) {
	if d.TLSConfig == nil {
		d.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		}
	}

	tlsConfig := d.TLSConfig

	emptyServerName := tlsConfig.ServerName == ""
	if emptyServerName {
		host, _, err := net.SplitHostPort(d.Addr)
		if err != nil {
			host = d.Addr
		}

		tlsConfig.ServerName = host
	}

	tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
}

// ConfigureClient configures the fasthttp.HostClient to run over HTTP/2.
func ConfigureClient(c *fasthttp.HostClient, opts ClientOpts) error {
	emptyServerName := c.TLSConfig != nil && c.TLSConfig.ServerName == ""

	d := &Dialer{
		Addr:      c.Addr,
		TLSConfig: c.TLSConfig,
		NetDial:   c.Dial,
	}

	cl := createClient(d, opts)
	cl.conns.Init()

	_, _, err := cl.createConn()
	if err != nil {
		if errors.Is(err, ErrServerSupport) && c.TLSConfig != nil { // remove added config settings
			for i := range c.TLSConfig.NextProtos {
				if c.TLSConfig.NextProtos[i] == "h2" {
					c.TLSConfig.NextProtos = append(c.TLSConfig.NextProtos[:i], c.TLSConfig.NextProtos[i+1:]...)
				}
			}

			if emptyServerName {
				c.TLSConfig.ServerName = ""
			}
		}

		return err
	}

	c.IsTLS = true
	c.TLSConfig = d.TLSConfig

	c.Transport = cl.Do

	return nil
}

// ConfigureServer configures the fasthttp server to handle
// HTTP/2 connections. The HTTP/2 connection can be only
// established if the fasthttp server is using TLS.
//
// Future implementations may support HTTP/2 through plain TCP.
//
// This package currently supports the following fasthttp.Server settings:
// - Handler: Obviously, the handler is taken from the Server.
// - ReadTimeout: Will cancel a stream if the client takes more than ReadTimeout
//   to send a request. This option NEVER closes the connection.
// - IdleTimeout: Will close the connection if the client doesn't send a request
//   within the IdleTimeout. This option ignores any PING/PONG mechanism.
//   To disable the option you can set it to zero. No value is taken by default,
//   which means that by default ALL connections are open until either endpoint
//   closes the connection.
func ConfigureServer(s *fasthttp.Server, cnf ServerConfig) *Server {
	cnf.defaults()

	s2 := &Server{
		s:   s,
		cnf: cnf,
	}

	s.NextProto(H2TLSProto, s2.ServeConn)

	return s2
}

// ConfigureServerAndConfig configures the fasthttp server to handle HTTP/2 connections
// and your own tlsConfig file. If you are NOT using your own tls config, you may want to use ConfigureServer.
func ConfigureServerAndConfig(s *fasthttp.Server, tlsConfig *tls.Config) *Server {
	s2 := &Server{
		s: s,
	}

	s.NextProto(H2TLSProto, s2.ServeConn)
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, H2TLSProto)

	return s2
}

var ErrNotAvailableStreams = errors.New("ran out of available streams")
