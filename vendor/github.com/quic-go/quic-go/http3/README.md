# HTTP/3

[![PkgGoDev](https://pkg.go.dev/badge/github.com/quic-go/quic-go/http3)](https://pkg.go.dev/github.com/quic-go/quic-go/http3)

This package implements HTTP/3 ([RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114)), including QPACK ([RFC 9204](https://datatracker.ietf.org/doc/html/rfc9204)).
It aims to provide feature parity with the standard library's HTTP/1.1 and HTTP/2 implementation.

## Serving HTTP/3

The easiest way to start an HTTP/3 server is using
```go
mux := http.NewServeMux()
// ... add HTTP handlers to mux ...
// If mux is nil, the http.DefaultServeMux is used.
http3.ListenAndServeQUIC("0.0.0.0:443", "/path/to/cert", "/path/to/key", mux)
```

`ListenAndServeQUIC` is a convenience function. For more configurability, set up an `http3.Server` explicitly:
```go
server := http3.Server{
	Handler:    mux,
	Addr:       "0.0.0.0:443",
	TLSConfig:  http3.ConfigureTLSConfig(&tls.Config{}), // use your tls.Config here
	QuicConfig: &quic.Config{},
}
err := server.ListenAndServe()
```

The `http3.Server` provides a number of configuration options, please refer to the [documentation](https://pkg.go.dev/github.com/quic-go/quic-go/http3#Server) for a complete list. The `QuicConfig` is used to configure the underlying QUIC connection. More details can be found in the documentation of the QUIC package.

It is also possible to manually set up a `quic.Transport`, and then pass the listener to the server. This is useful when you want to set configuration options on the `quic.Transport`.
```go
tr := quic.Transport{Conn: conn}
tlsConf := http3.ConfigureTLSConfig(&tls.Config{})  // use your tls.Config here
quicConf := &quic.Config{} // QUIC connection options
server := http3.Server{}
ln, _ := tr.ListenEarly(tlsConf, quicConf)
server.ServeListener(ln)
```

Alternatively, it is also possible to pass fully established QUIC connections to the HTTP/3 server. This is useful if the QUIC server offers multiple ALPNs (via `NextProtos` in the `tls.Config`).
```go
tr := quic.Transport{Conn: conn}
tlsConf := http3.ConfigureTLSConfig(&tls.Config{})  // use your tls.Config here
quicConf := &quic.Config{} // QUIC connection options
server := http3.Server{}
// alternatively, use tr.ListenEarly to accept 0-RTT connections
ln, _ := tr.Listen(tlsConf, quicConf)
for {
	c, _ := ln.Accept()
	switch c.ConnectionState().TLS.NegotiatedProtocol {
	case http3.NextProtoH3:
		go server.ServeQUICConn(c) 
        // ... handle other protocols ...  
	}
}
```

## Dialing HTTP/3

This package provides a `http.RoundTripper` implementation that can be used on the `http.Client`:

```go
&http3.RoundTripper{
	TLSClientConfig: &tls.Config{},  // set a TLS client config, if desired
	QuicConfig:      &quic.Config{}, // QUIC connection options
}
defer roundTripper.Close()
client := &http.Client{
	Transport: roundTripper,
}
```

The `http3.RoundTripper` provides a number of configuration options, please refer to the [documentation](https://pkg.go.dev/github.com/quic-go/quic-go/http3#RoundTripper) for a complete list.

To use a custom `quic.Transport`, the function used to dial new QUIC connections can be configured:
```go
tr := quic.Transport{}
roundTripper := &http3.RoundTripper{
	TLSClientConfig: &tls.Config{},  // set a TLS client config, if desired 
	QuicConfig:      &quic.Config{}, // QUIC connection options 
	Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
		a, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		return tr.DialEarly(ctx, a, tlsConf, quicConf)
	},
}
```

## Using the same UDP Socket for Server and Roundtripper

Since QUIC demultiplexes packets based on their connection IDs, it is possible allows running a QUIC server and client on the same UDP socket. This also works when using HTTP/3: HTTP requests can be sent from the same socket that a server is listening on.

To achieve this using this package, first initialize a single `quic.Transport`, and pass a `quic.EarlyListner` obtained from that transport to `http3.Server.ServeListener`, and use the `DialEarly` function of the transport as the `Dial` function for the `http3.RoundTripper`.

## QPACK

HTTP/3 utilizes QPACK ([RFC 9204](https://datatracker.ietf.org/doc/html/rfc9204)) for efficient HTTP header field compression. Our implementation, available at[quic-go/qpack](https://github.com/quic-go/qpack), provides a minimal implementation of the protocol.  

While the current implementation is a fully interoperable implementation of the QPACK protocol, it only uses the static compression table. The dynamic table would allow for more effective compression of frequently transmitted header fields. This can be particularly beneficial in scenarios where headers have considerable redundancy or in high-throughput environments.

If you think that your application would benefit from higher compression efficiency, or if you're interested in contributing improvements here, please let us know in [#2424](https://github.com/quic-go/quic-go/issues/2424).
