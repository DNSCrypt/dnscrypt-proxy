package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// Transport is the transport used in [Client], it deals with all the networking.
type Transport struct {
	// Dialer is used used to set local address and timeouts.
	Dialer *net.Dialer

	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// TLSClientConfig specifies the TLS configuration to use with DialTLS, if TLSConfig is not nil it will
	// be used to dial.
	TLSConfig *tls.Config
}

// defaultTransport is the default transport in client, when none is set. Note changing this value has global
// effects to future [Client]s and [Transfer]s. The TSIGSigner and TSIGVerifier are both set to [TSIGHMAC].
var defaultTransport = Transport{
	Dialer: &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 3 * time.Second,
	},
	ReadTimeout:  2 * time.Second,
	WriteTimeout: 2 * time.Second,
}

// NewTransport returns the default transport. That transport has Dialer timeout of 5s, keep alive of 3s and
// read and write timeout set to 2s.
func NewTransport() *Transport {
	d := defaultTransport
	return &d
}

// dial dials address via network. If tls config is set, a tls dialer is used. This method can be overriden to
// return e.g. a static net.Conn that is previously created.
func (t *Transport) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if t.TLSConfig != nil {
		dialer := tls.Dialer{NetDialer: t.Dialer, Config: t.TLSConfig}
		return dialer.DialContext(ctx, network, address)
	}
	return t.Dialer.DialContext(ctx, network, address)
}

// isEOFOrClosedNetwork returns true if the error err is an io.EOF or a *net.OpError with the
// text 'use of closed network connection'.
func isEOFOrClosedNetwork(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	if _, ok := err.(*net.OpError); ok {
		if strings.Contains(err.Error(), "use of closed network connection") {
			return true
		}
	}
	return false
}

// Tranfer defines the signing parameters that are used during a zone transfer.
type Transfer struct {
	// If non zero, TSIG signing and verification is done on messages that have a TSIG record in the pseudo section.
	TSIGSigner
	// If non zero SIG0 signing and verification is done on messages that have a SIG0 record in the pseudo section.
	SIG0Signer
}
