//go:build go1.25 && !go1.26

package handshake

import "crypto/tls"

const quicErrorEvent tls.QUICEventKind = -1

func extractQUICEventError(tls.QUICEvent) error {
	return nil
}
