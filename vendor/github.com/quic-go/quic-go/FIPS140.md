# FIPS 140-3

quic-go relies on the Go standard library for cryptography, including the Go Cryptographic Module described in [The FIPS 140-3 Go Cryptographic Module](https://go.dev/blog/fips140). quic-go does not seek separate FIPS 140-3 validation as a cryptographic module. This document explains how quic-go uses Go standard library cryptography for QUIC operations relevant to FIPS 140-3.

Starting with quic-go v0.60, the behavior described here applies when built with Go 1.26 or newer. With older Go versions, quic-go still builds and runs as usual, without any attempt to meet FIPS 140 requirements.

## QUIC operations relevant to FIPS 140-3

quic-go delegates the TLS 1.3 handshake, certificate handling, cipher suite selection, session tickets, and the TLS key schedule to `crypto/tls`. When Go's FIPS 140-3 mode is active, `crypto/tls` restricts the algorithms it negotiates.

### Packet protection AEADs

The main quic-go-specific FIPS-relevant operations are the AEADs protecting Handshake, 0-RTT, and 1-RTT packets.

AES-GCM packet protection AEADs are constructed through the Go standard library's TLS 1.3 AES-GCM implementation. Today this uses `go:linkname` to call the unexported `crypto/tls.aeadAESGCMTLS13`, because the standard library does not yet expose a QUIC-specific constructor; see [golang/go#79219](https://github.com/golang/go/issues/79219).

ChaCha20-Poly1305 is not used in Go's FIPS 140-3 mode. `crypto/tls` avoids that cipher suite during negotiation, and quic-go additionally guards its internal ChaCha20-Poly1305 path when FIPS 140-3 mode is enabled.

### Header protection

For Handshake, 0-RTT, and 1-RTT packets protected with AES cipher suites, header protection keys are derived with `crypto/hkdf` and the AES block operation uses `crypto/aes`. ChaCha20 header protection is tied to the ChaCha20-Poly1305 cipher suite and is not reachable in FIPS 140-3 mode.

### Address validation tokens

quic-go encrypts the address validation tokens it sends in Retry packets and NEW_TOKEN frames. These are not TLS session tickets (those are handled by `crypto/tls`); they carry server-defined state such as the client address, timestamp, RTT information, and Retry connection IDs.

Token-protection keys are derived with `crypto/hkdf`, AES is used via `crypto/aes`, and the token AEAD is constructed with `cipher.NewGCMWithRandomNonce`, keeping token encryption on standard library primitives.

## QUIC operations not relevant to FIPS 140-3

### Initial packet protection

Initial packet protection (including Initial header protection) is not treated as FIPS 140-relevant confidentiality protection: the Initial secrets are derived from constants in RFC 9001 and the packet's destination connection ID, so any observer can derive the same keys. quic-go therefore disables strict FIPS 140 enforcement around Initial packet construction in Go 1.26 FIPS 140-3 mode. See the IETF QUIC mailing list discussion at <https://mailarchive.ietf.org/arch/msg/quic/k2kl2W_n5WDEZBbt3O31Ef2XBbM/>.

### Retry packet integrity tag

RFC 9001 defines the Retry packet integrity tag using fixed keys and nonces. It guards against accidental corruption and casual injection but does not encrypt packet contents. quic-go treats it as outside the FIPS 140 scope and disables strict FIPS 140 enforcement for that AEAD construction in Go 1.26 FIPS 140-3 mode.
