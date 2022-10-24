package handshake

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const (
	tokenPrefixIP byte = iota
	tokenPrefixString
)

// A Token is derived from the client address and can be used to verify the ownership of this address.
type Token struct {
	IsRetryToken      bool
	SentTime          time.Time
	encodedRemoteAddr []byte
	// only set for retry tokens
	OriginalDestConnectionID protocol.ConnectionID
	RetrySrcConnectionID     protocol.ConnectionID
}

// ValidateRemoteAddr validates the address, but does not check expiration
func (t *Token) ValidateRemoteAddr(addr net.Addr) bool {
	return bytes.Equal(encodeRemoteAddr(addr), t.encodedRemoteAddr)
}

// token is the struct that is used for ASN1 serialization and deserialization
type token struct {
	IsRetryToken             bool
	RemoteAddr               []byte
	Timestamp                int64
	OriginalDestConnectionID []byte
	RetrySrcConnectionID     []byte
}

// A TokenGenerator generates tokens
type TokenGenerator struct {
	tokenProtector tokenProtector
}

// NewTokenGenerator initializes a new TookenGenerator
func NewTokenGenerator(rand io.Reader) (*TokenGenerator, error) {
	tokenProtector, err := newTokenProtector(rand)
	if err != nil {
		return nil, err
	}
	return &TokenGenerator{
		tokenProtector: tokenProtector,
	}, nil
}

// NewRetryToken generates a new token for a Retry for a given source address
func (g *TokenGenerator) NewRetryToken(
	raddr net.Addr,
	origDestConnID protocol.ConnectionID,
	retrySrcConnID protocol.ConnectionID,
) ([]byte, error) {
	data, err := asn1.Marshal(token{
		IsRetryToken:             true,
		RemoteAddr:               encodeRemoteAddr(raddr),
		OriginalDestConnectionID: origDestConnID.Bytes(),
		RetrySrcConnectionID:     retrySrcConnID.Bytes(),
		Timestamp:                time.Now().UnixNano(),
	})
	if err != nil {
		return nil, err
	}
	return g.tokenProtector.NewToken(data)
}

// NewToken generates a new token to be sent in a NEW_TOKEN frame
func (g *TokenGenerator) NewToken(raddr net.Addr) ([]byte, error) {
	data, err := asn1.Marshal(token{
		RemoteAddr: encodeRemoteAddr(raddr),
		Timestamp:  time.Now().UnixNano(),
	})
	if err != nil {
		return nil, err
	}
	return g.tokenProtector.NewToken(data)
}

// DecodeToken decodes a token
func (g *TokenGenerator) DecodeToken(encrypted []byte) (*Token, error) {
	// if the client didn't send any token, DecodeToken will be called with a nil-slice
	if len(encrypted) == 0 {
		return nil, nil
	}

	data, err := g.tokenProtector.DecodeToken(encrypted)
	if err != nil {
		return nil, err
	}
	t := &token{}
	rest, err := asn1.Unmarshal(data, t)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("rest when unpacking token: %d", len(rest))
	}
	token := &Token{
		IsRetryToken:      t.IsRetryToken,
		SentTime:          time.Unix(0, t.Timestamp),
		encodedRemoteAddr: t.RemoteAddr,
	}
	if t.IsRetryToken {
		token.OriginalDestConnectionID = protocol.ParseConnectionID(t.OriginalDestConnectionID)
		token.RetrySrcConnectionID = protocol.ParseConnectionID(t.RetrySrcConnectionID)
	}
	return token, nil
}

// encodeRemoteAddr encodes a remote address such that it can be saved in the token
func encodeRemoteAddr(remoteAddr net.Addr) []byte {
	if udpAddr, ok := remoteAddr.(*net.UDPAddr); ok {
		return append([]byte{tokenPrefixIP}, udpAddr.IP...)
	}
	return append([]byte{tokenPrefixString}, []byte(remoteAddr.String())...)
}
