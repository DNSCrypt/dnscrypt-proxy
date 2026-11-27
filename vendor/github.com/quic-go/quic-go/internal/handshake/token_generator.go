package handshake

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	tokenPrefixIP byte = iota
	tokenPrefixString
)

// A Token is derived from the client address and can be used to verify the ownership of this address.
type Token struct {
	IsRetryToken      bool
	SentTime          time.Time
	Version           protocol.Version
	encodedRemoteAddr []byte
	// only set for tokens sent in NEW_TOKEN frames
	RTT time.Duration
	// only set for retry tokens
	OriginalDestConnectionID protocol.ConnectionID
	RetrySrcConnectionID     protocol.ConnectionID
}

// ValidateRemoteAddr validates the address, but does not check expiration
func (t *Token) ValidateRemoteAddr(addr net.Addr) bool {
	return bytes.Equal(encodeRemoteAddr(addr), t.encodedRemoteAddr)
}

// The first byte of the token plaintext.
// Use new values when changing the plaintext format.
const (
	tokenTypeRetry    byte = 1
	tokenTypeNewToken byte = 2
)

// A TokenGenerator generates tokens
type TokenGenerator struct {
	tokenProtector tokenProtector
}

// NewTokenGenerator initializes a new TokenGenerator
func NewTokenGenerator(key TokenProtectorKey) *TokenGenerator {
	return &TokenGenerator{tokenProtector: *newTokenProtector(key)}
}

// NewRetryToken generates a new token for a Retry for a given source address
func (g *TokenGenerator) NewRetryToken(
	raddr net.Addr,
	origDestConnID protocol.ConnectionID,
	retrySrcConnID protocol.ConnectionID,
	v protocol.Version,
) ([]byte, error) {
	odcid := origDestConnID.Bytes()
	rscid := retrySrcConnID.Bytes()
	b := newTokenPlaintext(tokenTypeRetry, raddr, v, 2+len(odcid)+len(rscid))
	b = appendLengthPrefixed(b, odcid)
	b = appendLengthPrefixed(b, rscid)
	return g.tokenProtector.NewToken(b)
}

// NewToken generates a new token to be sent in a NEW_TOKEN frame
func (g *TokenGenerator) NewToken(raddr net.Addr, rtt time.Duration, v protocol.Version) ([]byte, error) {
	rttMicros := uint64(rtt.Microseconds())
	b := newTokenPlaintext(tokenTypeNewToken, raddr, v, quicvarint.Len(rttMicros))
	b = quicvarint.Append(b, rttMicros)
	return g.tokenProtector.NewToken(b)
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
	if len(data) < tokenHeaderLen {
		return nil, fmt.Errorf("token too short: %d", len(data))
	}
	typ := data[0]
	if typ != tokenTypeRetry && typ != tokenTypeNewToken {
		return nil, fmt.Errorf("unknown token type: %d", typ)
	}
	token := &Token{
		IsRetryToken: typ == tokenTypeRetry,
		Version:      protocol.Version(binary.BigEndian.Uint32(data[1:5])),
		SentTime:     time.Unix(0, int64(binary.BigEndian.Uint64(data[5:tokenHeaderLen]))),
	}
	addr, b, err := parseLengthPrefixed(data[tokenHeaderLen:])
	if err != nil {
		return nil, err
	}
	token.encodedRemoteAddr = addr
	if token.IsRetryToken {
		token.OriginalDestConnectionID, b, err = parseTokenConnID(b)
		if err != nil {
			return nil, err
		}
		token.RetrySrcConnectionID, b, err = parseTokenConnID(b)
		if err != nil {
			return nil, err
		}
	} else {
		rtt, l, err := quicvarint.Parse(b)
		if err != nil {
			return nil, err
		}
		token.RTT = time.Duration(rtt) * time.Microsecond
		b = b[l:]
	}
	if len(b) != 0 {
		return nil, fmt.Errorf("rest when unpacking token: %d", len(b))
	}
	return token, nil
}

// tokenHeaderLen is the length of the type, version and timestamp.
const tokenHeaderLen = 1 + 4 + 8

// newTokenPlaintext allocates the plaintext with room for n more bytes,
// and writes the token type, version, timestamp and remote address.
func newTokenPlaintext(typ byte, raddr net.Addr, v protocol.Version, n int) []byte {
	addr := encodeRemoteAddr(raddr)
	b := make([]byte, 0, tokenHeaderLen+quicvarint.Len(uint64(len(addr)))+len(addr)+n)
	b = append(b, typ)
	b = binary.BigEndian.AppendUint32(b, uint32(v))
	b = binary.BigEndian.AppendUint64(b, uint64(time.Now().UnixNano()))
	return appendLengthPrefixed(b, addr)
}

func appendLengthPrefixed(b, data []byte) []byte {
	b = quicvarint.Append(b, uint64(len(data)))
	return append(b, data...)
}

func parseLengthPrefixed(b []byte) (data, rest []byte, _ error) {
	l, n, err := quicvarint.Parse(b)
	if err != nil {
		return nil, nil, err
	}
	b = b[n:]
	if uint64(len(b)) < l {
		return nil, nil, io.EOF
	}
	return b[:l], b[l:], nil
}

func parseTokenConnID(b []byte) (protocol.ConnectionID, []byte, error) {
	data, rest, err := parseLengthPrefixed(b)
	if err != nil {
		return protocol.ConnectionID{}, nil, err
	}
	if len(data) > protocol.MaxConnIDLen {
		return protocol.ConnectionID{}, nil, fmt.Errorf("invalid connection ID length: %d", len(data))
	}
	return protocol.ParseConnectionID(data), rest, nil
}

// encodeRemoteAddr encodes a remote address such that it can be saved in the token
func encodeRemoteAddr(remoteAddr net.Addr) []byte {
	if udpAddr, ok := remoteAddr.(*net.UDPAddr); ok {
		return append([]byte{tokenPrefixIP}, udpAddr.IP...)
	}
	return append([]byte{tokenPrefixString}, []byte(remoteAddr.String())...)
}
