package quic

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
)

type statelessResetter struct {
	mx  sync.Mutex
	h   hash.Hash
	buf [sha256.Size]byte // holds the connection ID, then the HMAC, avoiding allocations
}

// newStatelessRetter creates a new stateless reset generator.
// It is valid to use a nil key. In that case, a random key will be used.
// This makes is impossible for on-path attackers to shut down established connections.
func newStatelessResetter(key *StatelessResetKey) *statelessResetter {
	var h hash.Hash
	if key != nil {
		h = hmac.New(sha256.New, key[:])
	} else {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		h = hmac.New(sha256.New, b)
	}
	return &statelessResetter{h: h}
}

func (r *statelessResetter) GetStatelessResetToken(connID protocol.ConnectionID) protocol.StatelessResetToken {
	r.mx.Lock()
	defer r.mx.Unlock()

	n := copy(r.buf[:], connID.Bytes())
	r.h.Write(r.buf[:n])
	var token protocol.StatelessResetToken
	copy(token[:], r.h.Sum(r.buf[:0]))
	r.h.Reset()
	return token
}
