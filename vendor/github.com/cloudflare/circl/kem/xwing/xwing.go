// Package xwing implements the X-Wing PQ/T hybrid KEM
//
//	https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem
//
// Implements the final version (-05).
package xwing

import (
	cryptoRand "crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// An X-Wing private key.
type PrivateKey struct {
	seed [32]byte
	m    mlkem768.PrivateKey
	x    x25519.Key
	xpk  x25519.Key
}

// An X-Wing public key.
type PublicKey struct {
	m mlkem768.PublicKey
	x x25519.Key
}

const (
	// Size of a seed of a keypair
	SeedSize = 32

	// Size of an X-Wing public key
	PublicKeySize = 1216

	// Size of an X-Wing private key
	PrivateKeySize = 32

	// Size of the seed passed to EncapsulateTo
	EncapsulationSeedSize = 64

	// Size of the established shared key
	SharedKeySize = 32

	// Size of an X-Wing ciphertext.
	CiphertextSize = 1120
)

func combiner(
	out []byte,
	ssm *[mlkem768.SharedKeySize]byte,
	ssx *x25519.Key,
	ctx *x25519.Key,
	pkx *x25519.Key,
) {
	h := sha3.New256()
	_, _ = h.Write(ssm[:])
	_, _ = h.Write(ssx[:])
	_, _ = h.Write(ctx[:])
	_, _ = h.Write(pkx[:])

	//   \./
	//   /^\
	_, _ = h.Write([]byte(`\.//^\`))

	_, _ = h.Read(out[:])
}

// Packs sk to buf.
//
// Panics if buf is not of size PrivateKeySize
func (sk *PrivateKey) Pack(buf []byte) {
	if len(buf) != PrivateKeySize {
		panic(kem.ErrPrivKeySize)
	}
	copy(buf, sk.seed[:])
}

// Packs pk to buf.
//
// Panics if buf is not of size PublicKeySize.
func (pk *PublicKey) Pack(buf []byte) {
	if len(buf) != PublicKeySize {
		panic(kem.ErrPubKeySize)
	}
	pk.m.Pack(buf[:mlkem768.PublicKeySize])
	copy(buf[mlkem768.PublicKeySize:], pk.x[:])
}

// DeriveKeyPair derives a public/private keypair deterministically
// from the given seed.
//
// Panics if seed is not of length SeedSize.
func DeriveKeyPair(seed []byte) (*PrivateKey, *PublicKey) {
	var (
		sk PrivateKey
		pk PublicKey
	)

	deriveKeyPair(seed, &sk, &pk)

	return &sk, &pk
}

func deriveKeyPair(seed []byte, sk *PrivateKey, pk *PublicKey) {
	if len(seed) != SeedSize {
		panic(kem.ErrSeedSize)
	}

	var seedm [mlkem768.KeySeedSize]byte

	copy(sk.seed[:], seed)

	h := sha3.NewShake256()
	_, _ = h.Write(seed)
	_, _ = h.Read(seedm[:])
	_, _ = h.Read(sk.x[:])

	pkm, skm := mlkem768.NewKeyFromSeed(seedm[:])
	sk.m = *skm
	pk.m = *pkm

	x25519.KeyGen(&pk.x, &sk.x)
	sk.xpk = pk.x
}

// DeriveKeyPairPacked derives a keypair like DeriveKeyPair, and
// returns them packed.
func DeriveKeyPairPacked(seed []byte) ([]byte, []byte) {
	sk, pk := DeriveKeyPair(seed)
	var (
		ppk [PublicKeySize]byte
		psk [PrivateKeySize]byte
	)
	pk.Pack(ppk[:])
	sk.Pack(psk[:])
	return psk[:], ppk[:]
}

// GenerateKeyPair generates public and private keys using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKeyPair(rand io.Reader) (*PrivateKey, *PublicKey, error) {
	var seed [SeedSize]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, nil, err
	}
	sk, pk := DeriveKeyPair(seed[:])
	return sk, pk, nil
}

// GenerateKeyPairPacked generates a keypair like GenerateKeyPair, and
// returns them packed.
func GenerateKeyPairPacked(rand io.Reader) ([]byte, []byte, error) {
	sk, pk, err := GenerateKeyPair(rand)
	if err != nil {
		return nil, nil, err
	}
	var (
		ppk [PublicKeySize]byte
		psk [PrivateKeySize]byte
	)
	pk.Pack(ppk[:])
	sk.Pack(psk[:])
	return psk[:], ppk[:], nil
}

// Encapsulate generates a shared key and ciphertext that contains it
// for the public key pk using randomness from seed.
//
// seed may be nil, in which case crypto/rand.Reader is used.
//
// Warning: note that the order of the returned ss and ct matches the
// X-Wing standard, which is the reverse of the Circl KEM API.
//
// Returns ErrPubKey if ML-KEM encapsulation key check fails.
//
// Panics if pk is not of size PublicKeySize, or randomness could not
// be read from crypto/rand.Reader.
func Encapsulate(pk, seed []byte) (ss, ct []byte, err error) {
	var pub PublicKey
	if err := pub.Unpack(pk); err != nil {
		return nil, nil, err
	}
	ct = make([]byte, CiphertextSize)
	ss = make([]byte, SharedKeySize)
	pub.EncapsulateTo(ct, ss, seed)
	return ss, ct, nil
}

// Decapsulate computes the shared key which is encapsulated in ct
// for the private key sk.
//
// Panics if sk or ct are not of length PrivateKeySize and CiphertextSize
// respectively.
func Decapsulate(ct, sk []byte) (ss []byte) {
	var priv PrivateKey
	priv.Unpack(sk)
	ss = make([]byte, SharedKeySize)
	priv.DecapsulateTo(ss, ct)
	return ss
}

// Raised when passing a byte slice of the wrong size for the shared
// secret to the EncapsulateTo or DecapsulateTo functions.
var ErrSharedKeySize = errors.New("wrong size for shared key")

// EncapsulateTo generates a shared key and ciphertext that contains it
// for the public key using randomness from seed and writes the shared key
// to ss and ciphertext to ct.
//
// Panics if ss, ct or seed are not of length SharedKeySize, CiphertextSize
// and EncapsulationSeedSize respectively.
//
// seed may be nil, in which case crypto/rand.Reader is used to generate one.
func (pk *PublicKey) EncapsulateTo(ct, ss, seed []byte) {
	if seed == nil {
		seed = make([]byte, EncapsulationSeedSize)
		if _, err := cryptoRand.Read(seed[:]); err != nil {
			panic(err)
		}
	} else {
		if len(seed) != EncapsulationSeedSize {
			panic(kem.ErrSeedSize)
		}
	}

	if len(ct) != CiphertextSize {
		panic(kem.ErrCiphertextSize)
	}

	if len(ss) != SharedKeySize {
		panic(ErrSharedKeySize)
	}

	var (
		seedm [32]byte
		ekx   x25519.Key
		ctx   x25519.Key
		ssx   x25519.Key
		ssm   [mlkem768.SharedKeySize]byte
	)

	copy(seedm[:], seed[:32])
	copy(ekx[:], seed[32:])

	x25519.KeyGen(&ctx, &ekx)
	// A peer public key with low order points results in an all-zeroes
	// shared secret. Ignored for now pending clarification in the spec,
	// https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem/issues/28
	x25519.Shared(&ssx, &ekx, &pk.x)
	pk.m.EncapsulateTo(ct[:mlkem768.CiphertextSize], ssm[:], seedm[:])

	combiner(ss, &ssm, &ssx, &ctx, &pk.x)
	copy(ct[mlkem768.CiphertextSize:], ctx[:])
}

// DecapsulateTo computes the shared key which is encapsulated in ct
// for the private key.
//
// Panics if ct or ss are not of length CiphertextSize and SharedKeySize
// respectively.
func (sk *PrivateKey) DecapsulateTo(ss, ct []byte) {
	if len(ct) != CiphertextSize {
		panic(kem.ErrCiphertextSize)
	}
	if len(ss) != SharedKeySize {
		panic(ErrSharedKeySize)
	}

	ctm := ct[:mlkem768.CiphertextSize]

	var (
		ssm [mlkem768.SharedKeySize]byte
		ssx x25519.Key
		ctx x25519.Key
	)

	copy(ctx[:], ct[mlkem768.CiphertextSize:])

	sk.m.DecapsulateTo(ssm[:], ctm)
	// A peer public key with low order points results in an all-zeroes
	// shared secret. Ignored for now pending clarification in the spec,
	// https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem/issues/28
	x25519.Shared(&ssx, &sk.x, &ctx)
	combiner(ss, &ssm, &ssx, &ctx, &sk.xpk)
}

// Unpacks pk from buf.
//
// Panics if buf is not of size PublicKeySize.
//
// Returns ErrPubKey if pk fails the ML-KEM encapsulation key check.
func (pk *PublicKey) Unpack(buf []byte) error {
	if len(buf) != PublicKeySize {
		panic(kem.ErrPubKeySize)
	}

	copy(pk.x[:], buf[mlkem768.PublicKeySize:])
	return pk.m.Unpack(buf[:mlkem768.PublicKeySize])
}

// Unpacks sk from buf.
//
// Panics if buf is not of size PrivateKeySize.
func (sk *PrivateKey) Unpack(buf []byte) {
	var pk PublicKey
	deriveKeyPair(buf, sk, &pk)
}
