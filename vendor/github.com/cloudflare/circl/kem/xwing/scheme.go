package xwing

import (
	"bytes"
	cryptoRand "crypto/rand"
	"crypto/subtle"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// This file contains the boilerplate code to connect X-Wing to the
// generic KEM API.

// Returns the generic KEM interface for  X-Wing PQ/T hybrid KEM.
func Scheme() kem.Scheme { return scheme{} }

type scheme struct{}

func (scheme) Name() string               { return "X-Wing" }
func (scheme) PublicKeySize() int         { return PublicKeySize }
func (scheme) PrivateKeySize() int        { return PrivateKeySize }
func (scheme) SeedSize() int              { return SeedSize }
func (scheme) EncapsulationSeedSize() int { return EncapsulationSeedSize }
func (scheme) SharedKeySize() int         { return SharedKeySize }
func (scheme) CiphertextSize() int        { return CiphertextSize }
func (*PrivateKey) Scheme() kem.Scheme    { return scheme{} }
func (*PublicKey) Scheme() kem.Scheme     { return scheme{} }

func (sch scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	var seed [EncapsulationSeedSize]byte
	_, err = cryptoRand.Read(seed[:])
	if err != nil {
		return
	}
	return sch.EncapsulateDeterministically(pk, seed[:])
}

func (scheme) EncapsulateDeterministically(
	pk kem.PublicKey, seed []byte,
) ([]byte, []byte, error) {
	if len(seed) != EncapsulationSeedSize {
		return nil, nil, kem.ErrSeedSize
	}
	pub, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}
	var (
		ct [CiphertextSize]byte
		ss [SharedKeySize]byte
	)
	pub.EncapsulateTo(ct[:], ss[:], seed)
	return ct[:], ss[:], nil
}

func (scheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
	var pk PublicKey
	if len(buf) != PublicKeySize {
		return nil, kem.ErrPubKeySize
	}

	if err := pk.Unpack(buf); err != nil {
		return nil, err
	}
	return &pk, nil
}

func (scheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
	var sk PrivateKey
	if len(buf) != PrivateKeySize {
		return nil, kem.ErrPrivKeySize
	}

	sk.Unpack(buf)
	return &sk, nil
}

func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	var ret [PrivateKeySize]byte
	sk.Pack(ret[:])
	return ret[:], nil
}

func (sk *PrivateKey) Equal(other kem.PrivateKey) bool {
	oth, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return sk.m.Equal(&oth.m) &&
		subtle.ConstantTimeCompare(oth.x[:], sk.x[:]) == 1
}

func (sk *PrivateKey) Public() kem.PublicKey {
	var pk PublicKey
	pk.m = *(sk.m.Public().(*mlkem768.PublicKey))
	pk.x = sk.xpk
	return &pk
}

func (pk *PublicKey) Equal(other kem.PublicKey) bool {
	oth, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return pk.m.Equal(&oth.m) && bytes.Equal(pk.x[:], oth.x[:])
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	var ret [PublicKeySize]byte
	pk.Pack(ret[:])
	return ret[:], nil
}

func (scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	sk, pk := DeriveKeyPair(seed)
	return pk, sk
}

func (scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	sk, pk, err := GenerateKeyPair(nil)
	return pk, sk, err
}

func (scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	if len(ct) != CiphertextSize {
		return nil, kem.ErrCiphertextSize
	}

	var ss [SharedKeySize]byte

	priv, ok := sk.(*PrivateKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}

	priv.DecapsulateTo(ss[:], ct[:])

	return ss[:], nil
}
