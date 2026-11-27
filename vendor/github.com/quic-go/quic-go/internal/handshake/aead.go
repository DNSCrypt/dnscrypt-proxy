package handshake

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
)

func createAEAD(suite cipherSuite, trafficSecret []byte, v protocol.Version) cipher.AEAD {
	keyLabel := hkdfLabelKeyV1
	ivLabel := hkdfLabelIVV1
	if v == protocol.Version2 {
		keyLabel = hkdfLabelKeyV2
		ivLabel = hkdfLabelIVV2
	}
	key := hkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, keyLabel, suite.KeyLen)
	iv := hkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, ivLabel, suite.IVLen())
	return suite.AEAD(key, iv)
}

type longHeaderSealer struct {
	aead            cipher.AEAD
	headerProtector headerProtector
	nonceBuf        [8]byte
}

var _ LongHeaderSealer = &longHeaderSealer{}

func newLongHeaderSealer(aead cipher.AEAD, headerProtector headerProtector) LongHeaderSealer {
	if aead.NonceSize() != 8 {
		panic("unexpected nonce size")
	}
	return &longHeaderSealer{
		aead:            aead,
		headerProtector: headerProtector,
	}
}

func (s *longHeaderSealer) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	binary.BigEndian.PutUint64(s.nonceBuf[:], uint64(pn))
	return s.aead.Seal(dst, s.nonceBuf[:], src, ad)
}

func (s *longHeaderSealer) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	s.headerProtector.EncryptHeader(sample, firstByte, pnBytes)
}

func (s *longHeaderSealer) Overhead() int {
	return s.aead.Overhead()
}

type longHeaderOpener struct {
	aead            cipher.AEAD
	headerProtector headerProtector
	invalidPackets  uint32

	// use a single array to avoid allocations
	nonceBuf [8]byte
}

var _ LongHeaderOpener = &longHeaderOpener{}

func newLongHeaderOpener(aead cipher.AEAD, headerProtector headerProtector) LongHeaderOpener {
	if aead.NonceSize() != 8 {
		panic("unexpected nonce size")
	}
	return &longHeaderOpener{
		aead:            aead,
		headerProtector: headerProtector,
	}
}

func (o *longHeaderOpener) Open(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(o.nonceBuf[:], uint64(pn))
	dec, err := o.aead.Open(dst, o.nonceBuf[:], src, ad)
	if err != nil {
		// RFC 9001, Section 6.6 counts failures across all keys.
		// To avoid sharing a counter between the openers, each long header key has its own limit,
		// and the 1-RTT limit is reduced accordingly.
		// These keys are dropped long before an attacker could send 2^32 forged packets.
		o.invalidPackets++
		if o.invalidPackets >= protocol.InvalidPacketLimitLongHeader {
			return nil, &qerr.TransportError{ErrorCode: qerr.AEADLimitReached}
		}
		err = ErrDecryptionFailed
	}
	return dec, err
}

func (o *longHeaderOpener) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	o.headerProtector.DecryptHeader(sample, firstByte, pnBytes)
}
