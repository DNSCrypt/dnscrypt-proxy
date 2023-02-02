package handshake

import (
	"crypto"
	"crypto/tls"

	"golang.org/x/crypto/hkdf"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qtls"
)

var (
	quicSaltOld = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSaltV1  = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2  = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

const (
	hkdfLabelKeyV1 = "quic key"
	hkdfLabelKeyV2 = "quicv2 key"
	hkdfLabelIVV1  = "quic iv"
	hkdfLabelIVV2  = "quicv2 iv"
)

func getSalt(v protocol.VersionNumber) []byte {
	if v == protocol.Version2 {
		return quicSaltV2
	}
	if v == protocol.Version1 {
		return quicSaltV1
	}
	return quicSaltOld
}

var initialSuite = &qtls.CipherSuiteTLS13{
	ID:     tls.TLS_AES_128_GCM_SHA256,
	KeyLen: 16,
	AEAD:   qtls.AEADAESGCMTLS13,
	Hash:   crypto.SHA256,
}

// NewInitialAEAD creates a new AEAD for Initial encryption / decryption.
func NewInitialAEAD(connID protocol.ConnectionID, pers protocol.Perspective, v protocol.VersionNumber) (LongHeaderSealer, LongHeaderOpener) {
	clientSecret, serverSecret := computeSecrets(connID, v)
	var mySecret, otherSecret []byte
	if pers == protocol.PerspectiveClient {
		mySecret = clientSecret
		otherSecret = serverSecret
	} else {
		mySecret = serverSecret
		otherSecret = clientSecret
	}
	myKey, myIV := computeInitialKeyAndIV(mySecret, v)
	otherKey, otherIV := computeInitialKeyAndIV(otherSecret, v)

	encrypter := qtls.AEADAESGCMTLS13(myKey, myIV)
	decrypter := qtls.AEADAESGCMTLS13(otherKey, otherIV)

	return newLongHeaderSealer(encrypter, newHeaderProtector(initialSuite, mySecret, true, v)),
		newLongHeaderOpener(decrypter, newAESHeaderProtector(initialSuite, otherSecret, true, hkdfHeaderProtectionLabel(v)))
}

func computeSecrets(connID protocol.ConnectionID, v protocol.VersionNumber) (clientSecret, serverSecret []byte) {
	initialSecret := hkdf.Extract(crypto.SHA256.New, connID.Bytes(), getSalt(v))
	clientSecret = hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())
	serverSecret = hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "server in", crypto.SHA256.Size())
	return
}

func computeInitialKeyAndIV(secret []byte, v protocol.VersionNumber) (key, iv []byte) {
	keyLabel := hkdfLabelKeyV1
	ivLabel := hkdfLabelIVV1
	if v == protocol.Version2 {
		keyLabel = hkdfLabelKeyV2
		ivLabel = hkdfLabelIVV2
	}
	key = hkdfExpandLabel(crypto.SHA256, secret, []byte{}, keyLabel, 16)
	iv = hkdfExpandLabel(crypto.SHA256, secret, []byte{}, ivLabel, 12)
	return
}
