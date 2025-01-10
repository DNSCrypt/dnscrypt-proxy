package main

import (
	"bytes"
	crypto_rand "crypto/rand"
	"crypto/sha512"
	"errors"

	"github.com/jedisct1/dlog"
	"github.com/jedisct1/xsecretbox"
	"golang.org/x/crypto/curve25519"
)

const (
	NonceSize        = xsecretbox.NonceSize
	HalfNonceSize    = xsecretbox.NonceSize / 2
	TagSize          = xsecretbox.TagSize
	PublicKeySize    = 32
	QueryOverhead    = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize
	ResponseOverhead = len(ServerMagic) + NonceSize + TagSize
)

func pad(packet []byte, minSize int) []byte {
	packet = append(packet, 0x80)
	for len(packet) < minSize {
		packet = append(packet, 0)
	}
	return packet
}

func unpad(packet []byte) ([]byte, error) {
	for i := len(packet); ; {
		if i == 0 {
			return nil, errors.New("Invalid padding (short packet)")
		}
		i--
		if packet[i] == 0x80 {
			return packet[:i], nil
		} else if packet[i] != 0x00 {
			return nil, errors.New("Invalid padding (delimiter not found)")
		}
	}
}

func ComputeSharedKey(
	cryptoConstruction CryptoConstruction,
	secretKey *[32]byte,
	serverPk *[32]byte,
	providerName *string,
) (sharedKey [32]byte) {
	if cryptoConstruction == XChacha20Poly1305 {
		var err error
		sharedKey, err = xsecretbox.SharedKey(*secretKey, *serverPk)
		if err != nil {
			dlog.Criticalf("[%v] Weak XChaCha20 public key", providerName)
		}
	} else {
		dlog.Criticalf("[%v] Unsupported encryption system", providerName)
	}
	return sharedKey
}

func (proxy *Proxy) Encrypt(
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
	nonce, clientNonce := make([]byte, NonceSize), make([]byte, HalfNonceSize)
	if _, err := crypto_rand.Read(clientNonce); err != nil {
		return nil, nil, nil, err
	}
	copy(nonce, clientNonce)
	var publicKey *[PublicKeySize]byte
	if proxy.ephemeralKeys {
		h := sha512.New512_256()
		h.Write(clientNonce)
		h.Write(proxy.proxySecretKey[:])
		var ephSk [32]byte
		h.Sum(ephSk[:0])
		var xPublicKey [PublicKeySize]byte
		curve25519.ScalarBaseMult(&xPublicKey, &ephSk)
		publicKey = &xPublicKey
		xsharedKey := ComputeSharedKey(serverInfo.CryptoConstruction, &ephSk, &serverInfo.ServerPk, nil)
		sharedKey = &xsharedKey
	} else {
		sharedKey = &serverInfo.SharedKey
		publicKey = &proxy.proxyPublicKey
	}
	minQuestionSize := QueryOverhead + len(packet)
	if proto == "udp" {
		minQuestionSize = Max(proxy.questionSizeEstimator.MinQuestionSize(), minQuestionSize)
	} else {
		var xpad [1]byte
		if _, err := crypto_rand.Read(xpad[:]); err != nil {
			return nil, nil, nil, err
		}
		minQuestionSize += int(xpad[0])
	}
	paddedLength := Min(MaxDNSUDPPacketSize, (Max(minQuestionSize, QueryOverhead)+1+63) & ^63)
	if serverInfo.knownBugs.fragmentsBlocked && proto == "udp" {
		paddedLength = MaxDNSUDPSafePacketSize
	} else if serverInfo.Relay != nil && proto == "tcp" {
		paddedLength = MaxDNSPacketSize
	}
	if QueryOverhead+len(packet)+1 > paddedLength {
		err = errors.New("Question too large; cannot be padded")
		return
	}
	encrypted = append(serverInfo.MagicQuery[:], publicKey[:]...)
	encrypted = append(encrypted, nonce[:HalfNonceSize]...)
	padded := pad(packet, paddedLength-QueryOverhead)
	if serverInfo.CryptoConstruction == XChacha20Poly1305 {
		encrypted = xsecretbox.Seal(encrypted, nonce, padded, sharedKey[:])
	} else {
		err = errors.New("Unsupported encryption system")
	}
	return
}

func (proxy *Proxy) Decrypt(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	encrypted []byte,
	nonce []byte,
) ([]byte, error) {
	serverMagicLen := len(ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize
	if len(encrypted) < responseHeaderLen+TagSize+int(MinDNSPacketSize) ||
		len(encrypted) > responseHeaderLen+TagSize+int(MaxDNSPacketSize) ||
		!bytes.Equal(encrypted[:serverMagicLen], ServerMagic[:]) {
		return encrypted, errors.New("Invalid message size or prefix")
	}
	serverNonce := encrypted[serverMagicLen:responseHeaderLen]
	if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
		return encrypted, errors.New("Unexpected nonce")
	}
	var packet []byte
	var err error
	if serverInfo.CryptoConstruction == XChacha20Poly1305 {
		packet, err = xsecretbox.Open(nil, serverNonce, encrypted[responseHeaderLen:], sharedKey[:])
	} else {
		err = errors.New("Unsupported encryption system")
	}
	if err != nil {
		return encrypted, err
	}
	packet, err = unpad(packet)
	if err != nil || len(packet) < MinDNSPacketSize {
		return encrypted, errors.New("Incorrect padding")
	}
	return packet, nil
}
