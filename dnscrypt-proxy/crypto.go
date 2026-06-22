package main

import (
	"bytes"
	crypto_rand "crypto/rand"
	"crypto/sha512"
	"errors"

	"github.com/jedisct1/dlog"
	"github.com/jedisct1/xsecretbox"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
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

func isClassicDNSCryptConstruction(cryptoConstruction CryptoConstruction) bool {
	return cryptoConstruction == XSalsa20Poly1305 || cryptoConstruction == XChacha20Poly1305
}

func ComputeSharedKey(
	cryptoConstruction CryptoConstruction,
	secretKey *[32]byte,
	serverPk *[32]byte,
	providerName *string,
) (sharedKey [32]byte) {
	if !isClassicDNSCryptConstruction(cryptoConstruction) {
		return [32]byte{}
	}
	if cryptoConstruction == XChacha20Poly1305 {
		var err error
		sharedKey, err = xsecretbox.SharedKey(*secretKey, *serverPk)
		if err != nil {
			dlog.Criticalf("[%v] Weak XChaCha20 public key", providerName)
			if _, err := crypto_rand.Read(sharedKey[:]); err != nil {
				dlog.Fatal(err)
			}
		}
	} else {
		box.Precompute(&sharedKey, serverPk, secretKey)
		c := byte(0)
		for i := range 32 {
			c |= sharedKey[i]
		}
		if c == 0 {
			dlog.Criticalf("[%v] Weak XSalsa20 public key", providerName)
			if _, err := crypto_rand.Read(sharedKey[:]); err != nil {
				dlog.Fatal(err)
			}
		}
	}
	return sharedKey
}

// setDNSCryptClientKeyLocked installs a fresh client keypair. The caller must
// hold proxy.cryptoKeyMu for writing.
func (proxy *Proxy) setDNSCryptClientKeyLocked(secretKey [32]byte) {
	proxy.proxySecretKey = secretKey
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)
}

// recomputeServerSharedKeyLocked refreshes a classic server's shared key from
// the current client key. The caller must hold proxy.cryptoKeyMu.
func (proxy *Proxy) recomputeServerSharedKeyLocked(serverInfo *ServerInfo) {
	if !isClassicDNSCryptConstruction(serverInfo.CryptoConstruction) {
		return
	}
	serverInfo.SharedKey = ComputeSharedKey(
		serverInfo.CryptoConstruction,
		&proxy.proxySecretKey,
		&serverInfo.ServerPk,
		&serverInfo.Name,
	)
}

func (proxy *Proxy) initDNSCryptClientKey() error {
	var secretKey [32]byte
	if _, err := crypto_rand.Read(secretKey[:]); err != nil {
		return err
	}
	proxy.cryptoKeyMu.Lock()
	proxy.setDNSCryptClientKeyLocked(secretKey)
	proxy.cryptoKeyMu.Unlock()
	return nil
}

func (proxy *Proxy) rotateDNSCryptClientKey() error {
	var secretKey [32]byte
	if _, err := crypto_rand.Read(secretKey[:]); err != nil {
		return err
	}
	proxy.cryptoKeyMu.Lock()
	proxy.setDNSCryptClientKeyLocked(secretKey)
	proxy.serversInfo.Lock()
	for _, serverInfo := range proxy.serversInfo.inner {
		proxy.recomputeServerSharedKeyLocked(serverInfo)
	}
	proxy.serversInfo.Unlock()
	proxy.cryptoKeyMu.Unlock()
	return nil
}

func (proxy *Proxy) computeSharedKey(
	cryptoConstruction CryptoConstruction,
	serverPk *[32]byte,
	providerName *string,
) [32]byte {
	proxy.cryptoKeyMu.RLock()
	defer proxy.cryptoKeyMu.RUnlock()
	return ComputeSharedKey(cryptoConstruction, &proxy.proxySecretKey, serverPk, providerName)
}

func (proxy *Proxy) Encrypt(
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, queryEpoch uint64, err error) {
	if serverInfo.CryptoConstruction == XWingPQ {
		return proxy.encryptPQ(serverInfo, packet, proto)
	}
	nonce, clientNonce := make([]byte, NonceSize), make([]byte, HalfNonceSize)
	if _, err := crypto_rand.Read(clientNonce); err != nil {
		return nil, nil, nil, queryEpoch, err
	}
	copy(nonce, clientNonce)
	var publicKey *[PublicKeySize]byte
	if proxy.ephemeralKeys {
		proxy.cryptoKeyMu.RLock()
		secretKey := proxy.proxySecretKey
		proxy.cryptoKeyMu.RUnlock()
		h := sha512.New512_256()
		h.Write(clientNonce)
		h.Write(secretKey[:])
		var ephSk [32]byte
		h.Sum(ephSk[:0])
		var xPublicKey [PublicKeySize]byte
		curve25519.ScalarBaseMult(&xPublicKey, &ephSk)
		publicKey = &xPublicKey
		xsharedKey := ComputeSharedKey(serverInfo.CryptoConstruction, &ephSk, &serverInfo.ServerPk, nil)
		sharedKey = &xsharedKey
	} else {
		proxy.cryptoKeyMu.RLock()
		serverSharedKey := serverInfo.SharedKey
		proxyPublicKey := proxy.proxyPublicKey
		proxy.cryptoKeyMu.RUnlock()
		sharedKey = &serverSharedKey
		publicKey = &proxyPublicKey
	}
	minQuestionSize := QueryOverhead + len(packet)
	if proto == "udp" {
		minQuestionSize = Max(proxy.questionSizeEstimator.MinQuestionSize(), minQuestionSize)
	} else {
		var xpad [1]byte
		if _, err := crypto_rand.Read(xpad[:]); err != nil {
			return nil, nil, nil, queryEpoch, err
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
		return sharedKey, encrypted, clientNonce, queryEpoch, err
	}
	encrypted = append(serverInfo.MagicQuery[:], publicKey[:]...)
	encrypted = append(encrypted, nonce[:HalfNonceSize]...)
	padded := pad(packet, paddedLength-QueryOverhead)
	if serverInfo.CryptoConstruction == XChacha20Poly1305 {
		encrypted = xsecretbox.Seal(encrypted, nonce, padded, sharedKey[:])
	} else {
		var xsalsaNonce [24]byte
		copy(xsalsaNonce[:], nonce)
		encrypted = secretbox.Seal(encrypted, padded, &xsalsaNonce, sharedKey)
	}
	return sharedKey, encrypted, clientNonce, queryEpoch, err
}

func (proxy *Proxy) Decrypt(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	encrypted []byte,
	nonce []byte,
	queryEpoch uint64,
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
	switch serverInfo.CryptoConstruction {
	case XChacha20Poly1305, XWingPQ:
		packet, err = xsecretbox.Open(nil, serverNonce, encrypted[responseHeaderLen:], sharedKey[:])
	default:
		var xsalsaServerNonce [24]byte
		copy(xsalsaServerNonce[:], serverNonce)
		var ok bool
		packet, ok = secretbox.Open(nil, encrypted[responseHeaderLen:], &xsalsaServerNonce, sharedKey)
		if !ok {
			err = errors.New("Incorrect tag")
		}
	}
	if err != nil {
		return encrypted, err
	}
	if serverInfo.CryptoConstruction == XWingPQ {
		packet, err = proxy.pqStripControl(serverInfo, sharedKey, nonce, packet, queryEpoch)
		if err != nil {
			return encrypted, err
		}
	}
	packet, err = unpad(packet)
	if err != nil || len(packet) < MinDNSPacketSize {
		return encrypted, errors.New("Incorrect padding")
	}
	return packet, nil
}
