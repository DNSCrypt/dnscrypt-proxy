package main

import (
"bufio"
"bytes"
crypto_rand "crypto/rand"
"crypto/sha512"
"errors"
"io"
"sync"

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

var (
// Pool for padding buffers (plaintext)
bufferPool = sync.Pool{
New: func() interface{} {
b := make([]byte, 0, 2048)
return &b
},
}

// Pool for buffered random readers to reduce syscall overhead
// reading 12 bytes at a time from /dev/urandom is inefficient.
randReaderPool = sync.Pool{
New: func() interface{} {
// 1KB buffer is plenty for ~85 queries before refilling
return bufio.NewReaderSize(crypto_rand.Reader, 1024)
},
}
)

// padTo copies packet to a new buffer of size minSize with ISO/IEC 7816-4 padding.
func padTo(packet []byte, minSize int) []byte {
out := make([]byte, minSize)
copy(out, packet)
out[len(packet)] = 0x80
return out
}

func unpad(packet []byte) ([]byte, error) {
// Optimization: Use assembly-optimized search for the delimiter
idx := bytes.LastIndexByte(packet, 0x80)
if idx == -1 {
return nil, errors.New("Invalid padding (delimiter not found)")
}

// Verify that all bytes after the delimiter are zero
// This scan is still necessary but the start point is found instantly
for i := idx + 1; i < len(packet); i++ {
if packet[i] != 0 {
return nil, errors.New("Invalid padding (non-zero bytes after delimiter)")
}
}
return packet[:idx], nil
}

// readRandom reads n bytes from a pooled buffered reader
func readRandom(p []byte) error {
reader := randReaderPool.Get().(*bufio.Reader)
_, err := io.ReadFull(reader, p)
randReaderPool.Put(reader)
return err
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
if providerName != nil {
dlog.Criticalf("[%v] Weak XChaCha20 public key", *providerName)
} else {
dlog.Criticalf("Weak XChaCha20 public key")
}
}
} else {
box.Precompute(&sharedKey, serverPk, secretKey)
c := byte(0)
for i := 0; i < 32; i++ {
c |= sharedKey[i]
}
if c == 0 {
if providerName != nil {
dlog.Criticalf("[%v] Weak XSalsa20 public key", *providerName)
} else {
dlog.Criticalf("Weak XSalsa20 public key")
}
if _, err := crypto_rand.Read(sharedKey[:]); err != nil {
dlog.Fatal(err)
}
}
}
return sharedKey
}

func (proxy *Proxy) Encrypt(
serverInfo *ServerInfo,
packet []byte,
proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
// 1. Zero-alloc, Batched Randomness
var nonce [NonceSize]byte
if err := readRandom(nonce[:HalfNonceSize]); err != nil {
return nil, nil, nil, err
}

clientNonceSlice := nonce[:HalfNonceSize]
var publicKey *[PublicKeySize]byte

if proxy.ephemeralKeys {
var buf [HalfNonceSize + 32]byte
copy(buf[:], clientNonceSlice)
copy(buf[HalfNonceSize:], proxy.proxySecretKey[:])
ephSk := sha512.Sum512_256(buf[:])
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
// Use pooled random for this byte too
if err := readRandom(xpad[:]); err != nil {
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
return sharedKey, nil, clientNonceSlice, errors.New("Question too large; cannot be padded")
}

totalSize := len(serverInfo.MagicQuery) + PublicKeySize + HalfNonceSize + (paddedLength - QueryOverhead) + TagSize
encrypted = make([]byte, 0, totalSize)

encrypted = append(encrypted, serverInfo.MagicQuery[:]...)
encrypted = append(encrypted, publicKey[:]...)
encrypted = append(encrypted, nonce[:HalfNonceSize]...)

plaintextLen := paddedLength - QueryOverhead
ptr := bufferPool.Get().(*[]byte)
paddedBuf := *ptr
if cap(paddedBuf) < plaintextLen {
paddedBuf = make([]byte, plaintextLen)
} else {
paddedBuf = paddedBuf[:plaintextLen]
}

copy(paddedBuf, packet)
paddedBuf[len(packet)] = 0x80
// Optimization: Efficient zeroing of the tail
tail := paddedBuf[len(packet)+1:]
for i := range tail {
tail[i] = 0
}

if serverInfo.CryptoConstruction == XChacha20Poly1305 {
encrypted = xsecretbox.Seal(encrypted, nonce[:], paddedBuf, sharedKey[:])
} else {
var xsalsaNonce [24]byte
copy(xsalsaNonce[:], nonce[:])
encrypted = secretbox.Seal(encrypted, paddedBuf, &xsalsaNonce, sharedKey)
}

*ptr = paddedBuf
bufferPool.Put(ptr)

retClientNonce := make([]byte, HalfNonceSize)
copy(retClientNonce, clientNonceSlice)

return sharedKey, encrypted, retClientNonce, nil
}

func (proxy *Proxy) Decrypt(
serverInfo *ServerInfo,
sharedKey *[32]byte,
encrypted []byte,
nonce []byte,
) ([]byte, error) {
// ... (Header checks omitted for brevity, same as before) ...
serverMagicLen := len(ServerMagic)
responseHeaderLen := serverMagicLen + NonceSize
if len(encrypted) < responseHeaderLen+TagSize+int(MinDNSPacketSize) ||
len(encrypted) > responseHeaderLen+TagSize+int(MaxDNSPacketSize) {
return encrypted, errors.New("Invalid message size")
}
if !bytes.Equal(encrypted[:serverMagicLen], ServerMagic[:]) {
return encrypted, errors.New("Invalid prefix")
}
serverNonce := encrypted[serverMagicLen:responseHeaderLen]
if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
return encrypted, errors.New("Unexpected nonce")
}

ciphertext := encrypted[responseHeaderLen:]

// Optimization: Pre-allocate result buffer to avoid internal re-allocs
// Size = Ciphertext - TagSize
outCap := len(ciphertext) - TagSize
if outCap < 0 { outCap = 0 }
packet := make([]byte, 0, outCap)

var err error
if serverInfo.CryptoConstruction == XChacha20Poly1305 {
packet, err = xsecretbox.Open(packet, serverNonce, ciphertext, sharedKey[:])
} else {
var xsalsaServerNonce [24]byte
copy(xsalsaServerNonce[:], serverNonce)
var ok bool
packet, ok = secretbox.Open(packet, ciphertext, &xsalsaServerNonce, sharedKey)
if !ok {
err = errors.New("Incorrect tag")
}
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
