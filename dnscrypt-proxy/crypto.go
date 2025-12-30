package main

import (
"bytes"
crypto_rand "crypto/rand"
"crypto/sha512"
"errors"
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
// bufferPool reduces GC pressure by reusing buffers for plaintext padding
// Sized for typical UDP packets (~1280 bytes) to cover most DNS queries
bufferPool = sync.Pool{
New: func() interface{} {
b := make([]byte, 0, 2048)
return &b
},
}
)

// pad copies packet to a new buffer of size minSize with ISO/IEC 7816-4 padding.
// It avoids the iterative append loop for O(1) allocation.
func pad(packet []byte, minSize int) []byte {
out := make([]byte, minSize)
copy(out, packet)
out[len(packet)] = 0x80
// Remaining bytes are 0x00 by default (Go zero initialization)
return out
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
box.Precompute(&sharedKey, serverPk, secretKey)
// Constant time check for weak keys (all zeros)
c := byte(0)
for i := 0; i < 32; i++ {
c |= sharedKey[i]
}
if c == 0 {
dlog.Criticalf("[%v] Weak XSalsa20 public key", providerName)
// Fallback to random key to prevent catastrophic failure, though connection will fail
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
// 1. Stack allocate nonce to avoid heap alloc
var nonce [NonceSize]byte
// We only need to randomize the first HalfNonceSize bytes
if _, err := crypto_rand.Read(nonce[:HalfNonceSize]); err != nil {
return nil, nil, nil, err
}

// Slice for return value (points to stack array, forces escape? No, we return a copy usually,
// but here we return a slice. To be safe/efficient, we copy to a small return buffer
// or accept the escape. In this signature, clientNonce is returned.)
// Optimally, return [HalfNonceSize]byte, but signature is fixed.
// We'll create a slice view.
clientNonceSlice := nonce[:HalfNonceSize]

var publicKey *[PublicKeySize]byte

if proxy.ephemeralKeys {
// 2. Optimization: Use stack buffer for hashing to avoid sha512.New() allocation
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
return sharedKey, nil, clientNonceSlice, errors.New("Question too large; cannot be padded")
}

// 3. Optimization: Pre-allocate destination buffer with exact capacity
// Structure: [Magic][PublicKey][Nonce][Ciphertext(PaddedMsg + Tag)]
totalSize := len(serverInfo.MagicQuery) + PublicKeySize + HalfNonceSize + (paddedLength - QueryOverhead) + TagSize
encrypted = make([]byte, 0, totalSize)

// Build Header
encrypted = append(encrypted, serverInfo.MagicQuery[:]...)
encrypted = append(encrypted, publicKey[:]...)
encrypted = append(encrypted, nonce[:HalfNonceSize]...)

// 4. Optimization: Efficient Padding
// Calculate size of plaintext to be encrypted
plaintextLen := paddedLength - QueryOverhead

// Get buffer from pool to avoid allocating 'padded' slice
ptr := bufferPool.Get().(*[]byte)
paddedBuf := *ptr
if cap(paddedBuf) < plaintextLen {
paddedBuf = make([]byte, plaintextLen)
} else {
paddedBuf = paddedBuf[:plaintextLen]
}

// Copy packet and add padding
copy(paddedBuf, packet)
paddedBuf[len(packet)] = 0x80
// Zero out the rest of the buffer (reuse might leave old data)
for i := len(packet) + 1; i < plaintextLen; i++ {
paddedBuf[i] = 0
}

// Seal appends to 'encrypted'
if serverInfo.CryptoConstruction == XChacha20Poly1305 {
encrypted = xsecretbox.Seal(encrypted, nonce[:], paddedBuf, sharedKey[:])
} else {
var xsalsaNonce [24]byte
copy(xsalsaNonce[:], nonce[:])
encrypted = secretbox.Seal(encrypted, paddedBuf, &xsalsaNonce, sharedKey)
}

// Return buffer to pool
// Note: For high security, one might want to Zero this before returning,
// but that trades performance.
*ptr = paddedBuf
bufferPool.Put(ptr)

// We must return a copy of clientNonce because it was stack allocated and 'nonce' array is gone?
// Actually, returning a slice to a stack array is invalid in C, but in Go it forces the array to heap.
// To strictly optimize, we should return a copy if we want 'nonce' to stay on stack for the calculation part.
// But since the interface requires returning `clientNonce []byte`, we just return a new slice copy.
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
serverMagicLen := len(ServerMagic)
responseHeaderLen := serverMagicLen + NonceSize

// Quick bounds check
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

var packet []byte
var err error

// Use ciphertext slice directly to avoid copying
ciphertext := encrypted[responseHeaderLen:]

if serverInfo.CryptoConstruction == XChacha20Poly1305 {
// Open appends to nil, allocating result
packet, err = xsecretbox.Open(nil, serverNonce, ciphertext, sharedKey[:])
} else {
var xsalsaServerNonce [24]byte
copy(xsalsaServerNonce[:], serverNonce)

var ok bool
// Optimization: We could reuse a buffer here if we had a per-request scratch space
packet, ok = secretbox.Open(nil, ciphertext, &xsalsaServerNonce, sharedKey)
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
