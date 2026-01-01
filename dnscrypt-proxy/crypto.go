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
    // Pre-allocated errors to avoid runtime allocation
    ErrInvalidPadding   = errors.New("invalid padding: delimiter not found")
    ErrInvalidPadBytes  = errors.New("invalid padding: non-zero bytes after delimiter")
    ErrInvalidMsgSize   = errors.New("invalid message size")
    ErrInvalidPrefix    = errors.New("invalid prefix")
    ErrUnexpectedNonce  = errors.New("unexpected nonce")
    ErrIncorrectTag     = errors.New("incorrect tag")
    ErrQuestionTooLarge = errors.New("question too large; cannot be padded")

    // Global zero buffer for efficient padding verification (memcmp)
    // Size covers MaxDNSUDPPacketSize to ensure we can always compare.
    zeroPage [4096]byte

    // Pool for padding buffers (plaintext)
    // Storing *[]byte avoids interface conversion overhead on slice headers
    bufferPool = sync.Pool{
        New: func() interface{} {
            b := make([]byte, 0, 2048)
            return &b
        },
    }

    // Pool for buffered random readers
    randReaderPool = sync.Pool{
        New: func() interface{} {
            // 1KB buffer reduces syscalls for batched queries
            return bufio.NewReaderSize(crypto_rand.Reader, 1024)
        },
    }
)

// padTo copies packet to a new buffer of size minSize with ISO/IEC 7816-4 padding.
func padTo(packet []byte, minSize int) []byte {
    out := make([]byte, minSize)
    copy(out, packet)
    out[len(packet)] = 0x80
    // Remaining bytes are zero-initialized by make()
    return out
}

func unpad(packet []byte) ([]byte, error) {
    // Optimization: Assembly-optimized search
    idx := bytes.LastIndexByte(packet, 0x80)
    if idx == -1 {
        return nil, ErrInvalidPadding
    }

    // Optimization: Verify trailing zeros using SIMD-optimized memcmp (bytes.Equal)
    // instead of a slow loop.
    tailLen := len(packet) - idx - 1
    if tailLen > 0 {
        if tailLen > len(zeroPage) {
            // Fallback for theoretically huge packets (unlikely in DNS)
            for i := idx + 1; i < len(packet); i++ {
                if packet[i] != 0 {
                    return nil, ErrInvalidPadBytes
                }
            }
        } else if !bytes.Equal(packet[idx+1:], zeroPage[:tailLen]) {
            return nil, ErrInvalidPadBytes
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
            logMsg := "Weak XChaCha20 public key"
            if providerName != nil {
                dlog.Criticalf("[%v] %s", *providerName, logMsg)
            } else {
                dlog.Critical(logMsg)
            }
        }
    } else {
        box.Precompute(&sharedKey, serverPk, secretKey)
        
        // Manual constant-time check for zero key
        var c byte
        for _, b := range sharedKey {
            c |= b
        }
        
        if c == 0 {
            logMsg := "Weak XSalsa20 public key"
            if providerName != nil {
                dlog.Criticalf("[%v] %s", *providerName, logMsg)
            } else {
                dlog.Critical(logMsg)
            }
            // Fallback to random to prevent catastrophe (though caller likely panics/exits)
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
        minQuestionSize = max(proxy.questionSizeEstimator.MinQuestionSize(), minQuestionSize)
    } else {
        var xpad [1]byte
        if err := readRandom(xpad[:]); err != nil {
            return nil, nil, nil, err
        }
        minQuestionSize += int(xpad[0])
    }

    // Upgrade: Use Go 1.21 max/min builtins
    paddedLength := min(MaxDNSUDPPacketSize, (max(minQuestionSize, QueryOverhead)+1+63)&^63)
    if serverInfo.knownBugs.fragmentsBlocked && proto == "udp" {
        paddedLength = MaxDNSUDPSafePacketSize
    } else if serverInfo.Relay != nil && proto == "tcp" {
        paddedLength = MaxDNSPacketSize
    }

    if QueryOverhead+len(packet)+1 > paddedLength {
        return sharedKey, nil, clientNonceSlice, ErrQuestionTooLarge
    }

    totalSize := len(serverInfo.MagicQuery) + PublicKeySize + HalfNonceSize + (paddedLength - QueryOverhead) + TagSize
    encrypted = make([]byte, 0, totalSize)

    encrypted = append(encrypted, serverInfo.MagicQuery[:]...)
    encrypted = append(encrypted, publicKey[:]...)
    encrypted = append(encrypted, nonce[:HalfNonceSize]...)

    plaintextLen := paddedLength - QueryOverhead
    ptr := bufferPool.Get().(*[]byte)
    paddedBuf := *ptr

    // Ensure capacity without discarding pooled memory if possible
    if cap(paddedBuf) < plaintextLen {
        paddedBuf = make([]byte, plaintextLen)
    } else {
        paddedBuf = paddedBuf[:plaintextLen]
    }

    copy(paddedBuf, packet)
    paddedBuf[len(packet)] = 0x80

    // Upgrade: Use clear() for efficient intrinsic zeroing (Go 1.21+)
    tail := paddedBuf[len(packet)+1:]
    clear(tail)

    if serverInfo.CryptoConstruction == XChacha20Poly1305 {
        encrypted = xsecretbox.Seal(encrypted, nonce[:], paddedBuf, sharedKey[:])
    } else {
        var xsalsaNonce [24]byte
        copy(xsalsaNonce[:], nonce[:])
        encrypted = secretbox.Seal(encrypted, paddedBuf, &xsalsaNonce, sharedKey)
    }

    // Update the pool pointer to the potentially larger buffer
    *ptr = paddedBuf
    bufferPool.Put(ptr)

    // Allocation Note: We must allocate for the return value here as it escapes.
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

    // Pre-check constraints
    if len(encrypted) < responseHeaderLen+TagSize+int(MinDNSPacketSize) ||
        len(encrypted) > responseHeaderLen+TagSize+int(MaxDNSPacketSize) {
        return encrypted, ErrInvalidMsgSize
    }

    if !bytes.Equal(encrypted[:serverMagicLen], ServerMagic[:]) {
        return encrypted, ErrInvalidPrefix
    }

    serverNonce := encrypted[serverMagicLen:responseHeaderLen]
    if !bytes.Equal(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) {
        return encrypted, ErrUnexpectedNonce
    }

    ciphertext := encrypted[responseHeaderLen:]

    // Optimization: Pre-allocate result buffer to avoid internal re-allocs
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
            err = ErrIncorrectTag
        }
    }

    if err != nil {
        return encrypted, err
    }

    packet, err = unpad(packet)
    if err != nil || len(packet) < MinDNSPacketSize {
        return encrypted, ErrInvalidPadding
    }

    return packet, nil
}
