package main

import (
    "bufio"
    "bytes"
    crypto_rand "crypto/rand"
    "crypto/sha512"
    "crypto/subtle"
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
    ErrInvalidPadding   = errors.New("invalid padding: delimiter not found")
    ErrInvalidPadBytes  = errors.New("invalid padding: non-zero bytes after delimiter")
    ErrInvalidMsgSize   = errors.New("invalid message size")
    ErrInvalidPrefix    = errors.New("invalid prefix")
    ErrUnexpectedNonce  = errors.New("unexpected nonce")
    ErrIncorrectTag     = errors.New("incorrect tag")
    ErrQuestionTooLarge = errors.New("question too large; cannot be padded")

    zeroPage [4096]byte

    // Pool for the plaintext padding buffer
    bufferPool = sync.Pool{
        New: func() interface{} {
            b := make([]byte, MaxDNSUDPPacketSize)
            return &b
        },
    }

    // Elite: Added pool for the final encrypted output to prevent heap escape
    encryptedPool = sync.Pool{
        New: func() interface{} {
            b := make([]byte, MaxDNSUDPPacketSize+QueryOverhead)
            return &b
        },
    }

    randReaderPool = sync.Pool{
        New: func() interface{} {
            return bufio.NewReaderSize(crypto_rand.Reader, 1024)
        },
    }
)

func padTo(packet []byte, minSize int) []byte {
    out := make([]byte, minSize)
    copy(out, packet)
    out[len(packet)] = 0x80
    return out
}

func unpad(packet []byte) ([]byte, error) {
    idx := bytes.LastIndexByte(packet, 0x80)
    if idx == -1 {
        return nil, ErrInvalidPadding
    }

    tailLen := len(packet) - idx - 1
    if tailLen > 0 {
        if tailLen > len(zeroPage) {
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
        
        // Elite: Use crypto/subtle for constant-time validation
        if subtle.ConstantTimeAllZero(sharedKey[:]) == 1 {
            logMsg := "Weak XSalsa20 public key"
            if providerName != nil {
                dlog.Criticalf("[%v] %s", *providerName, logMsg)
            } else {
                dlog.Critical(logMsg)
            }
            if _, err := crypto_rand.Read(sharedKey[:]); err != nil {
                dlog.Fatal(err)
            }
        }
    }
    return sharedKey
}

// Encrypt now returns the clientNonce as a fixed-size array to prevent heap allocation
func (proxy *Proxy) Encrypt(
    serverInfo *ServerInfo,
    packet []byte,
    proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce [HalfNonceSize]byte, err error) {
    // Zero-alloc: Read directly into the return array
    if err := readRandom(clientNonce[:]); err != nil {
        return nil, nil, clientNonce, err
    }

    var nonce [NonceSize]byte
    copy(nonce[:], clientNonce[:])

    var publicKey *[PublicKeySize]byte
    if proxy.ephemeralKeys {
        var buf [HalfNonceSize + 32]byte
        copy(buf[:], clientNonce[:])
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
            return nil, nil, clientNonce, err
        }
        minQuestionSize += int(xpad[0])
    }

    paddedLength := min(MaxDNSUDPPacketSize, (max(minQuestionSize, QueryOverhead)+1+63)&^63)
    if serverInfo.knownBugs.fragmentsBlocked && proto == "udp" {
        paddedLength = MaxDNSUDPSafePacketSize
    } else if serverInfo.Relay != nil && proto == "tcp" {
        paddedLength = MaxDNSPacketSize
    }

    if QueryOverhead+len(packet)+1 > paddedLength {
        return sharedKey, nil, clientNonce, ErrQuestionTooLarge
    }

    // Elite: Acquire pre-allocated output buffer from pool
    encPtr := encryptedPool.Get().(*[]byte)
    encrypted = (*encPtr)[:0] 

    encrypted = append(encrypted, serverInfo.MagicQuery[:]...)
    encrypted = append(encrypted, publicKey[:]...)
    encrypted = append(encrypted, clientNonce[:]...)

    plaintextLen := paddedLength - QueryOverhead
    ptr := bufferPool.Get().(*[]byte)
    paddedBuf := (*ptr)[:plaintextLen]

    copy(paddedBuf, packet)
    paddedBuf[len(packet)] = 0x80
    clear(paddedBuf[len(packet)+1:])

    if serverInfo.CryptoConstruction == XChacha20Poly1305 {
        encrypted = xsecretbox.Seal(encrypted, nonce[:], paddedBuf, sharedKey[:])
    } else {
        var xsalsaNonce [24]byte
        copy(xsalsaNonce[:], nonce[:])
        encrypted = secretbox.Seal(encrypted, paddedBuf, &xsalsaNonce, sharedKey)
    }

    bufferPool.Put(ptr)
    // Note: Caller must return 'encrypted' slice back to encryptedPool after use
    return sharedKey, encrypted, clientNonce, nil
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
        len(encrypted) > responseHeaderLen+TagSize+int(MaxDNSPacketSize) {
        return encrypted, ErrInvalidMsgSize
    }

    // Elite: Constant-time prefix check
    if subtle.ConstantTimeCompare(encrypted[:serverMagicLen], ServerMagic[:]) == 0 {
        return encrypted, ErrInvalidPrefix
    }

    serverNonce := encrypted[serverMagicLen:responseHeaderLen]
    // Elite: Constant-time nonce verification
    if subtle.ConstantTimeCompare(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) == 0 {
        return encrypted, ErrUnexpectedNonce
    }

    ciphertext := encrypted[responseHeaderLen:]
    outCap := len(ciphertext) - TagSize
    
    // Elite: Use pooled result buffer to avoid heap allocation per packet
    ptr := bufferPool.Get().(*[]byte)
    packet := (*ptr)[:0]

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
        bufferPool.Put(ptr)
        return encrypted, err
    }

    packet, err = unpad(packet)
    if err != nil || len(packet) < MinDNSPacketSize {
        bufferPool.Put(ptr)
        return encrypted, ErrInvalidPadding
    }

    // The returned packet is a slice of the pooled buffer. 
    // It must be used before the next Decrypt call or copied.
    return packet, nil
}
