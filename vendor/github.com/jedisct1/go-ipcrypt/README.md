# Go Implementation of IPCrypt

This is a Go implementation of the IP address encryption and obfuscation methods specified in the [ipcrypt document](https://datatracker.ietf.org/doc/draft-denis-ipcrypt/) ("Methods for IP Address Encryption and Obfuscation").

## Overview

The implementation provides four methods for IP address encryption:

1. **ipcrypt-deterministic**: A deterministic mode where the same input always produces the same output for a given key.
2. **ipcrypt-nd**: A non-deterministic mode that uses an 8-byte tweak for enhanced privacy.
3. **ipcrypt-ndx**: An extended non-deterministic mode that uses a 32-byte key and 16-byte tweak for increased security.
4. **ipcrypt-pfx**: A prefix-preserving mode that maintains the original IP format (IPv4 or IPv6).

## Installation

```sh
go get github.com/jedisct1/go-ipcrypt
```

## Usage

```go
package main

import (
    "crypto/rand"
    "fmt"
    "net"
    "github.com/jedisct1/go-ipcrypt"
)

func main() {
    // Create a 16-byte key for ipcrypt-deterministic mode
    key := make([]byte, ipcrypt.KeySizeDeterministic)
    rand.Read(key)

    // Encrypt an IP address (ipcrypt-deterministic mode)
    ip := net.ParseIP("192.168.1.1")
    encrypted, err := ipcrypt.EncryptIP(key, ip)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Encrypted: %s\n", encrypted)

    // Decrypt the IP address
    decrypted, err := ipcrypt.DecryptIP(key, encrypted)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Decrypted: %s\n", decrypted)

    // ipcrypt-nd mode with random tweak
    ndKey := make([]byte, ipcrypt.KeySizeND)
    rand.Read(ndKey)

    encryptedND, err := ipcrypt.EncryptIPNonDeterministic(ip.String(), ndKey, nil)
    if err != nil {
        panic(err)
    }

    decryptedND, err := ipcrypt.DecryptIPNonDeterministic(encryptedND, ndKey)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Non-deterministic decrypted: %s\n", decryptedND)

    // ipcrypt-ndx mode with random tweak
    xtsKey := make([]byte, ipcrypt.KeySizeNDX)
    rand.Read(xtsKey)

    encryptedX, err := ipcrypt.EncryptIPNonDeterministicX(ip.String(), xtsKey, nil)
    if err != nil {
        panic(err)
    }

    decryptedX, err := ipcrypt.DecryptIPNonDeterministicX(encryptedX, xtsKey)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Extended non-deterministic decrypted: %s\n", decryptedX)
}
```

## API Reference

### Constants

- `KeySizeDeterministic`: 16 bytes (ipcrypt-deterministic)
- `KeySizeND`: 16 bytes (ipcrypt-nd)
- `KeySizeNDX`: 32 bytes (ipcrypt-ndx)
- `TweakSize`: 8 bytes (ipcrypt-nd tweak)
- `TweakSizeX`: 16 bytes (ipcrypt-ndx tweak)

### Functions

#### Deterministic Mode
- `EncryptIP(key []byte, ip net.IP) (net.IP, error)` - Encrypts an IP address deterministically
- `DecryptIP(key []byte, encrypted net.IP) (net.IP, error)` - Decrypts an IP address deterministically

#### Prefix-Preserving Mode (ipcrypt-pfx)
- `EncryptIPPfx(ip net.IP, key []byte) (net.IP, error)` - Encrypts an IP address with prefix preservation
- `DecryptIPPfx(encryptedIP net.IP, key []byte) (net.IP, error)` - Decrypts an IP address with prefix preservation

#### Non-Deterministic Mode (ipcrypt-nd)
- `EncryptIPNonDeterministic(ip string, key []byte, tweak []byte) ([]byte, error)` - Encrypts with 8-byte tweak
- `DecryptIPNonDeterministic(ciphertext []byte, key []byte) (string, error)` - Decrypts ipcrypt-nd ciphertext

#### Extended Non-Deterministic Mode (ipcrypt-ndx)
- `EncryptIPNonDeterministicX(ip string, key []byte, tweak []byte) ([]byte, error)` - Encrypts with 16-byte tweak
- `DecryptIPNonDeterministicX(ciphertext []byte, key []byte) (string, error)` - Decrypts ipcrypt-ndx ciphertext
