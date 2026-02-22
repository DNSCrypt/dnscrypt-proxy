package dns

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/internal/dnslex"
	"codeberg.org/miekg/dns/internal/pack"
)

// NewPrivate returns a crypto.PrivateKey by parsing the string s.
// s should be in the same form of the BIND private key files.
func (k *DNSKEY) NewPrivate(s string) (crypto.PrivateKey, error) {
	if s == "" || s[len(s)-1] != '\n' { // We need a closing newline
		return k.readPrivate(strings.NewReader(s+"\n"), "")
	}
	return k.readPrivate(strings.NewReader(s), "")
}

// readPrivate reads a private key from the io.Reader q. The string file is only used in error reporting.
// The public key must be known, because some cryptographic algorithms embed
// the public inside the privatekey.
func (k *DNSKEY) readPrivate(q io.Reader, file string) (crypto.PrivateKey, error) {
	m, err := parseKey(q, file)
	if m == nil {
		return nil, err
	}
	if _, ok := m["private-key-format"]; !ok {
		return nil, fmt.Errorf("private-key-format not found")
	}
	if m["private-key-format"] != "v1.2" && m["private-key-format"] != "v1.3" {
		return nil, fmt.Errorf("private-key-format v1.2 or v.1.3 not found")
	}
	// TODO(mg): check if the pubkey matches the private key
	algostr, _, _ := strings.Cut(m["algorithm"], " ")
	algo, err := strconv.ParseUint(algostr, 10, 8)
	if err != nil {
		return nil, err
	}
	switch uint8(algo) {
	case RSASHA1, RSASHA1NSEC3SHA1, RSASHA256, RSASHA512:
		priv, err := readPrivateKeyRSA(m)
		if err != nil {
			return nil, err
		}
		pub := k.publicKeyRSA()
		if pub == nil {
			return nil, ErrKey
		}
		priv.PublicKey = *pub
		return priv, nil
	case ECDSAP256SHA256, ECDSAP384SHA384:
		priv, err := readPrivateKeyECDSA(m)
		if err != nil {
			return nil, err
		}
		pub := k.publicKeyECDSA()
		if pub == nil {
			return nil, ErrKey
		}
		priv.PublicKey = *pub
		return priv, nil
	case ED25519:
		return readPrivateKeyED25519(m)
	default:
		return nil, ErrAlg
	}
}

// Read a private key (file) string and create a public key. Return the private key.
func readPrivateKeyRSA(m map[string]string) (*rsa.PrivateKey, error) {
	p := new(rsa.PrivateKey)
	p.Primes = []*big.Int{nil, nil}
	for k, v := range m {
		switch k {
		case "modulus", "publicexponent", "privateexponent", "prime1", "prime2":
			v1, err := pack.Base64([]byte(v))
			if err != nil {
				return nil, err
			}
			switch k {
			case "modulus":
				p.N = new(big.Int).SetBytes(v1)
			case "publicexponent":
				i := new(big.Int).SetBytes(v1)
				p.E = int(i.Int64()) // int64 should be large enough
			case "privateexponent":
				p.D = new(big.Int).SetBytes(v1)
			case "prime1":
				p.Primes[0] = new(big.Int).SetBytes(v1)
			case "prime2":
				p.Primes[1] = new(big.Int).SetBytes(v1)
			}
		case "exponent1", "exponent2", "coefficient":
			// not used in Go (yet)
		case "created", "publish", "activate":
			// not used in Go (yet)
		}
	}
	return p, nil
}

func readPrivateKeyECDSA(m map[string]string) (*ecdsa.PrivateKey, error) {
	p := new(ecdsa.PrivateKey)
	p.D = new(big.Int)
	for k, v := range m {
		switch k {
		case "privatekey":
			v1, err := pack.Base64([]byte(v))
			if err != nil {
				return nil, err
			}
			p.D.SetBytes(v1)
		case "created", "publish", "activate":
			/* not used in Go (yet) */
		}
	}
	return p, nil
}

func readPrivateKeyED25519(m map[string]string) (ed25519.PrivateKey, error) {
	var p ed25519.PrivateKey
	for k, v := range m {
		switch k {
		case "privatekey":
			p1, err := pack.Base64([]byte(v))
			if err != nil {
				return nil, err
			}
			if len(p1) != ed25519.SeedSize {
				return nil, fmt.Errorf("ed25519 seed size error")
			}
			p = ed25519.NewKeyFromSeed(p1)
		case "created", "publish", "activate":
			/* not used in Go (yet) */
		}
	}
	return p, nil
}

// parseKey reads a private key from r. It returns a map[string]string,
// with the key-value pairs, or an error when the file is not correct.
func parseKey(r io.Reader, file string) (map[string]string, error) {
	m := make(map[string]string)
	var k string

	c := newKLexer(r)

	for l, ok := c.Next(); ok; l, ok = c.Next() {
		switch l.Value {
		case zKey:
			k = l.Token
		case zValue:
			if k == "" {
				return nil, &ParseError{file: file, err: "no private key seen", lex: l}
			}
			m[strings.ToLower(k)] = l.Token
			k = ""
		}
	}

	if err := c.Err(); err != nil {
		return nil, &ParseError{file: file, err: err.Error()}
	}
	return m, nil
}

type klexer struct {
	br io.ByteReader

	readErr error

	line   uint32
	column uint16

	key bool
	eol bool // end-of-line
}

func newKLexer(r io.Reader) *klexer {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = bufio.NewReaderSize(r, 1024)
	}

	return &klexer{
		br:   br,
		line: 1,
		key:  true,
	}
}

func (kl *klexer) Err() error {
	if kl.readErr == io.EOF {
		return nil
	}
	return kl.readErr
}

// readByte returns the next byte from the input
func (kl *klexer) readByte() (byte, bool) {
	if kl.readErr != nil {
		return 0, false
	}

	c, err := kl.br.ReadByte()
	if err != nil {
		kl.readErr = err
		return 0, false
	}

	// delay the newline handling until the next token is delivered,
	// fixes off-by-one errors when reporting a parse error.
	if kl.eol {
		kl.line++
		kl.column = 0
		kl.eol = false
	}

	if c == '\n' {
		kl.eol = true
	} else {
		kl.column++
	}
	return c, true
}

func (kl *klexer) Next() (dnslex.Lex, bool) {
	var (
		l     dnslex.Lex
		str   strings.Builder
		commt bool
	)

	for x, ok := kl.readByte(); ok; x, ok = kl.readByte() {
		l.Line, l.Column = kl.line, kl.column

		switch x {
		case ':':
			if commt || !kl.key {
				break
			}

			kl.key = false

			// Next token is a space, eat it
			kl.readByte()

			l.Value = zKey
			l.Token = str.String()
			return l, true
		case ';':
			commt = true
		case '\n':
			if commt {
				// Reset a comment
				commt = false
			}

			if kl.key && str.Len() == 0 {
				// ignore empty lines
				break
			}

			kl.key = true

			l.Value = zValue
			l.Token = str.String()
			return l, true
		default:
			if commt {
				break
			}

			str.WriteByte(x)
		}
	}

	if kl.readErr != nil && kl.readErr != io.EOF {
		// Don't return any tokens after a read error occurs.
		return dnslex.Lex{Value: dnslex.EOF}, false
	}

	if str.Len() > 0 {
		// Send remainder
		l.Value = zValue
		l.Token = str.String()
		return l, true
	}
	return dnslex.Lex{Value: dnslex.EOF}, false
}
