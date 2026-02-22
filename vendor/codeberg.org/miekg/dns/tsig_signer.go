package dns

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"

	"codeberg.org/miekg/dns/internal/pack"
)

// HmacTSIG is TSIGSigner and TSIGVerifier that does the default HMAC for TSIG, see RFC 8945.
type HmacTSIG struct {
	Secret []byte
}

func (h HmacTSIG) Key() []byte { return h.Secret }

func (h HmacTSIG) Sign(t *TSIG, p []byte, options TSIGOption) ([]byte, error) {
	secret := h.Key()
	if secret == nil {
		return nil, fmt.Errorf("%w: %s", ErrKey, "HMAC sign")
	}

	var hs hash.Hash
	switch t.Algorithm {
	case HmacSHA1:
		hs = hmac.New(sha1.New, secret)
	case HmacSHA224:
		hs = hmac.New(sha256.New224, secret)
	case HmacSHA256:
		hs = hmac.New(sha256.New, secret)
	case HmacSHA384:
		hs = hmac.New(sha512.New384, secret)
	case HmacSHA512:
		hs = hmac.New(sha512.New, secret)
	default:
		return nil, fmt.Errorf("%w: %s", ErrKeyAlg, "HMAC sign")
	}
	hs.Write(p)
	return hs.Sum(nil), nil
}

func (h HmacTSIG) Verify(t *TSIG, p []byte, options TSIGOption) error {
	buf, err := h.Sign(t, p, options)
	if err != nil {
		return err
	}
	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}
	if !hmac.Equal(buf, mac) {
		return fmt.Errorf("%w: %s", ErrSig, "HMAC verify")
	}
	return nil
}

// mac creates the buffer with the TSIG and message data that can then be signed.
func (rr *TSIG) mac(m *Msg, options TSIGOption) ([]byte, error) {
	buf := []byte{}
	if options.RequestMAC != "" {
		mw := &macWireFmt{MAC: options.RequestMAC, MACSize: uint16(len(options.RequestMAC) / 2)}
		buf = make([]byte, len(mw.MAC)) // long enough
		n, err := mw.pack(buf)
		if err != nil {
			return nil, err
		}
		buf = buf[:n]
	}

	tsigvar := make([]byte, MinMsgSize)
	if options.TimersOnly {
		tw := &timerWireFmt{TimeSigned: rr.TimeSigned, Fudge: rr.Fudge}
		n, err := tw.pack(tsigvar)
		if err != nil {
			return nil, err
		}
		tsigvar = tsigvar[:n]

	} else {

		tw := new(tsigWireFmt)
		tw.Name = dnsutilCanonical(rr.Hdr.Name)
		tw.Class = ClassANY
		tw.TTL = rr.Hdr.TTL
		tw.Algorithm = rr.Algorithm
		tw.TimeSigned = rr.TimeSigned
		tw.Fudge = rr.Fudge
		tw.Error = rr.Error
		tw.OtherLen = rr.OtherLen
		tw.OtherData = rr.OtherData
		n, err := tw.pack(tsigvar)
		if err != nil {
			return nil, err
		}
		tsigvar = tsigvar[:n]
	}

	if options.RequestMAC != "" {
		buf = append(buf, m.Data...)
		buf = append(buf, tsigvar...)
		return buf, nil
	}
	return append(m.Data, tsigvar...), nil
}

// If we have the MAC use this type to convert it to wiredata. Section 3.4.3. Request MAC.
type macWireFmt struct {
	MACSize uint16
	MAC     string `dns:"size-hex:MACSize"`
}

func (mw *macWireFmt) pack(buf []byte) (int, error) {
	off, err := pack.Uint16(mw.MACSize, buf, 0)
	if err != nil {
		return off, err
	}
	off, err = pack.StringHex(mw.MAC, buf, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

// 3.3. Time values used in TSIG calculations.
type timerWireFmt struct {
	TimeSigned uint64 `dns:"uint48"`
	Fudge      uint16
}

func (tw *timerWireFmt) pack(buf []byte) (int, error) {
	off, err := pack.Uint48(tw.TimeSigned, buf, 0)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint16(tw.Fudge, buf, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

// The following values must be put in wireformat, so that the MAC can be calculated.
// RFC 2845, section 3.4.2. TSIG Variables.
type tsigWireFmt struct {
	// from Header
	Name  string `dns:"domain-name"`
	Class uint16
	TTL   uint32
	// Rdata of the TSIG
	Algorithm  string `dns:"domain-name"`
	TimeSigned uint64 `dns:"uint48"`
	Fudge      uint16
	// MACSize, MAC and OrigId excluded
	Error     uint16
	OtherLen  uint16
	OtherData string `dns:"size-hex:OtherLen"`
}

func (tw *tsigWireFmt) pack(buf []byte) (int, error) {
	// Header
	off, err := pack.Name(tw.Name, buf, 0, nil, false)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint16(tw.Class, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint32(tw.TTL, buf, off)
	if err != nil {
		return off, err
	}

	off, err = pack.Name(tw.Algorithm, buf, off, nil, false)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint48(tw.TimeSigned, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint16(tw.Fudge, buf, off)
	if err != nil {
		return off, err
	}

	off, err = pack.Uint16(tw.Error, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint16(tw.OtherLen, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.StringHex(tw.OtherData, buf, off)
	if err != nil {
		return off, err
	}
	return off, nil
}
