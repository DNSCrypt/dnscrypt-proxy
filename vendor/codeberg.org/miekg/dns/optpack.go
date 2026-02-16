package dns

import (
	"fmt"

	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

func unpackOPT(s *cryptobyte.String) ([]EDNS0, error) {
	edns0 := []EDNS0{}
	for !s.Empty() {
		var (
			code uint16
			data cryptobyte.String
		)
		if !s.ReadUint16(&code) || !s.ReadUint16LengthPrefixed(&data) {
			return nil, unpack.ErrOverflow
		}
		var option EDNS0
		if newFn, ok := CodeToRR[code]; ok {
			option = newFn()
		} else {
			option = &ERFC3597{EDNS0Code: code}
		}
		if err := unpackOptionCode(option, &data); err != nil {
			return nil, err
		}
		edns0 = append(edns0, option)
	}
	return edns0, nil
}

func packOPT(options []EDNS0, msg []byte, off int) (int, error) {
	for i := range options {
		l := options[i].Len()
		if off+l >= len(msg) {
			return len(msg), pack.ErrBuf
		}
		code := RRToCode(options[i])
		if code == CodeNone {
			if erfc3597, ok := options[i].(*ERFC3597); ok {
				code = erfc3597.EDNS0Code
			} else {
				// really the last option
				return len(msg), fmt.Errorf("unknown option code")
			}
		}

		pack.Uint16(code, msg, off)
		pack.Uint16(uint16(l-tlv), msg, off+2)
		if /*optionoff*/ _, err := packOptionCode(options[i], msg, off+4); err != nil {
			return len(msg), err
		}
		// TODO(miek): if l != opentionoff ? We overestimated l, but that's the length we've packed
		off += l
	}
	return off, nil
}
