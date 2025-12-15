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
			return nil, unpack.Errorf("unknown OPT code %d", code)
		}
		if err := unpackOptionCode(option, &data); err != nil {
			return nil, err
		}
		edns0 = append(edns0, option)
	}
	return edns0, nil
}

func packOPT(options []EDNS0, msg []byte, off int) (int, error) {
	for _, option := range options {
		l := option.Len()
		if off+l >= len(msg) {
			return len(msg), pack.ErrBuf
		}
		code := RRToCode(option) // TODO(miek): Use Coder for externally supplied option code
		if code == CodeNone {
			return len(msg), fmt.Errorf("unknown option code seen")
		}

		pack.Uint16(code, msg, off)
		pack.Uint16(uint16(l-tlv), msg, off+2)
		if /*optionoff*/ _, err := packOptionCode(option, msg, off+4); err != nil {
			return len(msg), err
		}
		// TODO(miek): if l != opentionoff ? We overestimated l, but that's the length we've packed
		off += l
	}
	return off, nil
}
