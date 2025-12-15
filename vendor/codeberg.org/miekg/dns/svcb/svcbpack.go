package svcb

import (
	"slices"

	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"golang.org/x/crypto/cryptobyte"
)

func Unpack(s *cryptobyte.String) ([]Pair, error) {
	var pairs []Pair
	key := uint16(0)
	for !s.Empty() {
		var data cryptobyte.String
		if !s.ReadUint16(&key) || !s.ReadUint16LengthPrefixed(&data) {
			return nil, unpack.ErrOverflow
		}
		pairFn := KeyToPair(key)
		if pairFn == nil {
			return nil, unpack.Errorf("bad SVCB key")
		}
		pair := pairFn()

		if err := _unpack(pair, &data); err != nil {
			return nil, err
		}
		pairs = append(pairs, pair)
	}
	return pairs, nil
}

func Pack(pairs []Pair, msg []byte, off int) (off1 int, err error) {
	pairs = slices.Clone(pairs)
	prev := KeyReserved
	for _, pair := range pairs {
		key := PairToKey(pair)
		if key == prev {
			return len(msg), pack.Errorf("repeated SVCB keys are not allowed")
		}
		prev = key
		off, err = _pack(pair, msg, off)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}
