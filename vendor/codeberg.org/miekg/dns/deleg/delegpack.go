package deleg

import (
	"slices"

	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"codeberg.org/miekg/dns/pkg/dnsnet"
)

func Unpack(s *dnsnet.String) ([]Info, error) {
	var infos []Info
	key := uint16(0)
	for !s.Empty() {
		var data dnsnet.String
		if !s.ReadUint16(&key) || !s.ReadUint16LengthPrefixed(&data.String) {
			return nil, unpack.ErrOverflow
		}
		infoFn := KeyToInfo(key)
		if infoFn == nil {
			return nil, unpack.Errorf("bad DELEG key")
		}
		info := infoFn()
		if err := _unpack(info, &data); err != nil {
			return nil, err
		}
		if !data.Empty() {
			return nil, unpack.ErrTrailingData
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func Pack(infos []Info, msg []byte, off int) (off1 int, err error) {
	infos = slices.Clone(infos)
	prev := KeyReserved
	for _, info := range infos {
		key := InfoToKey(info)
		if key == prev {
			return len(msg), pack.Errorf("repeated DELEG keys are not allowed")
		}
		prev = key
		off, err = _pack(info, msg, off)
		if err != nil {
			return len(msg), err
		}
	}
	return off, nil
}
