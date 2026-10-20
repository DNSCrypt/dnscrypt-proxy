package dns

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"codeberg.org/miekg/dns/dnsjson"
	"golang.org/x/crypto/cryptobyte"
)

// MarshalJSON returns the JSON (RFC 8427) representation of [RR] as defined in [dnsjson.RR]. If more than one
// [RR] is given it is assumed this represents a [dnsjson.RRset].
func MarshalJSON(rrs ...RR) ([]byte, error) {
	buf := dnsjson.Pool.Get()
	defer dnsjson.Pool.Put(buf)

	jrr := &dnsjson.RR{
		Name:      rrs[0].Header().Name,
		TTL:       rrs[0].Header().TTL,
		TypeName:  typeToString(RRToType(rrs[0])),
		ClassName: classToString(rrs[0].Header().Class),
	}

	switch len(rrs) {
	case 1:
		if l := rrs[0].Len(); cap(buf) < l {
			buf = make([]byte, l)
		}

		off, err := zpack(rrs[0], buf, 0, nil)
		if err != nil {
			return nil, err
		}
		jrr.RdataHex = hex.EncodeToString(buf[:off])
	default:
		jrr.RRset = make([]dnsjson.RRset, len(rrs))
		for i, rr := range rrs {
			if l := rr.Len(); cap(buf) < l {
				buf = make([]byte, l)
			}

			off, err := zpack(rr, buf, 0, nil)
			if err != nil {
				return nil, err
			}
			jrr.RRset[i].RdataHex = hex.EncodeToString(buf[:off])
		}
	}

	return json.Marshal(jrr)
}

// UnmarshalJSON returns the [RR] from the JSON (RFC 8427) object. If class (CLASS, or CLASSname) is not set, [ClassINET] is assumed.
func UnmarshalJSON(data []byte) ([]RR, error) {
	jrr := &dnsjson.RR{}
	if err := json.Unmarshal(data, jrr); err != nil {
		return nil, err
	}
	rrs := make([]RR, 1)
	if len(jrr.RRset) > 0 {
		rrs = make([]RR, len(jrr.RRset))
	}

	var ok bool
	newfn := func() RR { return nil }
	switch {
	case jrr.Type > 0:
		newfn, ok = TypeToRR[jrr.Type]
	case jrr.TypeName != "":
		newfn, ok = TypeToRR[StringToType[jrr.TypeName]]
	}
	if !ok {
		return nil, fmt.Errorf("bad RR type")
	}

	class := uint16(0)
	switch {
	case jrr.Class > 0:
		class = jrr.Class
	case jrr.ClassName != "":
		class, _ = StringToClass[jrr.ClassName]
	default:
		class = ClassINET
	}

	buf := dnsjson.Pool.Get()
	defer dnsjson.Pool.Put(buf)

	switch len(rrs) {
	case 1:
		rrs[0] = newfn()

		rrs[0].Header().Name = jrr.Name
		rrs[0].Header().TTL = jrr.TTL
		rrs[0].Header().Class = class

		if l := hex.DecodedLen(len(jrr.RdataHex)); cap(buf) < l {
			buf = make([]byte, l)
		}

		n, err := hex.Decode(buf, []byte(jrr.RdataHex))
		if err != nil {
			return nil, err
		}
		if err := zunpack(rrs[0], cryptobyte.String(buf[:n]), nil); err != nil {
			return nil, err
		}
	default:
		for i := range rrs {
			rrs[i] = newfn()

			rrs[i].Header().Name = jrr.Name
			rrs[i].Header().TTL = jrr.TTL
			rrs[i].Header().Class = class

			if l := hex.DecodedLen(len(jrr.RRset[i].RdataHex)); cap(buf) < l {
				buf = make([]byte, l)
			}

			n, err := hex.Decode(buf, []byte(jrr.RRset[i].RdataHex))
			if err != nil {
				return nil, err
			}
			if err := zunpack(rrs[i], cryptobyte.String(buf[:n]), nil); err != nil {
				return nil, err
			}
		}
	}

	return rrs, nil
}
