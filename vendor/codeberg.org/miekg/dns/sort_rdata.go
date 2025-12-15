package dns

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"

	"codeberg.org/miekg/dns/deleg"
	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/pool"
	"codeberg.org/miekg/dns/svcb"
)

// comparename compares owernames in rdata, which is a difference compare that canonical because the
// actual wire data needs to be looked up, so we pack the names and compare them both.
func comparename(a, b string) int {
	if a == "" && b == "" {
		return 0
	}
	// optimize: before getting to the wiredata compare first label length, if not equal we already
	// have a sorting. We only care about equal.
	// TODO(miek): we might get away with no allocations and no wire data here...?
	an, _ := dnsutilNext(a, 0)
	bn, _ := dnsutilNext(b, 0)
	if an < bn {
		return -1
	}
	if an > bn {
		return +1
	}

	abuf := comparePool.Get()
	bbuf := comparePool.Get()
	aoff, _ := pack.Name(a, abuf, 0, nil, false)
	boff, _ := pack.Name(b, bbuf, 0, nil, false)

	x := bytes.Compare(abuf[:aoff], bbuf[:boff])

	comparePool.Put(abuf)
	comparePool.Put(bbuf)
	return x
}

func comparebase64(a, b string) int {
	abuf := comparePool.Get()
	bbuf := comparePool.Get()
	aoff, _ := base64.StdEncoding.Decode(abuf, []byte(a))
	boff, _ := base64.StdEncoding.Decode(bbuf, []byte(b))

	x := bytes.Compare(abuf[:aoff], bbuf[:boff])

	comparePool.Put(abuf)
	comparePool.Put(bbuf)
	return x
}

func comparebase32(a, b string) int {
	abuf := comparePool.Get()
	bbuf := comparePool.Get()
	aoff, _ := base32.HexEncoding.WithPadding(base32.NoPadding).Decode(abuf, []byte(a))
	boff, _ := base32.HexEncoding.WithPadding(base32.NoPadding).Decode(bbuf, []byte(b))

	x := bytes.Compare(abuf[:aoff], bbuf[:boff])

	comparePool.Put(abuf)
	comparePool.Put(bbuf)
	return x
}

func comparehex(a, b string) int {
	abuf := comparePool.Get()
	bbuf := comparePool.Get()
	aoff, _ := hex.Decode(abuf, []byte(a))
	boff, _ := hex.Decode(bbuf, []byte(b))

	x := bytes.Compare(abuf[:aoff], bbuf[:boff])

	comparePool.Put(abuf)
	comparePool.Put(bbuf)
	return x
}

func comparepair(a, b []svcb.Pair) int {
	abuf := comparePool.Get()
	bbuf := comparePool.Get()
	aoff, _ := svcb.Pack(a, abuf, 0)
	boff, _ := svcb.Pack(b, bbuf, 0)

	x := bytes.Compare(abuf[:aoff], bbuf[:boff])

	comparePool.Put(abuf)
	comparePool.Put(bbuf)
	return x
}

func compareinfo(a, b []deleg.Info) int {
	abuf := comparePool.Get()
	bbuf := comparePool.Get()
	aoff, _ := deleg.Pack(a, abuf, 0)
	boff, _ := deleg.Pack(b, bbuf, 0)

	x := bytes.Compare(abuf[:aoff], bbuf[:boff])

	comparePool.Put(abuf)
	comparePool.Put(bbuf)
	return x
}

var comparePool = pool.New(DefaultMsgSize)
