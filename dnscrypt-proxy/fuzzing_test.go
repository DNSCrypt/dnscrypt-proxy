//go:build gofuzzbeta
// +build gofuzzbeta

package main

import (
	"encoding/hex"
	"testing"

	stamps "github.com/jedisct1/go-dnsstamps"
)

func FuzzParseODoHTargetConfigs(f *testing.F) {
	configs_hex := "0020000100010020aacc53b3df0c6eb2d7d5ce4ddf399593376c9903ba6a52a52c3a2340f97bb764"
	configs, _ := hex.DecodeString(configs_hex)
	f.Add(configs)
	f.Fuzz(func(t *testing.T, configs []byte) {
		if _, err := parseODoHTargetConfigs(configs); err != nil {
			t.Skip()
		}
	})
}

func FuzzParseStampParser(f *testing.F) {
	f.Add("sdns://AgcAAAAAAAAACzEwNC4yMS42Ljc4AA1kb2guY3J5cHRvLnN4Ci9kbnMtcXVlcnk")
	f.Add("sdns://AgcAAAAAAAAAGlsyNjA2OjQ3MDA6MzAzNzo6NjgxNTo2NGVdABJkb2gtaXB2Ni5jcnlwdG8uc3gKL2Rucy1xdWVyeQ")
	f.Add(
		"sdns://AQcAAAAAAAAADTUxLjE1LjEyMi4yNTAg6Q3ZfapcbHgiHKLF7QFoli0Ty1Vsz3RXs1RUbxUrwZAcMi5kbnNjcnlwdC1jZXJ0LnNjYWxld2F5LWFtcw",
	)
	f.Add(
		"sdns://AQcAAAAAAAAAFlsyMDAxOmJjODoxODIwOjUwZDo6MV0g6Q3ZfapcbHgiHKLF7QFoli0Ty1Vsz3RXs1RUbxUrwZAcMi5kbnNjcnlwdC1jZXJ0LnNjYWxld2F5LWFtcw",
	)
	f.Add("sdns://gQ8xNjMuMTcyLjE4MC4xMjU")
	f.Add("sdns://BQcAAAAAAAAADm9kb2guY3J5cHRvLnN4Ci9kbnMtcXVlcnk")
	f.Add("sdns://hQcAAAAAAAAAACCi3jNJDEdtNW4tvHN8J3lpIklSa2Wrj7qaNCgEgci9_BpvZG9oLXJlbGF5LmVkZ2Vjb21wdXRlLmFwcAEv")
	f.Fuzz(func(t *testing.T, stamp string) {
		if _, err := stamps.NewServerStampFromString(stamp); err != nil {
			t.Skip()
		}
	})
}
