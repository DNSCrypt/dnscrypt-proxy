// +build gofuzzbeta

package main

import (
	"encoding/hex"
	"testing"
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
