package main

import (
	"fmt"
	"net"
	"testing"
)

func TestDNS64StaticPrefixes(t *testing.T) {
	for _, bits := range []int{32, 40, 48, 56, 64, 96} {
		prefix := fmt.Sprintf("2001:db8::/%d", bits)
		t.Run(prefix, func(t *testing.T) {
			plugin := new(PluginDNS64)
			proxy := &Proxy{listenAddresses: []string{"127.0.0.1:53"}, dns64Prefixes: []string{prefix}}
			if err := plugin.Init(proxy); err != nil {
				t.Fatal(err)
			}
			if len(plugin.pref64) != 1 || plugin.pref64[0].String() != prefix {
				t.Fatalf("unexpected prefixes: %v", plugin.pref64)
			}
		})
	}
	for _, prefix := range []string{"192.0.2.0/24", "::ffff:192.0.2.0/120", "2001:db8::/0", "2001:db8::/31", "2001:db8::/33", "2001:db8::/65", "2001:db8::/95", "2001:db8::/97", "2001:db8::/128"} {
		t.Run(prefix, func(t *testing.T) {
			plugin := new(PluginDNS64)
			proxy := &Proxy{listenAddresses: []string{"127.0.0.1:53"}, dns64Prefixes: []string{prefix}}
			if err := plugin.Init(proxy); err == nil {
				t.Fatal("invalid DNS64 prefix accepted")
			}
		})
	}
}

func TestDNS64Translation(t *testing.T) {
	for _, tt := range []struct{ prefix, want string }{
		{"2001:db8::/32", "2001:db8:c000:221::"},
		{"2001:db8:100::/40", "2001:db8:1c0:2:21::"},
		{"2001:db8:122::/48", "2001:db8:122:c000:2:2100::"},
		{"2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"},
		{"2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100:0"},
		{"2001:db8:122:344::/96", "2001:db8:122:344::c000:221"},
	} {
		t.Run(tt.prefix, func(t *testing.T) {
			_, prefix, err := net.ParseCIDR(tt.prefix)
			if err != nil {
				t.Fatal(err)
			}
			if got := translateToIPv6(net.IP{192, 0, 2, 33}, prefix); !got.Equal(net.ParseIP(tt.want)) {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}
