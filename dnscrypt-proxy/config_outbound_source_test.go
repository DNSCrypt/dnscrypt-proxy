package main

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestOutboundSourceConfigTOML(t *testing.T) {
	tests := []struct {
		name      string
		toml      string
		wantIPv4  string
		wantIPv6  string
		wantError string
	}{
		{name: "empty", toml: "outbound_source_ipv4 = ''\noutbound_source_ipv6 = ''"},
		{name: "IPv4", toml: "outbound_source_ipv4 = '192.0.2.10'", wantIPv4: "192.0.2.10"},
		{name: "mapped IPv4", toml: "outbound_source_ipv4 = '::ffff:192.0.2.10'", wantIPv4: "192.0.2.10"},
		{name: "IPv6", toml: "outbound_source_ipv6 = '2001:db8::10'", wantIPv6: "2001:db8::10"},
		{name: "scoped IPv6", toml: "outbound_source_ipv6 = 'fe80::1%eth0'", wantIPv6: "fe80::1%eth0"},
		{name: "dual stack", toml: "outbound_source_ipv4 = '192.0.2.10'\noutbound_source_ipv6 = '2001:db8::10'", wantIPv4: "192.0.2.10", wantIPv6: "2001:db8::10"},
		{name: "wrong IPv4 family", toml: "outbound_source_ipv4 = '2001:db8::10'", wantError: "expected an IPv4"},
		{name: "wrong IPv6 family", toml: "outbound_source_ipv6 = '192.0.2.10'", wantError: "expected an IPv6"},
		{name: "CIDR", toml: "outbound_source_ipv4 = '192.0.2.10/24'", wantError: "literal"},
		{name: "hostname", toml: "outbound_source_ipv4 = 'example.org'", wantError: "literal"},
		{name: "interface", toml: "outbound_source_ipv6 = 'eth0'", wantError: "literal"},
		{name: "port", toml: "outbound_source_ipv4 = '192.0.2.10:53'", wantError: "literal"},
		{name: "malformed", toml: "outbound_source_ipv6 = '2001:db8:::1'", wantError: "literal"},
		{name: "unspecified IPv4", toml: "outbound_source_ipv4 = '0.0.0.0'", wantError: "unspecified"},
		{name: "unspecified IPv6", toml: "outbound_source_ipv6 = '::'", wantError: "unspecified"},
		{name: "multicast IPv4", toml: "outbound_source_ipv4 = '224.0.0.1'", wantError: "multicast"},
		{name: "multicast IPv6", toml: "outbound_source_ipv6 = 'ff02::1%eth0'", wantError: "multicast"},
		{name: "broadcast", toml: "outbound_source_ipv4 = '255.255.255.255'", wantError: "limited broadcast"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := newConfig()
			if _, err := toml.Decode(test.toml, &config); err != nil {
				t.Fatal(err)
			}
			policy, err := parseOutboundSourcePolicy(config.OutboundSourceIPv4, config.OutboundSourceIPv6)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want containing %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			gotIPv4 := ""
			if policy.ipv4.IsValid() {
				gotIPv4 = policy.ipv4.String()
			}
			gotIPv6 := ""
			if policy.ipv6.IsValid() {
				gotIPv6 = policy.ipv6.String()
			}
			if gotIPv4 != test.wantIPv4 || gotIPv6 != test.wantIPv6 {
				t.Fatalf("got IPv4=%q IPv6=%q", gotIPv4, gotIPv6)
			}
		})
	}
}
