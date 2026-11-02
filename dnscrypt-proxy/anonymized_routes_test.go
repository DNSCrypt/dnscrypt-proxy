package main

import (
	"net"
	"testing"

	stamps "github.com/jedisct1/go-dnsstamps"
)

func TestDNSCryptRouteAddressFamilies(t *testing.T) {
	relayIPs := map[string]string{
		"v4-near": "192.0.2.2",
		"v4-far":  "198.51.100.2",
		"v6-near": "2001:db8::2",
		"v6-far":  "2001:db8:8000::2",
	}
	mixed := []string{"v4-near", "v6-near", "v4-far", "v6-far"}
	for _, tt := range []struct {
		name      string
		serverIP  string
		routeName string
		via       []string
		wantRelay string
	}{
		{"IPv4 wildcard mixed", "192.0.2.1", "*", mixed, "v4-far"},
		{"IPv6 wildcard mixed", "2001:db8::1", "*", mixed, "v6-far"},
		{"IPv6 wildcard all relays", "2001:db8::1", "*", []string{"*"}, "v6-far"},
		{"IPv6 named all relays", "2001:db8::1", "server", []string{"*"}, "v6-far"},
		{"IPv6 named route", "2001:db8::1", "server", []string{"v6-near", "v6-far"}, ""},
		{"IPv6 wildcard single relay", "2001:db8::1", "*", []string{"v6-far"}, "v6-far"},
		{"IPv6 wildcard single IPv4 relay", "2001:db8::1", "*", []string{"v4-far"}, "v4-far"},
	} {
		for _, port := range []string{"443", "5443"} {
			t.Run(tt.name+"/"+port, func(t *testing.T) {
				parseStamp := func(stamp stamps.ServerStamp) stamps.ServerStamp {
					t.Helper()
					parsed, err := stamps.NewServerStampFromString(stamp.String())
					if err != nil {
						t.Fatal(err)
					}
					return parsed
				}
				routes := map[string][]string{tt.routeName: tt.via}
				proxy := &Proxy{serversInfo: NewServersInfo(), routes: &routes}
				proxy.serversInfo.registerServer("server", parseStamp(stamps.ServerStamp{
					Proto:         stamps.StampProtoTypeDNSCrypt,
					ServerAddrStr: net.JoinHostPort(tt.serverIP, port),
					ServerPk:      make([]byte, 32),
					ProviderName:  "2.dnscrypt-cert.test",
				}))
				for _, name := range mixed {
					proxy.serversInfo.registerRelay(name, parseStamp(stamps.ServerStamp{
						Proto:         stamps.StampProtoTypeDNSCryptRelay,
						ServerAddrStr: net.JoinHostPort(relayIPs[name], port),
					}))
				}

				relay, err := route(proxy, "server", stamps.StampProtoTypeDNSCrypt)
				if err != nil {
					t.Fatal(err)
				}
				if relay == nil || relay.Dnscrypt == nil {
					t.Fatal("no DNSCrypt relay selected")
				}
				if tt.wantRelay != "" && relay.Name != tt.wantRelay {
					t.Fatalf("selected %q, want %q", relay.Name, tt.wantRelay)
				}
				if tt.wantRelay == "" && relay.Name != "v6-near" && relay.Name != "v6-far" {
					t.Fatalf("selected relay %q outside the named route", relay.Name)
				}
				wantAddr := net.JoinHostPort(relayIPs[relay.Name], port)
				if relay.Dnscrypt.RelayUDPAddr.String() != wantAddr || relay.Dnscrypt.RelayTCPAddr.String() != wantAddr {
					t.Fatalf("relay addresses: UDP %v, TCP %v; want %s", relay.Dnscrypt.RelayUDPAddr, relay.Dnscrypt.RelayTCPAddr, wantAddr)
				}
			})
		}
	}
}
