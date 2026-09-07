package main

import (
	"net/netip"
	"sync"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func TestDNS64DiscoveryOutboundSource(t *testing.T) {
	sourceIP := usableNonLoopbackIPv4(t)
	policy, err := parseOutboundSourcePolicy(sourceIP.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	resolver, peerCh, closeServer := startOutboundDNSServer(t, "udp", sourceIP, false, func(msg *dns.Msg) {
		msg.Answer = []dns.RR{&dns.AAAA{
			Hdr:  dns.Header{Name: rfc7050WKN, Class: dns.ClassINET, TTL: 60},
			AAAA: rdata.AAAA{Addr: netip.MustParseAddr("64:ff9b::c000:aa")},
		}}
	})
	defer closeServer()

	plugin := PluginDNS64{pref64Mutex: new(sync.RWMutex), proxy: &Proxy{outboundSource: policy}}
	if err := plugin.fetchPref64(resolver.String()); err != nil {
		t.Fatal(err)
	}
	if peer := <-peerCh; !peer.Equal(sourceIP) {
		t.Fatalf("DNS64 peer source = %s, want %s", peer, sourceIP)
	}
	if len(plugin.pref64) != 1 || plugin.pref64[0].String() != "64:ff9b::/96" {
		t.Fatalf("prefixes = %v", plugin.pref64)
	}
}
