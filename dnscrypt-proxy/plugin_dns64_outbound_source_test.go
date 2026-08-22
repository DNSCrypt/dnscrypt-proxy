package main

import (
	"net"
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
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peerCh := make(chan net.IP, 1)
	go func() {
		packet := make([]byte, MaxDNSPacketSize)
		length, peer, err := listener.ReadFromUDP(packet)
		if err != nil {
			return
		}
		peerCh <- peer.IP
		msg := dns.Msg{Data: packet[:length]}
		if msg.Unpack() != nil {
			return
		}
		msg.Response = true
		msg.Answer = []dns.RR{&dns.AAAA{
			Hdr:  dns.Header{Name: rfc7050WKN, Class: dns.ClassINET, TTL: 60},
			AAAA: rdata.AAAA{Addr: netip.MustParseAddr("64:ff9b::c000:aa")},
		}}
		if msg.Pack() == nil {
			_, _ = listener.WriteToUDP(msg.Data, peer)
		}
	}()

	plugin := PluginDNS64{pref64Mutex: new(sync.RWMutex), outboundSource: &policy}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	resolver := net.JoinHostPort(sourceIP.String(), formatPort(port))
	if err := plugin.fetchPref64(resolver); err != nil {
		t.Fatal(err)
	}
	if peer := <-peerCh; !peer.Equal(sourceIP) {
		t.Fatalf("DNS64 peer source = %s, want %s", peer, sourceIP)
	}
	if len(plugin.pref64) != 1 || plugin.pref64[0].String() != "64:ff9b::/96" {
		t.Fatalf("prefixes = %v", plugin.pref64)
	}
}
