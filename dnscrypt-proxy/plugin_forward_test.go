package main

import (
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// TestForwardKeepsResponseWhenFallbackFails checks that the answer of a server
// is returned when the next entry of the sequence cannot be reached.
func TestForwardKeepsResponseWhenFallbackFails(t *testing.T) {
	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	server, err := net.ListenUDP("udp", loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		for {
			buf := make([]byte, MaxDNSPacketSize)
			n, addr, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			query := dns.Msg{Data: buf[:n]}
			if err := query.Unpack(); err != nil {
				continue
			}
			response := EmptyResponseFromMessage(&query)
			response.Rcode = dns.RcodeNameError
			if err := response.Pack(); err != nil {
				continue
			}
			server.WriteToUDP(response.Data, addr)
		}
	}()
	unused, err := net.ListenUDP("udp", loopback)
	if err != nil {
		t.Fatal(err)
	}
	unreachable := unused.LocalAddr().String()
	unused.Close()

	plugin := &PluginForward{bootstrapResolvers: []string{unreachable}}
	_, plugin.forwardMap, err = plugin.parseForwardFile("test " + server.LocalAddr().String() + ",$BOOTSTRAP\n")
	if err != nil {
		t.Fatal(err)
	}
	pluginsState := PluginsState{qName: "host.test", timeout: time.Second}
	if err := plugin.Eval(&pluginsState, dns.NewMsg("host.test.", dns.TypeA)); err != nil {
		t.Fatalf("query dropped instead of returning the response of the first server: %v", err)
	}
	if pluginsState.synthResponse == nil || pluginsState.synthResponse.Rcode != dns.RcodeNameError {
		t.Errorf("unexpected response: %v", pluginsState.synthResponse)
	}
}
