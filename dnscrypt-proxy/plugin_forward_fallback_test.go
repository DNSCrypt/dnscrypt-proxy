package main

import (
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func TestForwardKeepsLastValidResponse(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		query := &dns.Msg{Data: buf[:n]}
		if err = query.Unpack(); err != nil {
			done <- err
			return
		}
		response := EmptyResponseFromMessage(query)
		response.Rcode = dns.RcodeNameError
		if err = response.Pack(); err == nil {
			_, err = conn.WriteTo(response.Data, addr)
		}
		done <- err
	}()
	plugin := &PluginForward{forwardMap: []PluginForwardEntry{{
		domain: "private.example",
		sequence: []SearchSequenceItem{
			{typ: Explicit, servers: []string{conn.LocalAddr().String()}},
			{typ: Explicit, servers: []string{"127.0.0.1:invalid"}},
		},
	}}}
	state := &PluginsState{qName: "private.example", timeout: time.Second, action: PluginsActionContinue}
	err = plugin.Eval(state, dns.NewMsg("private.example.", dns.TypeA))
	if serverErr := <-done; serverErr != nil {
		t.Fatal(serverErr)
	}
	if err != nil {
		t.Fatalf("valid response discarded after fallback error: %v", err)
	}
	if state.synthResponse == nil || state.synthResponse.Rcode != dns.RcodeNameError || state.action != PluginsActionSynth || state.serverName != conn.LocalAddr().String() {
		t.Fatal("last valid negative response was not retained")
	}
}

func TestForwardReturnsErrorWithoutValidResponse(t *testing.T) {
	plugin := &PluginForward{forwardMap: []PluginForwardEntry{{
		domain:   "private.example",
		sequence: []SearchSequenceItem{{typ: Explicit, servers: []string{"127.0.0.1:invalid"}}},
	}}}
	state := &PluginsState{qName: "private.example", timeout: time.Second, action: PluginsActionContinue}
	if err := plugin.Eval(state, dns.NewMsg("private.example.", dns.TypeA)); err == nil {
		t.Fatal("forwarding error was lost")
	}
	if state.synthResponse != nil || state.action != PluginsActionContinue {
		t.Fatal("failed exchange produced a response")
	}
}
