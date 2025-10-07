package main

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDeviceAndSubscriber_AddsBothWhenMissing(t *testing.T) {
	plugin := &PluginDeviceAndSubscriberID{deviceID: "0123456789abcdef0123456789abcdef", subscriberID: "38a8fc7ecfae49c1ad267af1a0aff525"}
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	st := NewPluginsState(&Proxy{}, "udp", nil, "udp", time.Now())

	err := plugin.Eval(&st, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	opts := getEDNS0Options(msg)
	if opts == nil {
		t.Fatal("expected OPT record to be added")
	}

	if got := countOptions(opts, 65001); got != 1 {
		t.Fatalf("expected one device option, got %d", got)
	}
	if got := countOptions(opts, 65075); got != 1 {
		t.Fatalf("expected one subscriber option, got %d", got)
	}

	// Validate payloads
	foundDev := false
	foundSub := false
	for _, o := range *opts {
		switch o.Option() {
		case 65001:
			if loc, ok := o.(*dns.EDNS0_LOCAL); ok {
				if plugin.deviceID != string(loc.Data) {
					t.Fatalf("deviceID payload mismatch: want %s got %s", plugin.deviceID, string(loc.Data))
				}
				foundDev = true
			}
		case 65075:
			if loc, ok := o.(*dns.EDNS0_LOCAL); ok {
				if plugin.subscriberID != string(loc.Data) {
					t.Fatalf("subscriberID payload mismatch: want %s got %s", plugin.subscriberID, string(loc.Data))
				}
				foundSub = true
			}
		}
	}
	if !foundDev {
		t.Fatal("device option not found")
	}
	if !foundSub {
		t.Fatal("subscriber option not found")
	}
}

func TestDeviceAndSubscriber_NoDuplicateWhenAlreadyPresent(t *testing.T) {
	plugin := &PluginDeviceAndSubscriberID{deviceID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", subscriberID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	msg.SetEdns0(1232, false)
 opts := getEDNS0Options(msg)
	if opts == nil {
		t.Fatal("expected OPT record to be present")
	}

	// Pre-add existing options
	*opts = append(*opts, &dns.EDNS0_LOCAL{Code: 65001, Data: []byte(plugin.deviceID)})
	*opts = append(*opts, &dns.EDNS0_LOCAL{Code: 65075, Data: []byte(plugin.subscriberID)})

	st := NewPluginsState(&Proxy{}, "udp", nil, "udp", time.Now())

	err := plugin.Eval(&st, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	opts = getEDNS0Options(msg)
	if got := countOptions(opts, 65001); got != 1 {
		t.Fatalf("no duplicate device option expected, got %d", got)
	}
	if got := countOptions(opts, 65075); got != 1 {
		t.Fatalf("no duplicate subscriber option expected, got %d", got)
	}
}

func TestDeviceAndSubscriber_DoesNothingIfOneEmpty(t *testing.T) {
	// Only device ID provided - expect no changes
	plugin := &PluginDeviceAndSubscriberID{deviceID: "cccccccccccccccccccccccccccccccc", subscriberID: ""}
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	st := NewPluginsState(&Proxy{}, "udp", nil, "udp", time.Now())

 err := plugin.Eval(&st, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	opts := getEDNS0Options(msg)
	if opts != nil {
		t.Fatal("expected no OPT to be added when one of IDs is empty")
	}

	// Only subscriber ID provided - expect no changes
	plugin = &PluginDeviceAndSubscriberID{deviceID: "", subscriberID: "dddddddddddddddddddddddddddddddd"}
	msg = new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	err = plugin.Eval(&st, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if getEDNS0Options(msg) != nil {
		t.Fatal("expected no OPT to be added when one of IDs is empty")
	}
}

// getEDNS0Options returns a pointer to the EDNS0 options slice from the given message, or nil if none is present.
func getEDNS0Options(msg *dns.Msg) *[]dns.EDNS0 {
	for _, extra := range msg.Extra {
		if extra.Header().Rrtype == dns.TypeOPT {
			opt := extra.(*dns.OPT)
			return &opt.Option
		}
	}
	return nil
}

// countOptions counts EDNS0 options with the given option code.
func countOptions(opts *[]dns.EDNS0, code uint16) int {
	if opts == nil {
		return 0
	}
	c := 0
	for _, o := range *opts {
		if o.Option() == code {
			c++
		}
	}
	return c
}
