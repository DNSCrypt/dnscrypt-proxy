package main

import "testing"

func TestResolveNetprobeAddresses(t *testing.T) {
	addrs, err := resolveNetprobeAddresses("9.9.9.9:53")
	if err != nil || len(addrs) != 1 || addrs[0].String() != "9.9.9.9:53" {
		t.Fatalf("single address: %v %v", addrs, err)
	}
	addrs, err = resolveNetprobeAddresses("9.9.9.9:53, [2620:fe::fe]:53")
	if err != nil || len(addrs) != 2 || addrs[1].String() != "[2620:fe::fe]:53" {
		t.Fatalf("multiple addresses: %v %v", addrs, err)
	}
	for _, bad := range []string{"9.9.9.9", "9.9.9.9:53,bogus", " , "} {
		if _, err := resolveNetprobeAddresses(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}
