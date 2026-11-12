package main

import (
	"strings"
	"testing"
)

// TestCloakPTRMultipleAddresses checks that cloak_ptr creates a PTR record
// for every address of a name, not only for the first one.
func TestCloakPTRMultipleAddresses(t *testing.T) {
	plugin := &PluginCloak{createPTR: true}
	matcher := NewPatternMatcher()
	rules := "host.test 192.0.2.1\nhost.test 192.0.2.2\nhost.test 2001:db8::1\nhost.test 2001:db8::2\n"
	if err := plugin.loadRules(rules, matcher); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2"} {
		arpa, err := reverseAddr(ip)
		if err != nil {
			t.Fatal(err)
		}
		_, _, val := matcher.Eval(strings.TrimSuffix(arpa, "."))
		cloakedName, _ := val.(*CloakedName)
		if cloakedName == nil {
			t.Errorf("no PTR record for %s", ip)
		} else if len(cloakedName.PTR) != 1 || cloakedName.PTR[0] != "host.test." {
			t.Errorf("PTR records for %s: %v, want [host.test.]", ip, cloakedName.PTR)
		}
	}
}
