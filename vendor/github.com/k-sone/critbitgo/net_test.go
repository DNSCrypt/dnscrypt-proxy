package critbitgo_test

import (
	"net"
	"testing"

	"github.com/k-sone/critbitgo"
)

func TestNet(t *testing.T) {
	trie := critbitgo.NewNet()
	cidr := "192.168.1.0/24"
	host := "192.168.1.1/32"
	hostIP := net.IPv4(192, 168, 1, 1)

	if _, _, err := trie.GetCIDR(""); err == nil {
		t.Error("GetCIDR() - not error")
	}
	if v, ok, err := trie.GetCIDR(cidr); v != nil || ok || err != nil {
		t.Errorf("GetCIDR() - phantom: %v, %v, %v", v, ok, err)
	}
	if _, _, err := trie.MatchCIDR(""); err == nil {
		t.Error("MatchCIDR() - not error")
	}
	if r, v, err := trie.MatchCIDR(host); r != nil || v != nil || err != nil {
		t.Errorf("MatchCIDR() - phantom: %v, %v, %v", r, v, err)
	}
	if _, _, err := trie.MatchIP(net.IP([]byte{})); err == nil {
		t.Error("MatchIP() - not error")
	}
	if r, v, err := trie.MatchIP(hostIP); r != nil || v != nil || err != nil {
		t.Errorf("MatchIP() - phantom: %v, %v, %v", r, v, err)
	}
	if _, err := trie.ContainedIP(net.IP([]byte{})); err == nil {
		t.Error("ContainedIP() - not error")
	}
	if b, err := trie.ContainedIP(hostIP); b || err != nil {
		t.Errorf("ContainedIP() - phantom: %v, %v", b, err)
	}
	if _, _, err := trie.DeleteCIDR(""); err == nil {
		t.Error("DeleteCIDR() - not error")
	}
	if v, ok, err := trie.DeleteCIDR(cidr); v != nil || ok || err != nil {
		t.Errorf("DeleteCIDR() - phantom: %v, %v, %v", v, ok, err)
	}

	if err := trie.AddCIDR(cidr, &cidr); err != nil {
		t.Errorf("AddCIDR() - %s: error occurred %s", cidr, err)
	}
	if v, ok, err := trie.GetCIDR(cidr); v != &cidr || !ok || err != nil {
		t.Errorf("GetCIDR() - failed: %v, %v, %v", v, ok, err)
	}
	if r, v, err := trie.MatchCIDR(host); r == nil || r.String() != cidr || v != &cidr || err != nil {
		t.Errorf("MatchCIDR() - failed: %v, %v, %v", r, v, err)
	}
	if r, v, err := trie.MatchIP(hostIP); r == nil || r.String() != cidr || v != &cidr || err != nil {
		t.Errorf("MatchIP() - failed: %v, %v, %v", r, v, err)
	}
	if b, err := trie.ContainedIP(hostIP); !b || err != nil {
		t.Errorf("ContainedIP() - failed: %v, %v", b, err)
	}
	if v, ok, err := trie.DeleteCIDR(cidr); v != &cidr || !ok || err != nil {
		t.Errorf("DeleteCIDR() - failed: %v, %v, %v", v, ok, err)
	}
}

func checkMatch(t *testing.T, trie *critbitgo.Net, request, expect string) {
	route, value, err := trie.MatchCIDR(request)
	if err != nil {
		t.Errorf("MatchCIDR() - %s: error occurred %s", request, err)
	}
	if cidr := route.String(); expect != cidr {
		t.Errorf("MatchCIDR() - %s: expected [%s], actual [%s]", request, expect, cidr)
	}
	if value == nil {
		t.Errorf("MatchCIDR() - %s: no value", request)
	}
}

func TestNetMatch(t *testing.T) {
	trie := critbitgo.NewNet()

	cidrs := []string{
		"0.0.0.0/4",
		"192.168.0.0/16",
		"192.168.1.0/24",
		"192.168.1.0/28",
		"192.168.1.0/32",
		"192.168.1.1/32",
		"192.168.1.2/32",
		"192.168.1.32/27",
		"192.168.1.32/30",
		"192.168.2.1/32",
		"192.168.2.2/32",
	}

	for _, cidr := range cidrs {
		if err := trie.AddCIDR(cidr, &cidr); err != nil {
			t.Errorf("AddCIDR() - %s: error occurred %s", cidr, err)
		}
	}

	checkMatch(t, trie, "10.0.0.0/8", "0.0.0.0/4")
	checkMatch(t, trie, "192.168.1.0/24", "192.168.1.0/24")
	checkMatch(t, trie, "192.168.1.0/30", "192.168.1.0/28")
	checkMatch(t, trie, "192.168.1.0/32", "192.168.1.0/32")
	checkMatch(t, trie, "192.168.1.128/26", "192.168.1.0/24")
	checkMatch(t, trie, "192.168.2.128/26", "192.168.0.0/16")
	checkMatch(t, trie, "192.168.1.1/32", "192.168.1.1/32")
	checkMatch(t, trie, "192.168.1.2/32", "192.168.1.2/32")
	checkMatch(t, trie, "192.168.1.3/32", "192.168.1.0/28")
	checkMatch(t, trie, "192.168.1.32/32", "192.168.1.32/30")
	checkMatch(t, trie, "192.168.1.35/32", "192.168.1.32/30")
	checkMatch(t, trie, "192.168.1.36/32", "192.168.1.32/27")
	checkMatch(t, trie, "192.168.1.63/32", "192.168.1.32/27")
	checkMatch(t, trie, "192.168.1.64/32", "192.168.1.0/24")
	checkMatch(t, trie, "192.168.2.2/32", "192.168.2.2/32")
	checkMatch(t, trie, "192.168.2.3/32", "192.168.0.0/16")
}
