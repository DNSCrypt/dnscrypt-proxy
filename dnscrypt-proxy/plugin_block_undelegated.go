package main

import (
	"github.com/k-sone/critbitgo"
	"github.com/miekg/dns"
)

var undelegatedSet = []string{
	"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
	"0.in-addr.arpa",
	"1",
	"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
	"10.in-addr.arpa",
	"100.100.in-addr.arpa",
	"100.51.198.in-addr.arpa",
	"101.100.in-addr.arpa",
	"102.100.in-addr.arpa",
	"103.100.in-addr.arpa",
	"104.100.in-addr.arpa",
	"105.100.in-addr.arpa",
	"106.100.in-addr.arpa",
	"107.100.in-addr.arpa",
	"108.100.in-addr.arpa",
	"109.100.in-addr.arpa",
	"110.100.in-addr.arpa",
	"111.100.in-addr.arpa",
	"112.100.in-addr.arpa",
	"113.0.203.in-addr.arpa",
	"113.100.in-addr.arpa",
	"114.100.in-addr.arpa",
	"115.100.in-addr.arpa",
	"116.100.in-addr.arpa",
	"117.100.in-addr.arpa",
	"118.100.in-addr.arpa",
	"119.100.in-addr.arpa",
	"120.100.in-addr.arpa",
	"121.100.in-addr.arpa",
	"122.100.in-addr.arpa",
	"123.100.in-addr.arpa",
	"124.100.in-addr.arpa",
	"125.100.in-addr.arpa",
	"126.100.in-addr.arpa",
	"127.100.in-addr.arpa",
	"127.in-addr.arpa",
	"16.172.in-addr.arpa",
	"168.192.in-addr.arpa",
	"17.172.in-addr.arpa",
	"18.172.in-addr.arpa",
	"19.172.in-addr.arpa",
	"2.0.192.in-addr.arpa",
	"20.172.in-addr.arpa",
	"21.172.in-addr.arpa",
	"22.172.in-addr.arpa",
	"23.172.in-addr.arpa",
	"24.172.in-addr.arpa",
	"25.172.in-addr.arpa",
	"254.169.in-addr.arpa",
	"255.255.255.255.in-addr.arpa",
	"26.172.in-addr.arpa",
	"27.172.in-addr.arpa",
	"28.172.in-addr.arpa",
	"29.172.in-addr.arpa",
	"30.172.in-addr.arpa",
	"31.172.in-addr.arpa",
	"64.100.in-addr.arpa",
	"65.100.in-addr.arpa",
	"66.100.in-addr.arpa",
	"67.100.in-addr.arpa",
	"68.100.in-addr.arpa",
	"69.100.in-addr.arpa",
	"70.100.in-addr.arpa",
	"71.100.in-addr.arpa",
	"72.100.in-addr.arpa",
	"73.100.in-addr.arpa",
	"74.100.in-addr.arpa",
	"75.100.in-addr.arpa",
	"76.100.in-addr.arpa",
	"77.100.in-addr.arpa",
	"78.100.in-addr.arpa",
	"79.100.in-addr.arpa",
	"8.b.d.0.1.0.0.2.ip6.arpa",
	"8.e.f.ip6.arpa",
	"80.100.in-addr.arpa",
	"81.100.in-addr.arpa",
	"82.100.in-addr.arpa",
	"83.100.in-addr.arpa",
	"84.100.in-addr.arpa",
	"85.100.in-addr.arpa",
	"86.100.in-addr.arpa",
	"87.100.in-addr.arpa",
	"88.100.in-addr.arpa",
	"89.100.in-addr.arpa",
	"9.e.f.ip6.arpa",
	"90.100.in-addr.arpa",
	"91.100.in-addr.arpa",
	"92.100.in-addr.arpa",
	"93.100.in-addr.arpa",
	"94.100.in-addr.arpa",
	"95.100.in-addr.arpa",
	"96.100.in-addr.arpa",
	"97.100.in-addr.arpa",
	"98.100.in-addr.arpa",
	"99.100.in-addr.arpa",
	"a.e.f.ip6.arpa",
	"airdream",
	"api",
	"b.e.f.ip6.arpa",
	"bbrouter",
	"belkin",
	"bind",
	"blinkap",
	"corp",
	"d.f.ip6.arpa",
	"davolink",
	"dearmyrouter",
	"dhcp",
	"dlink",
	"domain",
	"envoy",
	"example",
	"f.f.ip6.arpa",
	"grp",
	"gw==",
	"home",
	"hub",
	"internal",
	"intra",
	"intranet",
	"invalid",
	"ksyun",
	"lan",
	"loc",
	"local",
	"localdomain",
	"localhost",
	"localnet",
	"modem",
	"mynet",
	"myrouter",
	"novalocal",
	"onion",
	"openstacklocal",
	"priv",
	"private",
	"prv",
	"router",
	"telus",
	"test",
	"totolink",
	"wlan_ap",
	"workgroup",
	"zghjccbob3n0",
}

type PluginBlockUndelegated struct {
	suffixes *critbitgo.Trie
}

func (plugin *PluginBlockUndelegated) Name() string {
	return "block_undelegated"
}

func (plugin *PluginBlockUndelegated) Description() string {
	return "Block undelegated DNS names"
}

func (plugin *PluginBlockUndelegated) Init(proxy *Proxy) error {
	suffixes := critbitgo.NewTrie()
	for _, line := range undelegatedSet {
		pattern := StringReverse(line)
		suffixes.Insert([]byte(pattern), true)
	}
	plugin.suffixes = suffixes
	return nil
}

func (plugin *PluginBlockUndelegated) Drop() error {
	return nil
}

func (plugin *PluginBlockUndelegated) Reload() error {
	return nil
}

func (plugin *PluginBlockUndelegated) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	revQname := StringReverse(pluginsState.qName)
	match, _, found := plugin.suffixes.LongestPrefix([]byte(revQname))
	if !found {
		return nil
	}
	if len(match) == len(revQname) || revQname[len(match)] == '.' {
		synth := EmptyResponseFromMessage(msg)
		synth.Rcode = dns.RcodeNameError
		pluginsState.synthResponse = synth
		pluginsState.action = PluginsActionSynth
		pluginsState.returnCode = PluginsReturnCodeSynth
	}
	return nil
}
