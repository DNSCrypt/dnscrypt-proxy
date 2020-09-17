package main

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

const rfc7050WKN = "ipv4only.arpa."

var (
	rfc7050WKA1 = net.IPv4(192, 0, 0, 170)
	rfc7050WKA2 = net.IPv4(192, 0, 0, 171)
)

type PluginDNS64 struct {
	pref64Mutex    *sync.RWMutex
	pref64         []*net.IPNet
	dns64Resolvers []string
	ipv4Resolver   string
	proxy          *Proxy
}

func (plugin *PluginDNS64) Name() string {
	return "dns64"
}

func (plugin *PluginDNS64) Description() string {
	return "Synthesize DNS64 AAAA responses"
}

func (plugin *PluginDNS64) Init(proxy *Proxy) error {
	plugin.ipv4Resolver = proxy.listenAddresses[0] //recursively to ourselves
	plugin.pref64Mutex = new(sync.RWMutex)
	plugin.proxy = proxy

	if len(proxy.dns64Prefixes) != 0 {
		plugin.pref64Mutex.RLock()
		defer plugin.pref64Mutex.RUnlock()
		for _, prefStr := range proxy.dns64Prefixes {
			_, pref, err := net.ParseCIDR(prefStr)
			if err != nil {
				return err
			}
			dlog.Infof("Registered DNS64 prefix [%s]", pref.String())
			plugin.pref64 = append(plugin.pref64, pref)
		}
	} else if len(proxy.dns64Resolvers) != 0 {
		plugin.dns64Resolvers = proxy.dns64Resolvers
		if err := plugin.refreshPref64(); err != nil {
			return err
		}
	}

	return nil
}

func (plugin *PluginDNS64) Drop() error {
	return nil
}

func (plugin *PluginDNS64) Reload() error {
	return nil
}

func (plugin *PluginDNS64) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if hasAAAAAnswer(msg) {
		return nil
	}

	question := pluginsState.questionMsg.Question[0]
	if question.Qclass != dns.ClassINET || question.Qtype != dns.TypeAAAA {
		return nil
	}

	msgA := pluginsState.questionMsg.Copy()
	msgA.SetQuestion(question.Name, dns.TypeA)
	msgAPacket, err := msgA.Pack()
	if err != nil {
		return err
	}

	if !plugin.proxy.clientsCountInc() {
		return errors.New("Too many concurrent connections to handle DNS64 subqueries")
	}
	respPacket := plugin.proxy.processIncomingQuery("trampoline", plugin.proxy.mainProto, msgAPacket, nil, nil, time.Now())
	plugin.proxy.clientsCountDec()
	resp := dns.Msg{}
	if err := resp.Unpack(respPacket); err != nil {
		return err
	}

	if err != nil || resp.Rcode != dns.RcodeSuccess {
		return nil
	}

	if len(resp.Answer) == 0 {
		return nil
	}

	initialTTL := uint32(600)
	for _, ns := range resp.Ns {
		header := ns.Header()
		if header.Rrtype == dns.TypeSOA {
			initialTTL = header.Ttl
		}
	}

	synthAAAAs := make([]dns.RR, 0)
	for _, answer := range resp.Answer {
		header := answer.Header()
		if header.Rrtype == dns.TypeA {
			ttl := initialTTL
			if ttl > header.Ttl {
				ttl = header.Ttl
			}

			ipv4 := answer.(*dns.A).A.To4()
			if ipv4 != nil {
				plugin.pref64Mutex.Lock()
				for _, prefix := range plugin.pref64 {
					ipv6 := translateToIPv6(ipv4, prefix)
					synthAAAA := new(dns.AAAA)
					synthAAAA.Hdr = dns.RR_Header{Name: header.Name, Rrtype: dns.TypeAAAA, Class: header.Class, Ttl: ttl}
					synthAAAA.AAAA = ipv6
					synthAAAAs = append(synthAAAAs, synthAAAA)
				}
				plugin.pref64Mutex.Unlock()
			}
		}
	}

	synth := EmptyResponseFromMessage(msg)
	synth.Answer = append(synth.Answer, synthAAAAs...)

	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeCloak

	return nil
}

func hasAAAAAnswer(msg *dns.Msg) bool {
	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == dns.TypeAAAA {
			return true
		}
	}
	return false
}

func translateToIPv6(ipv4 net.IP, prefix *net.IPNet) net.IP {
	ipv6 := make(net.IP, net.IPv6len)
	copy(ipv6, prefix.IP)
	n, _ := prefix.Mask.Size()
	ipShift := n / 8
	for i := 0; i < net.IPv4len; i++ {
		if ipShift+i == 8 {
			ipShift++
		}
		ipv6[ipShift+i] = ipv4[i]
	}
	return ipv6
}

func (plugin *PluginDNS64) fetchPref64(resolver string) error {
	msg := new(dns.Msg)
	msg.SetQuestion(rfc7050WKN, dns.TypeAAAA)

	client := new(dns.Client)
	resp, _, err := client.Exchange(msg, resolver)

	if err != nil {
		return err
	}

	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return errors.New("Unable to fetch Pref64")
	}

	uniqPrefixes := make(map[string]struct{})
	prefixes := make([]*net.IPNet, 0)
	for _, answer := range resp.Answer {
		if answer.Header().Rrtype == dns.TypeAAAA {
			ipv6 := answer.(*dns.AAAA).AAAA
			if ipv6 != nil && len(ipv6) == net.IPv6len {
				prefEnd := 0

				if wka := net.IPv4(ipv6[12], ipv6[13], ipv6[14], ipv6[15]); wka.Equal(rfc7050WKA1) || wka.Equal(rfc7050WKA2) { //96
					prefEnd = 12
				} else if wka := net.IPv4(ipv6[9], ipv6[10], ipv6[11], ipv6[12]); wka.Equal(rfc7050WKA1) || wka.Equal(rfc7050WKA2) { //64
					prefEnd = 8
				} else if wka := net.IPv4(ipv6[7], ipv6[9], ipv6[10], ipv6[11]); wka.Equal(rfc7050WKA1) || wka.Equal(rfc7050WKA2) { //56
					prefEnd = 7
				} else if wka := net.IPv4(ipv6[6], ipv6[7], ipv6[9], ipv6[10]); wka.Equal(rfc7050WKA1) || wka.Equal(rfc7050WKA2) { //48
					prefEnd = 6
				} else if wka := net.IPv4(ipv6[5], ipv6[6], ipv6[7], ipv6[9]); wka.Equal(rfc7050WKA1) || wka.Equal(rfc7050WKA2) { //40
					prefEnd = 5
				} else if wka := net.IPv4(ipv6[4], ipv6[5], ipv6[6], ipv6[7]); wka.Equal(rfc7050WKA1) || wka.Equal(rfc7050WKA2) { //32
					prefEnd = 4
				}

				if prefEnd > 0 {
					prefix := new(net.IPNet)
					prefix.IP = append(ipv6[:prefEnd], net.IPv6zero[prefEnd:]...)
					prefix.Mask = net.CIDRMask(prefEnd*8, 128)
					if _, ok := uniqPrefixes[prefix.String()]; !ok {
						prefixes = append(prefixes, prefix)
						uniqPrefixes[prefix.String()] = struct{}{}
						dlog.Infof("Registered DNS64 prefix [%s]", prefix.String())
					}
				}
			}
		}
	}

	if len(prefixes) == 0 {
		return errors.New("Empty Pref64 list")
	}

	plugin.pref64Mutex.RLock()
	defer plugin.pref64Mutex.RUnlock()
	plugin.pref64 = prefixes
	return nil
}

func (plugin *PluginDNS64) refreshPref64() error {
	for _, resolver := range plugin.dns64Resolvers {
		if err := plugin.fetchPref64(resolver); err == nil {
			break
		}
	}

	plugin.pref64Mutex.Lock()
	defer plugin.pref64Mutex.Unlock()
	if len(plugin.pref64) == 0 {
		return errors.New("Empty Pref64 list")
	}

	return nil
}
