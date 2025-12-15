package main

import (
	"math/rand"
	"net"
	"net/netip"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
)

type PluginECS struct {
	nets []*net.IPNet
}

func (plugin *PluginECS) Name() string {
	return "ecs"
}

func (plugin *PluginECS) Description() string {
	return "Set EDNS-client-subnet information in outgoing queries."
}

func (plugin *PluginECS) Init(proxy *Proxy) error {
	plugin.nets = proxy.ednsClientSubnets
	dlog.Notice("ECS plugin enabled")
	return nil
}

func (plugin *PluginECS) Drop() error {
	return nil
}

func (plugin *PluginECS) Reload() error {
	return nil
}

func (plugin *PluginECS) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	// Check if SUBNET already exists in Pseudo section
	for _, rr := range msg.Pseudo {
		if _, ok := rr.(*dns.SUBNET); ok {
			return nil
		}
	}

	// Enable EDNS0 if not already enabled
	if msg.UDPSize == 0 {
		msg.UDPSize = uint16(pluginsState.maxPayloadSize)
	}

	// Create SUBNET option
	ipnet := plugin.nets[rand.Intn(len(plugin.nets))]
	bits, totalSize := ipnet.Mask.Size()

	var family uint16
	var addr netip.Addr
	if totalSize == 32 {
		family = 1
		if ip4 := ipnet.IP.To4(); ip4 != nil {
			addr = netip.AddrFrom4([4]byte(ip4))
		} else {
			return nil
		}
	} else if totalSize == 128 {
		family = 2
		if ip6 := ipnet.IP.To16(); ip6 != nil {
			addr = netip.AddrFrom16([16]byte(ip6))
		} else {
			return nil
		}
	} else {
		return nil
	}

	subnet := &dns.SUBNET{
		Family:        family,
		SourceNetmask: uint8(bits),
		SourceScope:   0,
		Address:       addr,
	}
	msg.Pseudo = append(msg.Pseudo, subnet)

	return nil
}
