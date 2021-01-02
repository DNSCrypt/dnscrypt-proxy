package main

import (
	"math/rand"
	"net"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
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
	var options *[]dns.EDNS0

	for _, extra := range msg.Extra {
		if extra.Header().Rrtype == dns.TypeOPT {
			options = &extra.(*dns.OPT).Option
			for _, option := range *options {
				if option.Option() == dns.EDNS0SUBNET {
					return nil
				}
			}
			break
		}
	}
	if options == nil {
		msg.SetEdns0(uint16(pluginsState.maxPayloadSize), false)
		for _, extra := range msg.Extra {
			if extra.Header().Rrtype == dns.TypeOPT {
				options = &extra.(*dns.OPT).Option
				break
			}
		}
	}
	if options == nil {
		return nil
	}
	prr := dns.EDNS0_SUBNET{}
	prr.Code = dns.EDNS0SUBNET
	net := plugin.nets[rand.Intn(len(plugin.nets))]
	bits, totalSize := net.Mask.Size()
	if totalSize == 32 {
		prr.Family = 1
	} else if totalSize == 128 {
		prr.Family = 2
	} else {
		return nil
	}
	prr.SourceNetmask = uint8(bits)
	prr.SourceScope = 0
	prr.Address = net.IP
	*options = append(*options, &prr)

	return nil
}
