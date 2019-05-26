package main

import (
	"github.com/miekg/dns"
)

type PluginEdns struct {
	removeEdnsClientSubnet bool
}

func (plugin *PluginEdns) Name() string {
	return "edns"
}

func (plugin *PluginEdns) Description() string {
	return "Remove EDNS client subnet data from requests"
}

func (plugin *PluginEdns) Init(proxy *Proxy) error {
	plugin.removeEdnsClientSubnet = proxy.removeEdnsClientSubnet
	return nil
}

func (plugin *PluginEdns) Drop() error {
	return nil
}

func (plugin *PluginEdns) Reload() error {
	return nil
}

func (plugin *PluginEdns) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	edns := msg.IsEdns0()
	if edns == nil {
		return nil
	}

	// extract client subnet details for logging
	for _, o := range edns.Option {
		switch o.(type) {
		case *dns.EDNS0_SUBNET:
			subnet := o.(*dns.EDNS0_SUBNET)

			switch subnet.Family {
			case 1: // IPv4
				fallthrough
			case 2: // IPv6
				pluginsState.ednsClientIP = subnet.Address
				pluginsState.ednsClientMask = subnet.SourceNetmask
			}
		}
	}

	// remove client subnet details from request
	if plugin.removeEdnsClientSubnet {
		plugin.removeClientSubnet(edns)
	}

	return nil
}

func (plugin *PluginEdns) removeClientSubnet(edns *dns.OPT) {
	i := 0
	for _, o := range edns.Option {
		switch o.(type) {
		case *dns.EDNS0_SUBNET:
		default:
			edns.Option[i] = o
			i++
		}
	}
	edns.Option = edns.Option[:i]
}
