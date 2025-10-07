package main

import (
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

// PluginDeviceAndSubscriberID injects both device_id (65001) and subscriber_id (65075)
// EDNS0 local options into outgoing DNS queries when configured.
type PluginDeviceAndSubscriberID struct {
	deviceID     string
	subscriberID string
}

var _ Plugin = (*PluginDeviceAndSubscriberID)(nil)

func (p *PluginDeviceAndSubscriberID) Name() string {
	return "device_and_subscriber_id"
}

func (p *PluginDeviceAndSubscriberID) Description() string {
	return "Set both EDNS-device-id (65001) and EDNS-subscriber-id (65075) in outgoing queries."
}

func (p *PluginDeviceAndSubscriberID) Init(proxy *Proxy) error {
	p.deviceID = proxy.ednsDeviceID
	p.subscriberID = proxy.ednsSubscriberID
	dlog.Notice("EDNS device and subscriber IDs plugin enabled")
	return nil
}

func (p *PluginDeviceAndSubscriberID) Drop() error {
	return nil
}

func (p *PluginDeviceAndSubscriberID) Reload() error {
	return nil
}

func (p *PluginDeviceAndSubscriberID) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	// If either ID is missing, do nothing
	if p.deviceID == "" || p.subscriberID == "" {
		return nil
	}

	var options *[]dns.EDNS0

	// Locate existing OPT record
	for _, extra := range msg.Extra {
		if extra.Header().Rrtype == dns.TypeOPT {
			options = &extra.(*dns.OPT).Option
			break
		}
	}

	// If no OPT found, create one
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

	// Track whether the options already exist
	hasDevice := false
	hasSubscriber := false
	for _, o := range *options {
		switch o.Option() {
		case 65001:
			hasDevice = true
		case 65075:
			hasSubscriber = true
		}
	}

	// Append missing ones
	if p.deviceID != "" && !hasDevice {
		e := new(dns.EDNS0_LOCAL)
		e.Code = 65001
		e.Data = []byte(p.deviceID)
		*options = append(*options, e)
	}

	if p.subscriberID != "" && !hasSubscriber {
		e := new(dns.EDNS0_LOCAL)
		e.Code = 65075
		e.Data = []byte(p.subscriberID)
		*options = append(*options, e)
	}

	return nil
}
