//go:build !windows

package dns

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var minOOB4Size, minOOB6Size = func() (int, int) {
	oob4 := ipv4.NewControlMessage(ipv4.FlagDst | ipv4.FlagInterface)
	oob6 := ipv6.NewControlMessage(ipv6.FlagDst | ipv6.FlagInterface)
	return len(oob4), len(oob6)
}()

// Size return the size of the oob buffer that should be used.
//
// We can't know whether we'll get an IPv4 control message or an
// IPv6 control message ahead of time. To get around this, we size
// the buffer equal to the largest of the two.
var oobSize = max(minOOB4Size, minOOB6Size)

// parseFromOOB takes oob data and returns the destination IP.
func parseFromOOB(oob []byte) net.IP {
	// Start with IPv6 and then fallback to IPv4
	// TODO(fastest963): Figure out a way to prefer one or the other. Looking at
	// the lvl of the header for a 0 or 41 isn't cross-platform.
	if len(oob) >= minOOB6Size {
		cm6 := new(ipv6.ControlMessage)
		if cm6.Parse(oob) == nil && cm6.Dst != nil {
			return cm6.Dst
		}
	}
	if len(oob) >= minOOB4Size {
		cm4 := new(ipv4.ControlMessage)
		if cm4.Parse(oob) == nil && cm4.Dst != nil {
			return cm4.Dst
		}
	}
	return nil
}

// sourceFromOOB takes oob data and returns new oob data with the Src equal to the Dst
func sourceFromOOB(oob []byte) []byte {
	dst := parseFromOOB(oob)
	if dst == nil {
		return nil
	}
	// If the dst is definitely an IPv6, then use ipv6's ControlMessage to
	// respond otherwise use ipv4's because ipv6's marshal ignores ipv4
	// addresses.
	if dst.To4() == nil {
		cm := new(ipv6.ControlMessage)
		cm.Src = dst
		oob = cm.Marshal()
	} else {
		cm := new(ipv4.ControlMessage)
		cm.Src = dst
		oob = cm.Marshal()
	}
	return oob
}
