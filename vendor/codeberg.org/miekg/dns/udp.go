//go:build !windows

package dns

import (
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var minOOB4Size, minOOB6Size = func() (int, int) {
	oob4 := ipv4.NewControlMessage(ipv4.FlagDst | ipv4.FlagInterface)
	oob6 := ipv6.NewControlMessage(ipv6.FlagDst | ipv6.FlagInterface)
	return len(oob4), len(oob6)
}()

// oobSize return the size of the oob buffer that should be used.
//
// We can't know whether we'll get an IPv4 control message or an
// IPv6 control message ahead of time. To get around this, we size
// the buffer equal to the largest of the two.
var oobSize = max(minOOB4Size, minOOB6Size)

// sourceFromOOB takes oob data and returns new oob data with the Src equal to the Dst.
func sourceFromOOB(oob []byte) []byte {
	if len(oob) >= minOOB6Size {
		cm6 := new(ipv6.ControlMessage)
		if cm6.Parse(oob) == nil && cm6.Dst != nil {
			// If the dst is definitely an IPv6, then use ipv6's ControlMessage to
			// respond otherwise use ipv4's because ipv6's marshal ignores ipv4 addresses.
			if cm6.Dst.To4() == nil {
				*cm6 = ipv6.ControlMessage{Src: cm6.Dst}
				return cm6.Marshal()
			}
			return (&ipv4.ControlMessage{Src: cm6.Dst}).Marshal()
		}
	}

	if len(oob) >= minOOB4Size {
		cm4 := new(ipv4.ControlMessage)
		if cm4.Parse(oob) == nil && cm4.Dst != nil {
			*cm4 = ipv4.ControlMessage{Src: cm4.Dst}
			return cm4.Marshal()
		}
	}

	return nil
}
