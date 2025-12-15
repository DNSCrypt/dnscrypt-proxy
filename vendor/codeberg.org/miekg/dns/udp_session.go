package dns

import "net"

// Session is a small strucures that keep track of where the (potential) UDP message came from.
type Session struct {
	Addr *net.UDPAddr // address from [net.ReadMsgUDP]
	// oob data also returned, this is needed to route to the correct interface. As these are small fixed
	// slices it makes sense to use a sync.Pool, to be able to override this behavior an
	OOB []byte
}
