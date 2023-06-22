package quic

import (
	"math"
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
)

// A sendConn allows sending using a simple Write() on a non-connected packet conn.
type sendConn interface {
	Write(b []byte, size protocol.ByteCount) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	capabilities() connCapabilities
}

type sconn struct {
	rawConn

	remoteAddr net.Addr
	info       packetInfo
	oob        []byte
}

var _ sendConn = &sconn{}

func newSendConn(c rawConn, remote net.Addr) *sconn {
	sc := &sconn{
		rawConn:    c,
		remoteAddr: remote,
	}
	if c.capabilities().GSO {
		// add 32 bytes, so we can add the UDP_SEGMENT msg
		sc.oob = make([]byte, 0, 32)
	}
	return sc
}

func newSendConnWithPacketInfo(c rawConn, remote net.Addr, info packetInfo) *sconn {
	oob := info.OOB()
	if c.capabilities().GSO {
		// add 32 bytes, so we can add the UDP_SEGMENT msg
		l := len(oob)
		oob = append(oob, make([]byte, 32)...)
		oob = oob[:l]
	}
	return &sconn{
		rawConn:    c,
		remoteAddr: remote,
		info:       info,
		oob:        oob,
	}
}

func (c *sconn) Write(p []byte, size protocol.ByteCount) error {
	if size > math.MaxUint16 {
		panic("size overflow")
	}
	_, err := c.WritePacket(p, uint16(size), c.remoteAddr, c.oob)
	return err
}

func (c *sconn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *sconn) LocalAddr() net.Addr {
	addr := c.rawConn.LocalAddr()
	if c.info.addr.IsValid() {
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			addrCopy := *udpAddr
			addrCopy.IP = c.info.addr.AsSlice()
			addr = &addrCopy
		}
	}
	return addr
}
