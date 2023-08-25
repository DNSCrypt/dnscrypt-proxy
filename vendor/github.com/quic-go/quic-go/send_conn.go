package quic

import (
	"fmt"
	"math"
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
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

	localAddr  net.Addr
	remoteAddr net.Addr

	logger utils.Logger

	info packetInfo
	oob  []byte
	// If GSO enabled, and we receive a GSO error for this remote address, GSO is disabled.
	gotGSOError bool
}

var _ sendConn = &sconn{}

func newSendConn(c rawConn, remote net.Addr, info packetInfo, logger utils.Logger) *sconn {
	localAddr := c.LocalAddr()
	if info.addr.IsValid() {
		if udpAddr, ok := localAddr.(*net.UDPAddr); ok {
			addrCopy := *udpAddr
			addrCopy.IP = info.addr.AsSlice()
			localAddr = &addrCopy
		}
	}

	oob := info.OOB()
	// add 32 bytes, so we can add the UDP_SEGMENT msg
	l := len(oob)
	oob = append(oob, make([]byte, 32)...)
	oob = oob[:l]
	return &sconn{
		rawConn:    c,
		localAddr:  localAddr,
		remoteAddr: remote,
		info:       info,
		oob:        oob,
		logger:     logger,
	}
}

func (c *sconn) Write(p []byte, size protocol.ByteCount) error {
	if !c.capabilities().GSO {
		if protocol.ByteCount(len(p)) != size {
			panic(fmt.Sprintf("inconsistent packet size (%d vs %d)", len(p), size))
		}
		_, err := c.WritePacket(p, c.remoteAddr, c.oob)
		return err
	}
	// GSO is supported. Append the control message and send.
	if size > math.MaxUint16 {
		panic("size overflow")
	}
	_, err := c.WritePacket(p, c.remoteAddr, appendUDPSegmentSizeMsg(c.oob, uint16(size)))
	if err != nil && isGSOError(err) {
		// disable GSO for future calls
		c.gotGSOError = true
		if c.logger.Debug() {
			c.logger.Debugf("GSO failed when sending to %s", c.remoteAddr)
		}
		// send out the packets one by one
		for len(p) > 0 {
			l := len(p)
			if l > int(size) {
				l = int(size)
			}
			if _, err := c.WritePacket(p[:l], c.remoteAddr, c.oob); err != nil {
				return err
			}
			p = p[l:]
		}
		return nil
	}
	return err
}

func (c *sconn) capabilities() connCapabilities {
	capabilities := c.rawConn.capabilities()
	if capabilities.GSO {
		capabilities.GSO = !c.gotGSOError
	}
	return capabilities
}

func (c *sconn) RemoteAddr() net.Addr { return c.remoteAddr }
func (c *sconn) LocalAddr() net.Addr  { return c.localAddr }
