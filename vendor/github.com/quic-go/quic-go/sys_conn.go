package quic

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

// OOBCapablePacketConn is a connection that allows the reading of ECN bits from the IP header.
// If the PacketConn passed to Dial or Listen satisfies this interface, quic-go will use it.
// In this case, ReadMsgUDP() will be used instead of ReadFrom() to read packets.
type OOBCapablePacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}

var _ OOBCapablePacketConn = &net.UDPConn{}

// OptimizeConn takes a net.PacketConn and attempts to enable various optimizations that will improve QUIC performance:
//  1. It enables the Don't Fragment (DF) bit on the IP header.
//     This is required to run DPLPMTUD (Path MTU Discovery, RFC 8899).
//  2. It enables reading of the ECN bits from the IP header.
//     This allows the remote node to speed up its loss detection and recovery.
//  3. It uses batched syscalls (recvmmsg) to more efficiently receive packets from the socket.
//  4. It uses Generic Segmentation Offload (GSO) to efficiently send batches of packets (on Linux).
//
// In order for this to work, the connection needs to implement the OOBCapablePacketConn interface (as a *net.UDPConn does).
//
// It's only necessary to call this function explicitly if the application calls WriteTo
// after passing the connection to the Transport.
func OptimizeConn(c net.PacketConn) (net.PacketConn, error) {
	return wrapConn(c)
}

func wrapConn(pc net.PacketConn) (interface {
	net.PacketConn
	rawConn
}, error,
) {
	conn, ok := pc.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	var supportsDF bool
	if ok {
		rawConn, err := conn.SyscallConn()
		if err != nil {
			return nil, err
		}

		if _, ok := pc.LocalAddr().(*net.UDPAddr); ok {
			// Only set DF on sockets that we expect to be able to handle that configuration.
			var err error
			supportsDF, err = setDF(rawConn)
			if err != nil {
				return nil, err
			}
		}
	}
	c, ok := pc.(OOBCapablePacketConn)
	if !ok {
		utils.DefaultLogger.Infof("PacketConn is not a net.UDPConn. Disabling optimizations possible on UDP connections.")
		return &basicConn{PacketConn: pc, supportsDF: supportsDF}, nil
	}
	return newConn(c, supportsDF)
}

// The basicConn is the most trivial implementation of a rawConn.
// It reads a single packet from the underlying net.PacketConn.
// It is used when
// * the net.PacketConn is not a OOBCapablePacketConn, and
// * when the OS doesn't support OOB.
type basicConn struct {
	net.PacketConn
	supportsDF bool
}

var _ rawConn = &basicConn{}

func (c *basicConn) ReadPacket() (receivedPacket, error) {
	buffer := getPacketBuffer()
	// The packet size should not exceed protocol.MaxPacketBufferSize bytes
	// If it does, we only read a truncated packet, which will then end up undecryptable
	buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
	n, addr, err := c.PacketConn.ReadFrom(buffer.Data)
	if err != nil {
		return receivedPacket{}, err
	}
	return receivedPacket{
		remoteAddr: addr,
		rcvTime:    time.Now(),
		data:       buffer.Data[:n],
		buffer:     buffer,
	}, nil
}

func (c *basicConn) WritePacket(b []byte, packetSize uint16, addr net.Addr, _ []byte) (n int, err error) {
	if uint16(len(b)) != packetSize {
		panic(fmt.Sprintf("inconsistent length. got: %d. expected %d", packetSize, len(b)))
	}
	return c.PacketConn.WriteTo(b, addr)
}

func (c *basicConn) capabilities() connCapabilities { return connCapabilities{DF: c.supportsDF} }
