package udp

import (
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

type Capabilities struct {
	// This connection has the Don't Fragment (DF) bit set.
	// This means it makes to run DPLPMTUD.
	DF bool
	// GSO (Generic Segmentation Offload) supported
	GSO bool
	// ECN (Explicit Congestion Notifications) supported
	ECN bool
}

// Packet is a received UDP datagram.
type Packet struct {
	Buffer     *PacketBuffer
	RemoteAddr net.Addr
	RcvTime    monotime.Time
	Data       []byte
	ECN        protocol.ECN
	Info       PacketInfo
}

// Conn reads and writes UDP datagrams, including their ancillary data.
type Conn interface {
	ReadPacket() (Packet, error)
	// WritePacket writes a packet on the wire.
	// gsoSize is the size of a single packet, or 0 to disable GSO.
	// It is invalid to set gsoSize if capabilities.GSO is not set.
	WritePacket(b []byte, addr net.Addr, packetInfoOOB []byte, gsoSize uint16, ecn protocol.ECN) (int, error)
	LocalAddr() net.Addr
	SetReadDeadline(time.Time) error
	io.Closer

	Capabilities() Capabilities
}

// OOBCapablePacketConn is a connection that allows the reading of ECN bits from the IP header.
// In this case, packets will be read in batches, and [OOBCapablePacketConn.WriteMsgUDP]
// will be used instead of [net.PacketConn.WriteTo] to write packets.
type OOBCapablePacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}

var _ OOBCapablePacketConn = &net.UDPConn{}

// Wrap configures pc for UDP I/O.
// If pc already implements Conn, it is returned unchanged.
func Wrap(pc net.PacketConn) (Conn, error) {
	// Conn uses internal types, so only packages in this module (e.g. simnet) can implement it.
	if c, ok := pc.(Conn); ok {
		return c, nil
	}
	if err := setReceiveBuffer(pc); err != nil {
		if !strings.Contains(err.Error(), "use of closed network connection") {
			setBufferWarningOnce.Do(func() {
				if disable, _ := strconv.ParseBool(os.Getenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING")); disable {
					return
				}
				log.Printf("%s. See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details.", err)
			})
		}
	}
	if err := setSendBuffer(pc); err != nil {
		if !strings.Contains(err.Error(), "use of closed network connection") {
			setBufferWarningOnce.Do(func() {
				if disable, _ := strconv.ParseBool(os.Getenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING")); disable {
					return
				}
				log.Printf("%s. See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details.", err)
			})
		}
	}

	conn, ok := pc.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	var supportsDF bool
	if ok {
		rawConn, err := conn.SyscallConn()
		if err != nil {
			return nil, err
		}

		// only set DF on UDP sockets
		if _, ok := pc.LocalAddr().(*net.UDPAddr); ok {
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

var _ Conn = &basicConn{}

func (c *basicConn) ReadPacket() (Packet, error) {
	buffer := GetPacketBuffer()
	// The packet size should not exceed protocol.MaxPacketBufferSize bytes.
	// Larger packets are truncated and will fail decryption.
	buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
	n, addr, err := c.ReadFrom(buffer.Data)
	if err != nil {
		return Packet{}, err
	}
	return Packet{
		RemoteAddr: addr,
		RcvTime:    monotime.Now(),
		Data:       buffer.Data[:n],
		Buffer:     buffer,
	}, nil
}

func (c *basicConn) WritePacket(b []byte, addr net.Addr, _ []byte, gsoSize uint16, ecn protocol.ECN) (n int, err error) {
	if gsoSize != 0 {
		panic("cannot use GSO with a basicConn")
	}
	if ecn != protocol.ECNUnsupported {
		panic("cannot use ECN with a basicConn")
	}
	return c.WriteTo(b, addr)
}

func (c *basicConn) Capabilities() Capabilities { return Capabilities{DF: c.supportsDF} }

// only print warnings about the UDP receive buffer size once
var setBufferWarningOnce sync.Once
