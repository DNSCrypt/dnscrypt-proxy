//go:build darwin || linux || freebsd

package quic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

const (
	ecnMask       = 0x3
	oobBufferSize = 128
)

// Contrary to what the naming suggests, the ipv{4,6}.Message is not dependent on the IP version.
// They're both just aliases for x/net/internal/socket.Message.
// This means we can use this struct to read from a socket that receives both IPv4 and IPv6 messages.
var _ ipv4.Message = ipv6.Message{}

type batchConn interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
}

func inspectReadBuffer(c syscall.RawConn) (int, error) {
	var size int
	var serr error
	if err := c.Control(func(fd uintptr) {
		size, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	}); err != nil {
		return 0, err
	}
	return size, serr
}

func inspectWriteBuffer(c syscall.RawConn) (int, error) {
	var size int
	var serr error
	if err := c.Control(func(fd uintptr) {
		size, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	}); err != nil {
		return 0, err
	}
	return size, serr
}

type oobConn struct {
	OOBCapablePacketConn
	batchConn batchConn

	readPos uint8
	// Packets received from the kernel, but not yet returned by ReadPacket().
	messages []ipv4.Message
	buffers  [batchSize]*packetBuffer

	cap connCapabilities
}

var _ rawConn = &oobConn{}

func newConn(c OOBCapablePacketConn, supportsDF bool) (*oobConn, error) {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	needsPacketInfo := false
	if udpAddr, ok := c.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP.IsUnspecified() {
		needsPacketInfo = true
	}
	// We don't know if this a IPv4-only, IPv6-only or a IPv4-and-IPv6 connection.
	// Try enabling receiving of ECN and packet info for both IP versions.
	// We expect at least one of those syscalls to succeed.
	var errECNIPv4, errECNIPv6, errPIIPv4, errPIIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errECNIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
		errECNIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)

		if needsPacketInfo {
			errPIIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, ipv4RECVPKTINFO, 1)
			errPIIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, ipv6RECVPKTINFO, 1)
		}
	}); err != nil {
		return nil, err
	}
	switch {
	case errECNIPv4 == nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4 and IPv6.")
	case errECNIPv4 == nil && errECNIPv6 != nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4.")
	case errECNIPv4 != nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv6.")
	case errECNIPv4 != nil && errECNIPv6 != nil:
		return nil, errors.New("activating ECN failed for both IPv4 and IPv6")
	}
	if needsPacketInfo {
		switch {
		case errPIIPv4 == nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info for IPv4 and IPv6.")
		case errPIIPv4 == nil && errPIIPv6 != nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info bits for IPv4.")
		case errPIIPv4 != nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info bits for IPv6.")
		case errPIIPv4 != nil && errPIIPv6 != nil:
			return nil, errors.New("activating packet info failed for both IPv4 and IPv6")
		}
	}

	// Allows callers to pass in a connection that already satisfies batchConn interface
	// to make use of the optimisation. Otherwise, ipv4.NewPacketConn would unwrap the file descriptor
	// via SyscallConn(), and read it that way, which might not be what the caller wants.
	var bc batchConn
	if ibc, ok := c.(batchConn); ok {
		bc = ibc
	} else {
		bc = ipv4.NewPacketConn(c)
	}

	// Try enabling GSO.
	// This will only succeed on Linux, and only for kernels > 4.18.
	supportsGSO := maybeSetGSO(rawConn)

	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		// preallocate the [][]byte
		msgs[i].Buffers = make([][]byte, 1)
	}
	oobConn := &oobConn{
		OOBCapablePacketConn: c,
		batchConn:            bc,
		messages:             msgs,
		readPos:              batchSize,
	}
	oobConn.cap.DF = supportsDF
	oobConn.cap.GSO = supportsGSO
	for i := 0; i < batchSize; i++ {
		oobConn.messages[i].OOB = make([]byte, oobBufferSize)
	}
	return oobConn, nil
}

func (c *oobConn) ReadPacket() (receivedPacket, error) {
	if len(c.messages) == int(c.readPos) { // all messages read. Read the next batch of messages.
		c.messages = c.messages[:batchSize]
		// replace buffers data buffers up to the packet that has been consumed during the last ReadBatch call
		for i := uint8(0); i < c.readPos; i++ {
			buffer := getPacketBuffer()
			buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
			c.buffers[i] = buffer
			c.messages[i].Buffers[0] = c.buffers[i].Data
		}
		c.readPos = 0

		n, err := c.batchConn.ReadBatch(c.messages, 0)
		if n == 0 || err != nil {
			return receivedPacket{}, err
		}
		c.messages = c.messages[:n]
	}

	msg := c.messages[c.readPos]
	buffer := c.buffers[c.readPos]
	c.readPos++

	data := msg.OOB[:msg.NN]
	p := receivedPacket{
		remoteAddr: msg.Addr,
		rcvTime:    time.Now(),
		data:       msg.Buffers[0][:msg.N],
		buffer:     buffer,
	}
	for len(data) > 0 {
		hdr, body, remainder, err := unix.ParseOneSocketControlMessage(data)
		if err != nil {
			return receivedPacket{}, err
		}
		if hdr.Level == unix.IPPROTO_IP {
			switch hdr.Type {
			case msgTypeIPTOS:
				p.ecn = protocol.ECN(body[0] & ecnMask)
			case msgTypeIPv4PKTINFO:
				// struct in_pktinfo {
				// 	unsigned int   ipi_ifindex;  /* Interface index */
				// 	struct in_addr ipi_spec_dst; /* Local address */
				// 	struct in_addr ipi_addr;     /* Header Destination
				// 									address */
				// };
				var ip [4]byte
				if len(body) == 12 {
					copy(ip[:], body[8:12])
					p.info.ifIndex = binary.LittleEndian.Uint32(body)
				} else if len(body) == 4 {
					// FreeBSD
					copy(ip[:], body)
				}
				p.info.addr = netip.AddrFrom4(ip)
			}
		}
		if hdr.Level == unix.IPPROTO_IPV6 {
			switch hdr.Type {
			case unix.IPV6_TCLASS:
				p.ecn = protocol.ECN(body[0] & ecnMask)
			case msgTypeIPv6PKTINFO:
				// struct in6_pktinfo {
				// 	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
				// 	unsigned int    ipi6_ifindex; /* send/recv interface index */
				// };
				if len(body) == 20 {
					var ip [16]byte
					copy(ip[:], body[:16])
					p.info.addr = netip.AddrFrom16(ip)
					p.info.ifIndex = binary.LittleEndian.Uint32(body[16:])
				}
			}
		}
		data = remainder
	}
	return p, nil
}

// WriteTo (re)implements the net.PacketConn method.
// This is needed for users who call OptimizeConn to be able to send (non-QUIC) packets on the underlying connection.
// With GSO enabled, this would otherwise not be needed, as the kernel requires the UDP_SEGMENT message to be set.
func (c *oobConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.WritePacket(p, uint16(len(p)), addr, nil)
}

// WritePacket writes a new packet.
// If the connection supports GSO (and we activated GSO support before),
// it appends the UDP_SEGMENT size message to oob.
// Callers are advised to make sure that oob has a sufficient capacity,
// such that appending the UDP_SEGMENT size message doesn't cause an allocation.
func (c *oobConn) WritePacket(b []byte, packetSize uint16, addr net.Addr, oob []byte) (n int, err error) {
	if c.cap.GSO {
		oob = appendUDPSegmentSizeMsg(oob, packetSize)
	} else if uint16(len(b)) != packetSize {
		panic(fmt.Sprintf("inconsistent length. got: %d. expected %d", packetSize, len(b)))
	}
	n, _, err = c.OOBCapablePacketConn.WriteMsgUDP(b, oob, addr.(*net.UDPAddr))
	return n, err
}

func (c *oobConn) capabilities() connCapabilities {
	return c.cap
}

type packetInfo struct {
	addr    netip.Addr
	ifIndex uint32
}

func (info *packetInfo) OOB() []byte {
	if info == nil {
		return nil
	}
	if info.addr.Is4() {
		ip := info.addr.As4()
		// struct in_pktinfo {
		// 	unsigned int   ipi_ifindex;  /* Interface index */
		// 	struct in_addr ipi_spec_dst; /* Local address */
		// 	struct in_addr ipi_addr;     /* Header Destination address */
		// };
		cm := ipv4.ControlMessage{
			Src:     ip[:],
			IfIndex: int(info.ifIndex),
		}
		return cm.Marshal()
	} else if info.addr.Is6() {
		ip := info.addr.As16()
		// struct in6_pktinfo {
		// 	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
		// 	unsigned int    ipi6_ifindex; /* send/recv interface index */
		// };
		cm := ipv6.ControlMessage{
			Src:     ip[:],
			IfIndex: int(info.ifIndex),
		}
		return cm.Marshal()
	}
	return nil
}
