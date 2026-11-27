//go:build darwin

package udp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	msgTypeIPTOS = unix.IP_RECVTOS
	ipv4PKTINFO  = unix.IP_RECVPKTINFO
)

const ecnIPv4DataLen = 4

const desiredBufferSize = 7 << 20 // 7 MiB

// ReadBatch only returns a single packet on OSX,
// see https://godoc.org/golang.org/x/net/ipv4#PacketConn.ReadBatch.
const batchSize = 1

func parseIPv4PktInfo(body []byte) (ip netip.Addr, ifIndex uint32, ok bool) {
	// struct in_pktinfo {
	// 	unsigned int   ipi_ifindex;  /* Interface index */
	// 	struct in_addr ipi_spec_dst; /* Local address */
	// 	struct in_addr ipi_addr;     /* Header Destination address */
	// };
	if len(body) != 12 {
		return netip.Addr{}, 0, false
	}
	return netip.AddrFrom4(*(*[4]byte)(body[8:12])), binary.NativeEndian.Uint32(body), true
}

// The interface index is not set: if it is, macOS ignores ipi_spec_dst
// and picks a source address of that interface, see
// https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/netinet/udp_usrreq.c#L1531-L1546.
func marshalIPv4PktInfo(ip [4]byte, _ uint32) []byte {
	cm := ipv4.ControlMessage{Src: ip[:]}
	return cm.Marshal()
}

func isGSOEnabled(syscall.RawConn) bool { return false }

func isECNEnabled() bool { return !isECNDisabledUsingEnv() }

// for macOS versions, see https://en.wikipedia.org/wiki/Darwin_(operating_system)#Darwin_20_onwards
const (
	macOSVersion11 = 20
	macOSVersion15 = 24
)

func setDF(rawConn syscall.RawConn) (bool, error) {
	// Setting DF bit is only supported from macOS 11.
	// https://github.com/chromium/chromium/blob/117.0.5881.2/net/socket/udp_socket_posix.cc#L555
	version, err := getMacOSVersion()
	if err != nil || version < macOSVersion11 {
		return false, err
	}

	var controlErr error
	var disableDF bool
	if err := rawConn.Control(func(fd uintptr) {
		addr, err := unix.Getsockname(int(fd))
		if err != nil {
			controlErr = fmt.Errorf("getsockname: %w", err)
			return
		}

		// Dual-stack sockets are effectively IPv6 sockets (with IPV6_ONLY set to 0).
		// On macOS, the DF bit on dual-stack sockets is controlled by the IPV6_DONTFRAG option.
		// See https://datatracker.ietf.org/doc/draft-seemann-tsvwg-udp-fragmentation/ for details.
		switch addr.(type) {
		case *unix.SockaddrInet4:
			controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		case *unix.SockaddrInet6:
			controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)

			// Setting the DF bit on dual-stack sockets works since macOS Sequoia.
			// Disable DF on dual-stack sockets before Sequoia.
			if version < macOSVersion15 {
				// check if this is a dual-stack socket by reading the IPV6_V6ONLY flag
				v6only, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
				if err != nil {
					controlErr = fmt.Errorf("getting IPV6_V6ONLY: %w", err)
					return
				}
				disableDF = v6only == 0
			}
		default:
			controlErr = fmt.Errorf("unknown address type: %T", addr)
		}
	}); err != nil {
		return false, err
	}
	if controlErr != nil {
		return false, controlErr
	}
	return !disableDF, nil
}

func IsSendMsgSizeErr(err error) bool {
	return errors.Is(err, unix.EMSGSIZE)
}

func IsRecvMsgSizeErr(error) bool { return false }

func getMacOSVersion() (int, error) {
	uname := &unix.Utsname{}
	if err := unix.Uname(uname); err != nil {
		return 0, err
	}
	before, _, ok := strings.Cut(string(uname.Release[:]), ".")
	if !ok {
		return 0, nil
	}
	version, err := strconv.Atoi(before)
	if err != nil {
		return 0, err
	}
	return version, nil
}

func appendUDPSegmentSizeMsg([]byte, uint16) []byte { return nil }
