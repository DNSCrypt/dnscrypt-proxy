//go:build freebsd

package udp

import (
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	msgTypeIPTOS = unix.IP_RECVTOS
	ipv4PKTINFO  = 0x7
)

const ecnIPv4DataLen = 1

const batchSize = 8

func parseIPv4PktInfo(body []byte) (ip netip.Addr, _ uint32, ok bool) {
	// struct in_pktinfo {
	// 	struct in_addr ipi_addr;     /* Header Destination address */
	// };
	if len(body) != 4 {
		return netip.Addr{}, 0, false
	}
	return netip.AddrFrom4(*(*[4]byte)(body)), 0, true
}

// FreeBSD has no IP_PKTINFO. The source address is set using IP_SENDSRCADDR,
// which doesn't take an interface index.
func marshalIPv4PktInfo(ip [4]byte, _ uint32) []byte {
	b := make([]byte, unix.CmsgSpace(len(ip)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.IPPROTO_IP
	h.Type = unix.IP_SENDSRCADDR
	h.SetLen(unix.CmsgLen(len(ip)))
	copy(b[unix.CmsgLen(0):], ip[:])
	return b
}

func isGSOEnabled(syscall.RawConn) bool { return false }

func isECNEnabled() bool { return !isECNDisabledUsingEnv() }

const desiredBufferSize = 7 << 20 // 7 MiB

func appendUDPSegmentSizeMsg([]byte, uint16) []byte { return nil }
