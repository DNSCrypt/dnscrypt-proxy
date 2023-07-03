//go:build linux

package quic

import (
	"errors"
	"log"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go/internal/utils"
)

// UDP_SEGMENT controls GSO (Generic Segmentation Offload)
//
//nolint:stylecheck
const UDP_SEGMENT = 103

func setDF(rawConn syscall.RawConn) (bool, error) {
	// Enabling IP_MTU_DISCOVER will force the kernel to return "sendto: message too long"
	// and the datagram will not be fragmented
	var errDFIPv4, errDFIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errDFIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
		errDFIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
	}); err != nil {
		return false, err
	}
	switch {
	case errDFIPv4 == nil && errDFIPv6 == nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv4 and IPv6.")
	case errDFIPv4 == nil && errDFIPv6 != nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv4.")
	case errDFIPv4 != nil && errDFIPv6 == nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv6.")
	case errDFIPv4 != nil && errDFIPv6 != nil:
		return false, errors.New("setting DF failed for both IPv4 and IPv6")
	}
	return true, nil
}

func maybeSetGSO(rawConn syscall.RawConn) bool {
	enable, _ := strconv.ParseBool(os.Getenv("QUIC_GO_ENABLE_GSO"))
	if !enable {
		return false
	}

	var setErr error
	if err := rawConn.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), syscall.IPPROTO_UDP, UDP_SEGMENT, 1)
	}); err != nil {
		setErr = err
	}
	if setErr != nil {
		log.Println("failed to enable GSO")
		return false
	}
	return true
}

func isMsgSizeErr(err error) bool {
	// https://man7.org/linux/man-pages/man7/udp.7.html
	return errors.Is(err, unix.EMSGSIZE)
}

func appendUDPSegmentSizeMsg(b []byte, size uint16) []byte {
	startLen := len(b)
	const dataLen = 2 // payload is a uint16
	b = append(b, make([]byte, unix.CmsgSpace(dataLen))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = syscall.IPPROTO_UDP
	h.Type = UDP_SEGMENT
	h.SetLen(unix.CmsgLen(dataLen))

	// UnixRights uses the private `data` method, but I *think* this achieves the same goal.
	offset := startLen + unix.CmsgSpace(0)
	*(*uint16)(unsafe.Pointer(&b[offset])) = size
	return b
}
