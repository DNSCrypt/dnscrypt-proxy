//go:build !linux && !windows && !darwin

package udp

import (
	"syscall"
)

func setDF(syscall.RawConn) (bool, error) {
	// no-op on unsupported platforms
	return false, nil
}

func IsSendMsgSizeErr(err error) bool {
	// to be implemented for more specific platforms
	return false
}

func IsRecvMsgSizeErr(err error) bool {
	// to be implemented for more specific platforms
	return false
}
