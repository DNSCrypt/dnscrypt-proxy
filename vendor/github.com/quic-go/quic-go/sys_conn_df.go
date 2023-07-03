//go:build !linux && !windows

package quic

import (
	"syscall"
)

func setDF(syscall.RawConn) (bool, error) {
	// no-op on unsupported platforms
	return false, nil
}

func isMsgSizeErr(err error) bool {
	// to be implemented for more specific platforms
	return false
}
