//go:build !darwin && !freebsd && !linux && !openbsd && !windows

package quic

func inspectReadBuffer(any) (int, error)  { return 0, nil }
func inspectWriteBuffer(any) (int, error) { return 0, nil }
