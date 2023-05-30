//go:build !linux

package quic

func forceSetReceiveBuffer(c any, bytes int) error { return nil }
func forceSetSendBuffer(c any, bytes int) error    { return nil }
