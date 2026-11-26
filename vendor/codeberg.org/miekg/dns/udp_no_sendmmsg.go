//go:build windows

package dns

type udpWriter struct{}

func (w *udpWriter) write(_ *Session, _ []byte) bool { return false }
