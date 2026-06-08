//go:build !go1.26

package handshake

func withoutFIPSEnforcement(f func()) {
	f()
}
