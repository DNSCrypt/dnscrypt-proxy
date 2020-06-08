// +build !linux,!darwin,!dragonfly,!freebsd,!netbsd,!openbsd,!windows

package check

func isTerminal() bool {
	return false
}
