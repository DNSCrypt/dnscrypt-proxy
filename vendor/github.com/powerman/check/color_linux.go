//go:build linux
// +build linux

package check

import (
	"os"

	"golang.org/x/sys/unix"
)

func isTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS)
	return err == nil
}
