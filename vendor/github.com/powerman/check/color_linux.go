//go:build linux

package check

import (
	"os"

	"golang.org/x/sys/unix"
)

func isTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS) //nolint:gosec // False positive.
	return err == nil
}
