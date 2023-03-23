//go:build windows
// +build windows

package check

import (
	"os"
	"syscall"
)

func isTerminal() bool {
	var mode uint32
	err := syscall.GetConsoleMode(syscall.Handle(os.Stdout.Fd()), &mode)
	return err == nil
}
