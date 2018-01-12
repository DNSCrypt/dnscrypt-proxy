package godaemon

// Copyright (c) 2013-2015 VividCortex, Inc. All rights reserved.
// Please see the LICENSE file for applicable license terms.

import (
	"fmt"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	getModuleFileName = syscall.MustLoadDLL("kernel32.dll").MustFindProc("GetModuleFileNameW")
)

// GetExecutablePath returns the absolute path to the currently running
// executable.  It is used internally by the godaemon package, and exported
// publicly because it's useful outside of the package too.
func GetExecutablePath() (string, error) {
	buf := make([]uint16, syscall.MAX_PATH+1)

	res, _, err := getModuleFileName.Call(0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if res == 0 || res >= syscall.MAX_PATH || buf[0] == 0 || buf[res-1] == 0 {
		return "", fmt.Errorf("GetModuleFileNameW returned %d errno=%d", res, err)
	}

	return string(utf16.Decode(buf[:res])), nil
}
