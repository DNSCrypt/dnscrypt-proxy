package godaemon

// Copyright (c) 2013 VividCortex, Inc. All rights reserved.
// Please see the LICENSE file for applicable license terms.

//#include <mach-o/dyld.h>
import "C"

import (
	"bytes"
	"fmt"
	"path/filepath"
	"unsafe"
)

// GetExecutablePath returns the absolute path to the currently running
// executable.  It is used internally by the godaemon package, and exported
// publicly because it's useful outside of the package too.
func GetExecutablePath() (string, error) {
	PATH_MAX := 1024 // From <sys/syslimits.h>
	exePath := make([]byte, PATH_MAX)
	exeLen := C.uint32_t(len(exePath))

	status, err := C._NSGetExecutablePath((*C.char)(unsafe.Pointer(&exePath[0])), &exeLen)

	if err != nil {
		return "", fmt.Errorf("_NSGetExecutablePath: %v", err)
	}

	// Not sure why this might happen with err being nil, but...
	if status != 0 {
		return "", fmt.Errorf("_NSGetExecutablePath returned %d", status)
	}

	// Convert from null-padded []byte to a clean string. (Can't simply cast!)
	exePathStringLen := bytes.Index(exePath, []byte{0})
	exePathString := string(exePath[:exePathStringLen])

	return filepath.Clean(exePathString), nil
}
