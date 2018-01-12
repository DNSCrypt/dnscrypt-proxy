package godaemon

// Copyright (c) 2013 VividCortex, Inc. All rights reserved.
// Please see the LICENSE file for applicable license terms.

//#include <sys/types.h>
//#include <sys/sysctl.h>
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
	exeLen := C.size_t(len(exePath))

	// Beware: sizeof(int) != sizeof(C.int)
	var mib [4]C.int
	// From <sys/sysctl.h>
	mib[0] = 1  // CTL_KERN
	mib[1] = 14 // KERN_PROC
	mib[2] = 12 // KERN_PROC_PATHNAME
	mib[3] = -1

	status, err := C.sysctl((*C.int)(unsafe.Pointer(&mib[0])), 4, unsafe.Pointer(&exePath[0]), &exeLen, nil, 0)

	if err != nil {
		return "", fmt.Errorf("sysctl: %v", err)
	}

	// Not sure why this might happen with err being nil, but...
	if status != 0 {
		return "", fmt.Errorf("sysctl returned %d", status)
	}

	// Convert from null-padded []byte to a clean string. (Can't simply cast!)
	exePathStringLen := bytes.Index(exePath, []byte{0})
	exePathString := string(exePath[:exePathStringLen])

	return filepath.Clean(exePathString), nil
}
