package godaemon

// Copyright (c) 2013 VividCortex, Inc. All rights reserved.
// Please see the LICENSE file for applicable license terms.

import (
	"fmt"
	"path/filepath"
)

// GetExecutablePath returns the absolute path to the currently running
// executable.  It is used internally by the godaemon package, and exported
// publicly because it's useful outside of the package too.
func GetExecutablePath() (string, error) {
	exePath, err := Readlink("/proc/self/exe")

	if err != nil {
		err = fmt.Errorf("can't read /proc/self/exe: %v", err)
	}

	return filepath.Clean(exePath), err
}
