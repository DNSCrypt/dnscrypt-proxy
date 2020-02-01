package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/jedisct1/dlog"
)

var (
	workingDir = ""
)

func PledgePromises(promises string) {
	dlog.Debugf("Pledging [%s]", promises)
	err := unix.PledgePromises(promises)
	if err != nil {
		dlog.Fatalf("Failed to pledge [%s]: [%s]", promises, err)
	}
}

func UnveilContainingDirectoryOf(path string, flags string) {
	if len(path) > 0 {
		saveWorkingDir()
		if !filepath.IsAbs(path) {
			path = filepath.Join(workingDir, path)
		}
		Unveil(filepath.Dir(path), flags)
	}
}

func Unveil(path string, flags string) {
	if len(path) > 0 {
		saveWorkingDir()
		dlog.Debugf("Unveiling [%s] for [%s] access", path, flags)
		if !filepath.IsAbs(path) {
			path = filepath.Join(workingDir, path)
		}
		err := unix.Unveil(path, flags)
		if err != nil {
			dlog.Fatalf("Failed to unveil [%s] for [%s] access: [%s]", path, flags, err)
		}
	}
}

func UnveilBlock() {
	dlog.Debug("Blocking further unveil calls")
	err := unix.UnveilBlock()
	if err != nil {
		dlog.Fatalf("UnveilBlock failed: [%s]", err)
	}
}

// stash the working dir because once we start unveiling it becomes difficult to access it
func saveWorkingDir() {
	if len(workingDir) == 0 {
		wd, err := os.Getwd()
		if err != nil {
			dlog.Fatalf("Unable to get the current working directory: [%s]", err)
		}
		workingDir = wd
	}
}
