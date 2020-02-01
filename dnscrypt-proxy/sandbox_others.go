// +build !openbsd

package main

import (
	"os"
	"path/filepath"

	"github.com/jedisct1/dlog"
)

func PledgePromises(promises string) {
	dlog.Debugf("Pledging [%s]", promises)
}

func UnveilContainingDirectoryOf(path string, flags string) {
	if len(path) > 0 {
		if !filepath.IsAbs(path) {
			wd, err := os.Getwd()
			if err != nil {
				dlog.Warnf("Unable to get the current working directory: [%s]", err)
				return
			}
			path = filepath.Join(wd, path)
		}
		Unveil(path, flags)
	}
}

func Unveil(path string, flags string) {
	if len(path) > 0 {
		if !filepath.IsAbs(path) {
			wd, err := os.Getwd()
			if err != nil {
				dlog.Warnf("Unable to get the current working directory: [%s]", err)
				return
			}
			path = filepath.Join(wd, path)
		}
		dlog.Debugf("Unveiling [%s] for [%s] access", path, flags)
	}
}

func UnveilBlock() {
	dlog.Debug("Blocking further unveil calls")
}
