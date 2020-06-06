package main

import (
	"os/exec"
	"strings"
	"time"
)

func TimezoneSetup() error {
	out, err := exec.Command("/system/bin/getprop", "persist.sys.timezone").Output()
	if err != nil {
		return err
	}
	z, err := time.LoadLocation(strings.TrimSpace(string(out)))
	if err != nil {
		return err
	}
	time.Local = z
	return nil
}
