package main

import (
	"flag"
	"os"
	"path/filepath"
	"strconv"

	"github.com/dchest/safefile"
)

var pidFile = flag.String("pidfile", "", "Store the PID into a file")

func PidFileCreate() error {
	if pidFile == nil || len(*pidFile) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(*pidFile), 0755); err != nil {
		return err
	}
	return safefile.WriteFile(*pidFile, []byte(strconv.Itoa(os.Getpid())), 0644)
}

func PidFileRemove() error {
	if pidFile == nil || len(*pidFile) == 0 {
		return nil
	}
	return os.Remove(*pidFile)
}
