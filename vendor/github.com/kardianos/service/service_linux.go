// Copyright 2015 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package service

import (
	"bufio"
	"os"
	"strings"
)

var cgroupFile = "/proc/1/cgroup"

type linuxSystemService struct {
	name        string
	detect      func() bool
	interactive func() bool
	new         func(i Interface, platform string, c *Config) (Service, error)
}

func (sc linuxSystemService) String() string {
	return sc.name
}
func (sc linuxSystemService) Detect() bool {
	return sc.detect()
}
func (sc linuxSystemService) Interactive() bool {
	return sc.interactive()
}
func (sc linuxSystemService) New(i Interface, c *Config) (Service, error) {
	return sc.new(i, sc.String(), c)
}

func init() {
	ChooseSystem(linuxSystemService{
		name:   "linux-systemd",
		detect: isSystemd,
		interactive: func() bool {
			is, _ := isInteractive()
			return is
		},
		new: newSystemdService,
	},
		linuxSystemService{
			name:   "linux-upstart",
			detect: isUpstart,
			interactive: func() bool {
				is, _ := isInteractive()
				return is
			},
			new: newUpstartService,
		},
		linuxSystemService{
			name:   "unix-systemv",
			detect: func() bool { return true },
			interactive: func() bool {
				is, _ := isInteractive()
				return is
			},
			new: newSystemVService,
		},
	)
}

func isInteractive() (bool, error) {
	// TODO: This is not true for user services.
	inContainer, err := isInContainer(cgroupFile)
	if err != nil {
		return false, err
	}
	return os.Getppid() != 1 || inContainer, nil
}

// isInContainer checks if the service is being executed in docker or lxc
// container.
func isInContainer(cgroupPath string) (bool, error) {
	const maxlines = 5 // maximum lines to scan

	f, err := os.Open(cgroupPath)
	if err != nil {
		return false, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)

	lines := 0
	for scan.Scan() && !(lines > maxlines) {
		if strings.Contains(scan.Text(), "docker") || strings.Contains(scan.Text(), "lxc") {
			return true, nil
		}
		lines++
	}
	if err := scan.Err(); err != nil {
		return false, err
	}

	return false, nil
}

var tf = map[string]interface{}{
	"cmd": func(s string) string {
		return `"` + strings.Replace(s, `"`, `\"`, -1) + `"`
	},
	"cmdEscape": func(s string) string {
		return strings.Replace(s, " ", `\x20`, -1)
	},
}
