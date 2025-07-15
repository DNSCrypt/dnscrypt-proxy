// Copyright 2015 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package service

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

var cgroupFile = "/proc/1/cgroup"
var mountInfoFile = "/proc/self/mountinfo"
var dockerEnvFile = "/.dockerenv"

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
			name:   "linux-openrc",
			detect: isOpenRC,
			interactive: func() bool {
				is, _ := isInteractive()
				return is
			},
			new: newOpenRCService,
		},
		linuxSystemService{
			name:   "linux-rcs",
			detect: isRCS,
			interactive: func() bool {
				is, _ := isInteractive()
				return is
			},
			new: newRCSService,
		},
		linuxSystemService{
			name:   "linux-procd",
			detect: isProcd,
			interactive: func() bool {
				is, _ := isInteractive()
				return is
			},
			new: newProcdService,
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

func binaryName(pid int) (string, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	dataBytes, err := ioutil.ReadFile(statPath)
	if err != nil {
		return "", err
	}

	// First, parse out the image name
	data := string(dataBytes)
	binStart := strings.IndexRune(data, '(') + 1
	binEnd := strings.IndexRune(data[binStart:], ')')
	return data[binStart : binStart+binEnd], nil
}

func isInteractive() (bool, error) {
	inContainer, err := isInContainer()
	if err != nil {
		return false, err
	}

	if inContainer {
		return true, nil
	}

	ppid := os.Getppid()
	if ppid == 1 {
		return false, nil
	}

	binary, _ := binaryName(ppid)
	return binary != "systemd", nil
}

// isInContainer checks if the service is being executed in docker or lxc
// container.
func isInContainer() (bool, error) {
	inContainer, err := isInContainerDockerEnv(dockerEnvFile)
	if err != nil {
		return false, err
	}
	if inContainer {
		return true, nil
	}

	inContainer, err = isInContainerCGroup(cgroupFile)
	if err != nil {
		return false, err
	}
	if inContainer {
		return true, nil
	}

	return isInContainerMountInfo(mountInfoFile)
}

func isInContainerDockerEnv(filePath string) (bool, error) {
	_, err := os.Stat(filePath)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	return false, err
}

func isInContainerMountInfo(filePath string) (bool, error) {
	const maxlines = 15 // maximum lines to scan
	f, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)

	lines := 0
	for scan.Scan() && !(lines > maxlines) {
		if strings.Contains(scan.Text(), "/docker/containers") {
			return true, nil
		}
		lines++
	}
	if err := scan.Err(); err != nil {
		return false, err
	}

	return false, nil
}

func isInContainerCGroup(cgroupPath string) (bool, error) {
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
