//go:build aix
// +build aix

// Copyright 2015 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"
)

const (
	maxPathSize = 32 * 1024
	version     = "aix-ssrc"
)

type aixSystem struct{}

func (aixSystem) String() string {
	return version
}

func (aixSystem) Detect() bool {
	return true
}

func (aixSystem) Interactive() bool {
	return interactive
}

func (aixSystem) New(i Interface, c *Config) (Service, error) {
	return &aixService{
		i:      i,
		Config: c,
	}, nil
}

// Retrieve process arguments from a PID.
func getArgsFromPid(pid int) string {
	cmd := exec.Command("ps", "-o", "args", "-p", strconv.Itoa(pid))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		lines := strings.Split(out.String(), "\n")
		if len(lines) > 1 {
			return strings.TrimSpace(lines[1])
		}
	}
	return ""
}

var interactive = false

func init() {
	ChooseSystem(aixSystem{})

	var err error
	interactive, err = isInteractive()
	if err != nil {
		panic(fmt.Sprintf("Failed to determine if interactive: %v", err))
	}
}

// Check if the process is running interactively.
func isInteractive() (bool, error) {
	parentArgs := getArgsFromPid(os.Getppid())
	return parentArgs != "/usr/sbin/srcmstr", nil
}

type aixService struct {
	i Interface
	*Config
}

func (s *aixService) String() string {
	if len(s.DisplayName) > 0 {
		return s.DisplayName
	}
	return s.Name
}

func (s *aixService) Platform() string {
	return version
}

func (s *aixService) template() *template.Template {
	functions := template.FuncMap{
		"bool": func(v bool) string {
			if v {
				return "true"
			}
			return "false"
		},
	}

	customConfig := s.Option.string(optionSysvScript, "")
	if customConfig != "" {
		return template.Must(template.New("").Funcs(functions).Parse(customConfig))
	}
	return template.Must(template.New("").Funcs(functions).Parse(svcConfig))
}

func (s *aixService) configPath() (string, error) {
	return "/etc/rc.d/init.d/" + s.Config.Name, nil
}

func (s *aixService) Install() error {
	// Install service
	path, err := s.execPath()
	if err != nil {
		return err
	}
	if len(s.Config.Arguments) > 0 {
		err = run("mkssys", "-s", s.Name, "-p", path, "-a", strings.Join(s.Config.Arguments, " "), "-u", "0", "-R", "-Q", "-S", "-n", "15", "-f", "9", "-d", "-w", "30")
	} else {
		err = run("mkssys", "-s", s.Name, "-p", path, "-u", "0", "-R", "-Q", "-S", "-n", "15", "-f", "9", "-d", "-w", "30")
	}
	if err != nil {
		return err
	}

	// Write start script
	confPath, err := s.configPath()
	if err != nil {
		return err
	}
	if _, err = os.Stat(confPath); err == nil {
		return fmt.Errorf("Init already exists: %s", confPath)
	}

	f, err := os.Create(confPath)
	if err != nil {
		return err
	}
	defer f.Close()

	to := struct {
		*Config
		Path string
	}{
		Config: s.Config,
		Path:   path,
	}

	if err = s.template().Execute(f, &to); err != nil {
		return err
	}

	if err = os.Chmod(confPath, 0755); err != nil {
		return err
	}

	rcd := "/etc/rc"
	if _, err = os.Stat("/etc/rc.d/rc2.d"); err == nil {
		rcd = "/etc/rc.d/rc"
	}

	for _, i := range [...]string{"2", "3"} {
		if err = os.Symlink(confPath, fmt.Sprintf("%s%s.d/S50%s", rcd, i, s.Name)); err != nil {
			continue
		}
		if err = os.Symlink(confPath, fmt.Sprintf("%s%s.d/K02%s", rcd, i, s.Name)); err != nil {
			continue
		}
	}

	return nil
}

func (s *aixService) Uninstall() error {
	if err := s.Stop(); err != nil {
		return err
	}

	if err := run("rmssys", "-s", s.Name); err != nil {
		return err
	}

	confPath, err := s.configPath()
	if err != nil {
		return err
	}
	return os.Remove(confPath)
}

func (s *aixService) Status() (Status, error) {
	exitCode, out, err := runWithOutput("lssrc", "-s", s.Name)
	if exitCode == 0 && err != nil {
		if !strings.Contains(err.Error(), "failed with stderr") {
			return StatusUnknown, err
		}
	}

	re := regexp.MustCompile(`\s+` + regexp.QuoteMeta(s.Name) + `\s+(\w+\s+)?(\d+\s+)?(\w+)`)
	matches := re.FindStringSubmatch(out)
	if len(matches) == 4 {
		switch matches[3] {
		case "inoperative":
			return StatusStopped, nil
		case "active":
			return StatusRunning, nil
		default:
			fmt.Printf("Got unknown service status %s\n", matches[3])
			return StatusUnknown, errors.New("unknown status")
		}
	}

	confPath, err := s.configPath()
	if err != nil {
		return StatusUnknown, err
	}

	if _, err = os.Stat(confPath); err == nil {
		return StatusStopped, nil
	}

	return StatusUnknown, ErrNotInstalled
}

func (s *aixService) Start() error {
	return run("startsrc", "-s", s.Name)
}

func (s *aixService) Stop() error {
	return run("stopsrc", "-s", s.Name)
}

func (s *aixService) Restart() error {
	if err := s.Stop(); err != nil {
		return err
	}
	time.Sleep(50 * time.Millisecond)
	return s.Start()
}

func (s *aixService) Run() error {
	if err := s.i.Start(s); err != nil {
		return err
	}

	s.Option.funcSingle(optionRunWait, func() {
		sigChan := make(chan os.Signal, 3)
		signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
		<-sigChan
	})()

	return s.i.Stop(s)
}

func (s *aixService) Logger(errs chan<- error) (Logger, error) {
	if interactive {
		return ConsoleLogger, nil
	}
	return s.SystemLogger(errs)
}

func (s *aixService) SystemLogger(errs chan<- error) (Logger, error) {
	return newSysLogger(s.Name, errs)
}

var svcConfig = `#!/bin/ksh
case "$1" in
start)
        startsrc -s {{.Name}}
        ;;
stop)
        stopsrc -s {{.Name}}
        ;;
*)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac
`
