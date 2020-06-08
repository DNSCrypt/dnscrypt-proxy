// Copyright 2015 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package service

import (
	"bytes"
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

const maxPathSize = 32 * 1024

const version = "aix-ssrc"

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
	s := &aixService{
		i:      i,
		Config: c,
	}

	return s, nil
}

func getPidOfSvcMaster() int {
	pat := regexp.MustCompile(`\s+root\s+(\d+)\s+\d+\s+\d+\s+\w+\s+\d+\s+\S+\s+[0-9:]+\s+/usr/sbin/srcmstr`)
	cmd := exec.Command("ps", "-ef")
	var out bytes.Buffer
	cmd.Stdout = &out
	pid := 0
	if err := cmd.Run(); err == nil {
		matches := pat.FindAllStringSubmatch(out.String(),-1)
		for _, match := range matches {
			pid, _ = strconv.Atoi(match[1])
			break
		}
	}
	return pid
}

func init() {
	ChooseSystem(aixSystem{})
}

var interactive = false

func init() {
	var err error
	interactive, err = isInteractive()
	if err != nil {
		panic(err)
	}
}

func isInteractive() (bool, error) {
	// The PPid of a service process should match PID of srcmstr.
	return os.Getppid() != getPidOfSvcMaster(), nil
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
	} else {
		return template.Must(template.New("").Funcs(functions).Parse(svcConfig))
	}
}

func (s *aixService) configPath() (cp string, err error) {
	cp = "/etc/rc.d/init.d/" + s.Config.Name
	return
}

func (s *aixService) Install() error {
	// install service
	path, err := s.execPath()
	if err != nil {
		return err
	}
	err = run("mkssys", "-s", s.Name, "-p", path, "-u", "0", "-R", "-Q", "-S", "-n", "15", "-f", "9", "-d", "-w", "30" )
	if err != nil {
		return err
	}

	// write start script
	confPath, err := s.configPath()
	if err != nil {
		return err
	}
	_, err = os.Stat(confPath)
	if err == nil {
		return fmt.Errorf("Init already exists: %s", confPath)
	}

	f, err := os.Create(confPath)
	if err != nil {
		return err
	}
	defer f.Close()

	var to = &struct {
		*Config
		Path string
	}{
		s.Config,
		path,
	}

	err = s.template().Execute(f, to)
	if err != nil {
		return err
	}

	if err = os.Chmod(confPath, 0755); err != nil {
		return err
	}
	for _, i := range [...]string{"2", "3"} {
		if err = os.Symlink(confPath, "/etc/rc"+i+".d/S50"+s.Name); err != nil {
			continue
		}
		if err = os.Symlink(confPath, "/etc/rc"+i+".d/K02"+s.Name); err != nil {
			continue
		}
	}

	return nil
}

func (s *aixService) Uninstall() error {
	s.Stop()

	err := run("rmssys", "-s", s.Name)
	if err != nil {
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

	re := regexp.MustCompile(`\s+` + s.Name + `\s+(\w+\s+)?(\d+\s+)?(\w+)`)
	matches := re.FindStringSubmatch(out)
	if len(matches) == 4 {
		status := string(matches[3])
		if status == "inoperative" {
			return StatusStopped, nil
		} else if status == "active" {
			return StatusRunning, nil
		} else {
			fmt.Printf("Got unknown service status %s\n", status)
			return StatusUnknown, err
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
	err := s.Stop()
	if err != nil {
		return err
	}
	time.Sleep(50 * time.Millisecond)
	return s.Start()
}

func (s *aixService) Run() error {
	var err error

	err = s.i.Start(s)
	if err != nil {
		return err
	}

	s.Option.funcSingle(optionRunWait, func() {
		var sigChan = make(chan os.Signal, 3)
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
start )
        startsrc -s {{.Name}}
        ;;
stop )
        stopsrc -s {{.Name}}
        ;;
* )
        echo "Usage: $0 (start | stop)"
        exit 1
esac
`
