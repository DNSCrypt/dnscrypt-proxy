// Copyright 2019 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package service

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

const version = "freebsd"
const configDir = "/usr/local/etc/rc.d"

type freebsdSystem struct{}

func (freebsdSystem) String() string {
	return version
}
func (freebsdSystem) Detect() bool {
	return true
}
func (freebsdSystem) Interactive() bool {
	return interactive
}
func (freebsdSystem) New(i Interface, c *Config) (Service, error) {
	s := &freebsdService{
		i:      i,
		Config: c,
	}

	return s, nil
}

func init() {
	ChooseSystem(freebsdSystem{})
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
	return os.Getenv("IS_DAEMON") != "1", nil
}

type freebsdService struct {
	i Interface
	*Config
}

func (s *freebsdService) String() string {
	if len(s.DisplayName) > 0 {
		return s.DisplayName
	}
	return s.Name
}

func (s *freebsdService) Platform() string {
	return version
}

var rcTemplate = mustParse(rcScript)

func (s *freebsdService) template() (*tmpl, error) {
	if custom := s.Option.string(optionSysvScript, ""); custom != "" {
		return parseTemplate(custom)
	}
	return rcTemplate, nil
}

func (s *freebsdService) configPath() (cp string, err error) {
	if oserr := os.MkdirAll(configDir, 0755); oserr != nil {
		err = oserr
		return
	}
	cp = filepath.Join(configDir, s.Config.Name)
	return
}

func (s *freebsdService) Install() error {
	path, err := s.execPath()
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

	c := s.Config
	data := map[string]any{
		"Name":             c.Name,
		"Path":             path,
		"Arguments":        c.Arguments,
		"WorkingDirectory": c.WorkingDirectory,
	}

	t, err := s.template()
	if err != nil {
		return err
	}
	out, err := t.render(data, nil)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(out); err != nil {
		return err
	}

	if err = os.Chmod(confPath, 0755); err != nil {
		return err
	}

	return nil
}

func (s *freebsdService) Uninstall() error {
	cp, err := s.configPath()
	if err != nil {
		return err
	}
	return os.Remove(cp)
}

func (s *freebsdService) Status() (Status, error) {
	cp, err := s.configPath()
	if err != nil {
		return StatusUnknown, err
	}

	if _, err = os.Stat(cp); os.IsNotExist(err) {
		return StatusStopped, ErrNotInstalled
	}

	status, _, err := runCommand("service", false, s.Name, "status")
	if status == 1 {
		return StatusStopped, nil
	} else if err != nil {
		return StatusUnknown, err
	}
	return StatusRunning, nil
}

func (s *freebsdService) Start() error {
	return run("service", s.Name, "start")
}

func (s *freebsdService) Stop() error {
	return run("service", s.Name, "stop")
}

func (s *freebsdService) Restart() error {
	return run("service", s.Name, "restart")
}

func (s *freebsdService) Run() error {
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

func (s *freebsdService) Logger(errs chan<- error) (Logger, error) {
	if interactive {
		return ConsoleLogger, nil
	}
	return s.SystemLogger(errs)
}

func (s *freebsdService) SystemLogger(errs chan<- error) (Logger, error) {
	return newSysLogger(s.Name, errs)
}

const rcScript = `#!/bin/sh

# PROVIDE: {{Name}}
# REQUIRE: SERVERS
# KEYWORD: shutdown

. /etc/rc.subr

name="{{Name}}"
{{Name}}_env="IS_DAEMON=1"
pidfile="/var/run/${name}.pid"
command="/usr/sbin/daemon"
daemon_args="-P ${pidfile} -r -t \"${name}: daemon\"{{if WorkingDirectory}} -c {{WorkingDirectory}}{{end}}"
command_args="${daemon_args} {{Path}}{{range Arguments}} {{.}}{{end}}"

run_rc_command "$1"
`
