// Copyright 2015 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"
)

func isProcd() bool {
	if _, err := exec.LookPath("procd"); err == nil {
		return true
	}
	return false
}

type procd struct {
	*sysv
	scriptPath string
}

func newProcdService(i Interface, platform string, c *Config) (Service, error) {
	sv := &sysv{
		i:        i,
		platform: platform,
		Config:   c,
	}

	p := &procd{
		sysv:       sv,
		scriptPath: "/etc/init.d/" + sv.Name,
	}
	return p, nil
}

func (p *procd) template() *template.Template {
	customScript := p.Option.string(optionSysvScript, "")

	if customScript != "" {
		return template.Must(template.New("").Funcs(tf).Parse(customScript))
	}
	return template.Must(template.New("").Funcs(tf).Parse(procdScript))
}

func (p *procd) Install() error {
	confPath, err := p.configPath()
	if err != nil {
		return err
	}
	_, err = os.Stat(confPath)
	if err == nil {
		return fmt.Errorf("init already exists: %q", confPath)
	}

	f, err := os.Create(confPath)
	if err != nil {
		return err
	}
	defer f.Close()

	path, err := p.execPath()
	if err != nil {
		return err
	}

	var to = &struct {
		*Config
		Path         string
		LogDirectory string
	}{
		p.Config,
		path,
		p.Option.string(optionLogDirectory, defaultLogDirectory),
	}

	err = p.template().Execute(f, to)
	if err != nil {
		return err
	}

	if err = os.Chmod(confPath, 0755); err != nil {
		return err
	}

	if err = os.Symlink(confPath, "/etc/rc.d/S50"+p.Name); err != nil {
		return err
	}
	if err = os.Symlink(confPath, "/etc/rc.d/K02"+p.Name); err != nil {
		return err
	}

	return nil
}

func (p *procd) Uninstall() error {
	if err := run(p.scriptPath, "disable"); err != nil {
		return err
	}
	cp, err := p.configPath()
	if err != nil {
		return err
	}
	if err := os.Remove(cp); err != nil {
		return err
	}
	return nil
}

func (p *procd) Status() (Status, error) {
	_, out, err := runWithOutput(p.scriptPath, "status")
	if err != nil && !(err.Error() == "exit status 3") {
		return StatusUnknown, err
	}

	switch {
	case strings.HasPrefix(out, "running"):
		return StatusRunning, nil
	case strings.HasPrefix(out, "inactive"):
		return StatusStopped, nil
	default:
		return StatusUnknown, ErrNotInstalled
	}
}

func (p *procd) Start() error {
	return run(p.scriptPath, "start")
}

func (p *procd) Stop() error {
	return run(p.scriptPath, "stop")
}

func (p *procd) Restart() error {
	err := p.Stop()
	if err != nil {
		return err
	}
	time.Sleep(50 * time.Millisecond)
	return p.Start()
}

const procdScript = `#!/bin/sh /etc/rc.common
USE_PROCD=1
# After network starts
START=21
# Before network stops
STOP=89
cmd="{{.Path}}{{range .Arguments}} {{.|cmd}}{{end}}"
name="{{.Name}}"
pid_file="/var/run/${name}.pid"

start_service() {
    echo "Starting ${name}"
    procd_open_instance
    procd_set_param command ${cmd}

    # respawn automatically if something died, be careful if you have an alternative process supervisor
    # if process exits sooner than respawn_threshold, it is considered crashed and after 5 retries the service is stopped
    # if process finishes later than respawn_threshold, it is restarted unconditionally, regardless of error code
    # notice that this is literal respawning of the process, no in a respawn-on-failure sense
    procd_set_param respawn ${respawn_threshold:-3600} ${respawn_timeout:-5} ${respawn_retry:-5}

    procd_set_param stdout 1             # forward stdout of the command to logd
    procd_set_param stderr 1             # same for stderr
    procd_set_param pidfile ${pid_file}  # write a pid file on instance start and remove it on stop
    procd_close_instance
    echo "${name} has been started"
}
`
