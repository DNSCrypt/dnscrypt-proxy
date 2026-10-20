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
	"strings"
	"syscall"
	"time"
)

type rcs struct {
	i        Interface
	platform string
	*Config
}

func isRCS() bool {
	if _, err := os.Stat("/etc/init.d/rcS"); err != nil {
		return false
	}
	if _, err := exec.LookPath("service"); err == nil {
		return false
	}
	if _, err := os.Stat("/etc/inittab"); err == nil {
		filerc, err := os.Open("/etc/inittab")
		if err != nil {
			return false
		}
		defer filerc.Close()

		buf := new(bytes.Buffer)
		buf.ReadFrom(filerc)
		contents := buf.String()

		re := regexp.MustCompile(`::sysinit:.*rcS`)
		matches := re.FindStringSubmatch(contents)
		if len(matches) > 0 {
			return true
		}
		return false
	}
	return false
}

func newRCSService(i Interface, platform string, c *Config) (Service, error) {
	s := &rcs{
		i:        i,
		platform: platform,
		Config:   c,
	}

	return s, nil
}

func (s *rcs) String() string {
	if len(s.DisplayName) > 0 {
		return s.DisplayName
	}
	return s.Name
}

func (s *rcs) Platform() string {
	return s.platform
}

// todo
var errNoUserServiceRCS = errors.New("User services are not supported on rcS.")

func (s *rcs) configPath() (cp string, err error) {
	if s.Option.bool(optionUserService, optionUserServiceDefault) {
		err = errNoUserServiceRCS
		return
	}
	cp = "/etc/init.d/" + s.Config.Name
	return
}

var rcsTemplate = mustParse(rcsScript)

func (s *rcs) template() (*tmpl, error) {
	if custom := s.Option.string(optionRCSScript, ""); custom != "" {
		return parseTemplate(custom)
	}
	return rcsTemplate, nil
}

func (s *rcs) Install() error {
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

	path, err := s.execPath()
	if err != nil {
		return err
	}

	c := s.Config
	data := map[string]any{
		"Description":      c.Description,
		"DisplayName":      c.DisplayName,
		"Name":             c.Name,
		"Path":             path,
		"Arguments":        c.Arguments,
		"WorkingDirectory": c.WorkingDirectory,
		"LogDirectory":     s.Option.string(optionLogDirectory, defaultLogDirectory),
	}

	t, err := s.template()
	if err != nil {
		return err
	}
	out, err := t.render(data, tfs)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(out); err != nil {
		return err
	}

	if err = os.Chmod(confPath, 0755); err != nil {
		return err
	}

	if err = os.Symlink(confPath, "/etc/rc.d/S50"+s.Name); err != nil {
		return err
	}

	return nil
}

func (s *rcs) Uninstall() error {
	cp, err := s.configPath()
	if err != nil {
		return err
	}
	if err := os.Remove(cp); err != nil {
		return err
	}
	if err := os.Remove("/etc/rc.d/S50" + s.Name); err != nil {
		return err
	}
	return nil
}

func (s *rcs) Logger(errs chan<- error) (Logger, error) {
	if system.Interactive() {
		return ConsoleLogger, nil
	}
	return s.SystemLogger(errs)
}
func (s *rcs) SystemLogger(errs chan<- error) (Logger, error) {
	return newSysLogger(s.Name, errs)
}

func (s *rcs) Run() (err error) {
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

func (s *rcs) Status() (Status, error) {
	_, out, err := runWithOutput("/etc/init.d/"+s.Name, "status")
	if err != nil {
		return StatusUnknown, err
	}

	switch {
	case strings.HasPrefix(out, "Running"):
		return StatusRunning, nil
	case strings.HasPrefix(out, "Stopped"):
		return StatusStopped, nil
	default:
		return StatusUnknown, ErrNotInstalled
	}
}

func (s *rcs) Start() error {
	return run("/etc/init.d/"+s.Name, "start")
}

func (s *rcs) Stop() error {
	return run("/etc/init.d/"+s.Name, "stop")
}

func (s *rcs) Restart() error {
	err := s.Stop()
	if err != nil {
		return err
	}
	time.Sleep(50 * time.Millisecond)
	return s.Start()
}

const rcsScript = `#!/bin/sh
# For RedHat and cousins:
# chkconfig: - 99 01
# description: {{Description}}
# processname: {{Path}}

### BEGIN INIT INFO
# Provides:          {{Path}}
# Required-Start:
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: {{DisplayName}}
# Description:       {{Description}}
### END INIT INFO

cmd="{{Path}}{{range Arguments}} {{. | cmd}}{{end}}"

name={{Name}}
pid_file="/var/run/$name.pid"
stdout_log="{{LogDirectory}}/$name.log"
stderr_log="{{LogDirectory}}/$name.err"

[ -e /etc/sysconfig/$name ] && . /etc/sysconfig/$name

get_pid() {
    cat "$pid_file"
}

is_running() {
    [ -f "$pid_file" ] && cat /proc/$(get_pid)/stat > /dev/null 2>&1
}

case "$1" in
    start)
        if is_running; then
            echo "Already started"
        else
            echo "Starting $name"
            {{if WorkingDirectory}}cd '{{WorkingDirectory}}'{{end}}
            $cmd >> "$stdout_log" 2>> "$stderr_log" &
            echo $! > "$pid_file"
            if ! is_running; then
                echo "Unable to start, see $stdout_log and $stderr_log"
                exit 1
            fi
        fi
    ;;
    stop)
        if is_running; then
            echo -n "Stopping $name.."
            kill $(get_pid)
            for i in $(seq 1 10)
            do
                if ! is_running; then
                    break
                fi
                echo -n "."
                sleep 1
            done
            echo
            if is_running; then
                echo "Not stopped; may still be shutting down or shutdown may have failed"
                exit 1
            else
                echo "Stopped"
                if [ -f "$pid_file" ]; then
                    rm "$pid_file"
                fi
            fi
        else
            echo "Not running"
        fi
    ;;
    restart)
        $0 stop
        if is_running; then
            echo "Unable to stop, will not attempt to start"
            exit 1
        fi
        $0 start
    ;;
    status)
        if is_running; then
            echo "Running"
        else
            echo "Stopped"
            exit 1
        fi
    ;;
    *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 1
    ;;
esac
exit 0
`
