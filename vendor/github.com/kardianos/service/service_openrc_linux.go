package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"syscall"
	"time"
)

func isOpenRC() bool {
	if _, err := exec.LookPath("openrc-init"); err == nil {
		return true
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

		re := regexp.MustCompile(`::sysinit:.*openrc.*sysinit`)
		matches := re.FindStringSubmatch(contents)
		if len(matches) > 0 {
			return true
		}
		return false
	}
	return false
}

type openrc struct {
	i        Interface
	platform string
	*Config
}

func (s *openrc) String() string {
	if len(s.DisplayName) > 0 {
		return s.DisplayName
	}
	return s.Name
}

func (s *openrc) Platform() string {
	return s.platform
}

var openRCTemplate = mustParse(openRCScript)

func (s *openrc) template() (*tmpl, error) {
	if custom := s.Option.string(optionOpenRCScript, ""); custom != "" {
		return parseTemplate(custom)
	}
	return openRCTemplate, nil
}

func newOpenRCService(i Interface, platform string, c *Config) (Service, error) {
	s := &openrc{
		i:        i,
		platform: platform,
		Config:   c,
	}
	return s, nil
}

var errNoUserServiceOpenRC = errors.New("user services are not supported on OpenRC")

func (s *openrc) configPath() (cp string, err error) {
	if s.Option.bool(optionUserService, optionUserServiceDefault) {
		err = errNoUserServiceOpenRC
		return
	}
	cp = "/etc/init.d/" + s.Config.Name
	return
}

func (s *openrc) Install() error {
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

	err = os.Chmod(confPath, 0755)
	if err != nil {
		return err
	}

	path, err := s.execPath()
	if err != nil {
		return err
	}

	c := s.Config

	// depend() lists each dependency on its own tab-indented line; bake the
	// tab in here so the template is a plain {{range}}.
	deps := make([]string, len(c.Dependencies))
	for i, d := range c.Dependencies {
		deps[i] = "\t" + d
	}

	data := map[string]any{
		"DisplayName":  c.DisplayName,
		"Description":  c.Description,
		"Path":         path,
		"Arguments":    c.Arguments,
		"Dependencies": deps,
		"LogDirectory": s.Option.string(optionLogDirectory, defaultLogDirectory),
		"EnvVars":      envVars(c.EnvVars, func(k, v string) string { return "export " + k + "=" + v }),
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
	// run rc-update
	return s.runAction("add")
}

func (s *openrc) Uninstall() error {
	confPath, err := s.configPath()
	if err != nil {
		return err
	}
	if err := os.Remove(confPath); err != nil {
		return err
	}
	return s.runAction("delete")
}

func (s *openrc) Logger(errs chan<- error) (Logger, error) {
	if system.Interactive() {
		return ConsoleLogger, nil
	}
	return s.SystemLogger(errs)
}

func (s *openrc) SystemLogger(errs chan<- error) (Logger, error) {
	return newSysLogger(s.Name, errs)
}

func (s *openrc) Run() (err error) {
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

func (s *openrc) Status() (Status, error) {
	// rc-service uses the errno library for its exit codes:
	// errno 0 = service started
	// errno 1 = EPERM 1 Operation not permitted
	// errno 2 = ENOENT 2 No such file or directory
	// errno 3 = ESRCH 3 No such process
	// for more info, see https://man7.org/linux/man-pages/man3/errno.3.html
	_, out, err := runWithOutput("rc-service", s.Name, "status")
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0
			exitCode := exiterr.ExitCode()
			switch {
			case exitCode == 1:
				return StatusUnknown, err
			case exitCode == 2:
				return StatusUnknown, ErrNotInstalled
			case exitCode == 3:
				return StatusStopped, nil
			default:
				return StatusUnknown, fmt.Errorf("unknown error: %v - %v", out, err)
			}
		} else {
			return StatusUnknown, err
		}
	}
	return StatusRunning, nil
}

func (s *openrc) Start() error {
	return run("rc-service", s.Name, "start")
}

func (s *openrc) Stop() error {
	return run("rc-service", s.Name, "stop")
}

func (s *openrc) Restart() error {
	err := s.Stop()
	if err != nil {
		return err
	}
	time.Sleep(50 * time.Millisecond)
	return s.Start()
}

func (s *openrc) runAction(action string) error {
	return s.run(action, s.Name)
}

func (s *openrc) run(action string, args ...string) error {
	return run("rc-update", append([]string{action}, args...)...)
}

const openRCScript = `#!/sbin/openrc-run
supervisor=supervise-daemon
name="{{DisplayName}}"
description="{{Description}}"
command={{Path | cmdEscape}}
{{if Arguments}}command_args="{{range Arguments}}{{.}} {{end}}"
{{end}}name=$(basename $(readlink -f $command))
supervise_daemon_args="--stdout {{LogDirectory}}/${name}.log --stderr {{LogDirectory}}/${name}.err"

{{range EnvVars}}{{.}}
{{end}}
{{if Dependencies}}depend() {
{{range Dependencies}}{{.}}
{{end}}}
{{end}}`
