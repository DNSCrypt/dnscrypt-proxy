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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

func isSystemd() bool {
	if _, err := exec.LookPath("rpm-ostree"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return true
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	if _, err := os.Stat("/proc/1/comm"); err == nil {
		filerc, err := os.Open("/proc/1/comm")
		if err != nil {
			return false
		}
		defer filerc.Close()

		buf := new(bytes.Buffer)
		buf.ReadFrom(filerc)
		contents := buf.String()

		if strings.Trim(contents, " \r\n") == "systemd" {
			return true
		}
	}
	return false
}

type systemd struct {
	i        Interface
	platform string
	*Config
}

func newSystemdService(i Interface, platform string, c *Config) (Service, error) {
	s := &systemd{
		i:        i,
		platform: platform,
		Config:   c,
	}

	return s, nil
}

func (s *systemd) String() string {
	if len(s.DisplayName) > 0 {
		return s.DisplayName
	}
	return s.Name
}

func (s *systemd) Platform() string {
	return s.platform
}

func (s *systemd) configPath() (cp string, err error) {
	if !s.isUserService() {
		cp = "/etc/systemd/system/" + s.unitName()
		return
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	systemdUserDir := filepath.Join(homeDir, ".config/systemd/user")
	err = os.MkdirAll(systemdUserDir, os.ModePerm)
	if err != nil {
		return
	}
	cp = filepath.Join(systemdUserDir, s.unitName())
	return
}

func (s *systemd) unitName() string {
	return s.Config.Name + ".service"
}

func (s *systemd) getSystemdVersion() int64 {
	_, out, err := s.runWithOutput("systemctl", "--version")
	if err != nil {
		return -1
	}

	re := regexp.MustCompile(`systemd ([0-9]+)`)
	matches := re.FindStringSubmatch(out)
	if len(matches) != 2 {
		return -1
	}

	v, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return -1
	}

	return v
}

func (s *systemd) hasOutputFileSupport() bool {
	defaultValue := true
	version := s.getSystemdVersion()
	if version == -1 {
		return defaultValue
	}

	if version < 236 {
		return false
	}

	return defaultValue
}

// systemdTemplate is the built-in template, parsed once at init and reused for
// every install. A custom SystemdScript is parsed per install instead.
var systemdTemplate = mustParse(systemdScript)

func (s *systemd) template() (*tmpl, error) {
	if custom := s.Option.string(optionSystemdScript, ""); custom != "" {
		return parseTemplate(custom)
	}
	return systemdTemplate, nil
}

func (s *systemd) isUserService() bool {
	return s.Option.bool(optionUserService, optionUserServiceDefault)
}

func (s *systemd) Install() error {
	confPath, err := s.configPath()
	if err != nil {
		return err
	}
	_, err = os.Stat(confPath)
	if err == nil {
		return fmt.Errorf("Init already exists: %s", confPath)
	}

	f, err := os.OpenFile(confPath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	path, err := s.execPath()
	if err != nil {
		return err
	}

	c := s.Config

	// Conditions that the mini engine cannot express (and/gt on non-string
	// values) are collapsed here to a present-or-empty string, so the template
	// only needs {{if Key}} truthiness. Everything else is passed through as a
	// string or a []string for {{range}}.
	outputFileSupport := ""
	if s.Option.bool(optionLogOutput, optionLogOutputDefault) && s.hasOutputFileSupport() {
		outputFileSupport = "yes"
	}

	limitNOFILE := ""
	if n := s.Option.int(optionLimitNOFILE, optionLimitNOFILEDefault); n > -1 {
		limitNOFILE = strconv.Itoa(n)
	}

	data := map[string]any{
		"Description":       c.Description,
		"Path":              path,
		"Name":              c.Name,
		"Dependencies":      c.Dependencies,
		"Arguments":         c.Arguments,
		"ChRoot":            c.ChRoot,
		"WorkingDirectory":  c.WorkingDirectory,
		"UserName":          c.UserName,
		"ReloadSignal":      s.Option.string(optionReloadSignal, ""),
		"PIDFile":           s.Option.string(optionPIDFile, ""),
		"LogDirectory":      s.Option.string(optionLogDirectory, defaultLogDirectory),
		"OutputFileSupport": outputFileSupport,
		"LimitNOFILE":       limitNOFILE,
		"Restart":           s.Option.string(optionRestart, "always"),
		"SuccessExitStatus": s.Option.string(optionSuccessExitStatus, ""),
		"EnvVars":           envVars(c.EnvVars, func(k, v string) string { return "Environment=" + k + "=" + v }),
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

	err = s.runAction("enable")
	if err != nil {
		return err
	}

	return s.run("daemon-reload")
}

func (s *systemd) Uninstall() error {
	err := s.runAction("disable")
	if err != nil {
		return err
	}
	cp, err := s.configPath()
	if err != nil {
		return err
	}
	if err := os.Remove(cp); err != nil {
		return err
	}
	return s.run("daemon-reload")
}

func (s *systemd) Logger(errs chan<- error) (Logger, error) {
	if system.Interactive() {
		return ConsoleLogger, nil
	}
	return s.SystemLogger(errs)
}
func (s *systemd) SystemLogger(errs chan<- error) (Logger, error) {
	return newSysLogger(s.Name, errs)
}

func (s *systemd) Run() (err error) {
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

func (s *systemd) Status() (Status, error) {
	exitCode, out, err := s.runWithOutput("systemctl", "is-active", s.unitName())
	if exitCode == 0 && err != nil {
		return StatusUnknown, err
	}

	switch {
	case strings.HasPrefix(out, "active"):
		return StatusRunning, nil
	case strings.HasPrefix(out, "inactive"):
		// inactive can also mean its not installed, check unit files
		exitCode, out, err := s.runWithOutput("systemctl", "list-unit-files", "-t", "service", s.unitName())
		if exitCode == 0 && err != nil {
			return StatusUnknown, err
		}
		if strings.Contains(out, s.Name) {
			// unit file exists, installed but not running
			return StatusStopped, nil
		}
		// no unit file
		return StatusUnknown, ErrNotInstalled
	case strings.HasPrefix(out, "activating"):
		return StatusRunning, nil
	case strings.HasPrefix(out, "failed"):
		return StatusUnknown, errors.New("service in failed state")
	default:
		return StatusUnknown, ErrNotInstalled
	}
}

func (s *systemd) Start() error {
	return s.runAction("start")
}

func (s *systemd) Stop() error {
	return s.runAction("stop")
}

func (s *systemd) Restart() error {
	return s.runAction("restart")
}

func (s *systemd) runWithOutput(command string, arguments ...string) (int, string, error) {
	if s.isUserService() {
		arguments = append(arguments, "--user")
	}
	return runWithOutput(command, arguments...)
}

func (s *systemd) run(action string, args ...string) error {
	if s.isUserService() {
		return run("systemctl", append([]string{action, "--user"}, args...)...)
	}
	return run("systemctl", append([]string{action}, args...)...)
}

func (s *systemd) runAction(action string) error {
	return s.run(action, s.unitName())
}

// systemdScript is expanded by the mini template engine (renderTemplate).
// {{if}}/{{range}} operate on plain string / []string values built in Install;
// compound conditions such as "and .LogOutput .HasOutputFileSupport" or
// "gt .LimitNOFILE -1" are precomputed there into a present-or-empty string.
const systemdScript = `[Unit]
Description={{Description}}
ConditionFileIsExecutable={{Path | cmdEscape}}
{{range Dependencies}}{{.}}
{{end}}
[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart={{Path | cmdEscape}}{{range Arguments}} {{. | cmd}}{{end}}
{{if ChRoot}}RootDirectory={{ChRoot | cmd}}
{{end}}{{if WorkingDirectory}}WorkingDirectory={{WorkingDirectory | cmdEscape}}
{{end}}{{if UserName}}User={{UserName}}
{{end}}{{if ReloadSignal}}ExecReload=/bin/kill -{{ReloadSignal}} "$MAINPID"
{{end}}{{if PIDFile}}PIDFile={{PIDFile | cmd}}
{{end}}{{if OutputFileSupport}}StandardOutput=file:{{LogDirectory}}/{{Name}}.out
StandardError=file:{{LogDirectory}}/{{Name}}.err
{{end}}{{if LimitNOFILE}}LimitNOFILE={{LimitNOFILE}}
{{end}}{{if Restart}}Restart={{Restart}}
{{end}}{{if SuccessExitStatus}}SuccessExitStatus={{SuccessExitStatus}}
{{end}}RestartSec=120
EnvironmentFile=-/etc/sysconfig/{{Name}}

{{range EnvVars}}{{.}}
{{end}}[Install]
WantedBy=multi-user.target
`
