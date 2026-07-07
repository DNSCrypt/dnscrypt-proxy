// Copyright 2015 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package service

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const maxPathSize = 32 * 1024

const (
	version                   = "darwin-launchd"
	defaultDarwinLogDirectory = "/var/log"
)

type darwinSystem struct{}

func (darwinSystem) String() string {
	return version
}

func (darwinSystem) Detect() bool {
	return true
}

func (darwinSystem) Interactive() bool {
	return interactive
}

func (darwinSystem) New(i Interface, c *Config) (Service, error) {
	s := &darwinLaunchdService{
		i:      i,
		Config: c,

		userService: c.Option.bool(optionUserService, optionUserServiceDefault),
	}

	return s, nil
}

func init() {
	ChooseSystem(darwinSystem{})
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
	// TODO: The PPID of Launchd is 1. The PPid of a service process should match launchd's PID.
	return os.Getppid() != 1, nil
}

type darwinLaunchdService struct {
	i Interface
	*Config

	userService bool
}

func (s *darwinLaunchdService) String() string {
	if len(s.DisplayName) > 0 {
		return s.DisplayName
	}
	return s.Name
}

func (s *darwinLaunchdService) Platform() string {
	return version
}

func (s *darwinLaunchdService) getHomeDir() (string, error) {
	u, err := user.Current()
	if err == nil {
		return u.HomeDir, nil
	}

	// alternate methods
	homeDir := os.Getenv("HOME") // *nix
	if homeDir == "" {
		return "", errors.New("User home directory not found.")
	}
	return homeDir, nil
}

func (s *darwinLaunchdService) getServiceFilePath() (string, error) {
	if s.userService {
		homeDir, err := s.getHomeDir()
		if err != nil {
			return "", err
		}
		return homeDir + "/Library/LaunchAgents/" + s.Name + ".plist", nil
	}
	return "/Library/LaunchDaemons/" + s.Name + ".plist", nil
}

func (s *darwinLaunchdService) logDir() (string, error) {
	if customDir := s.Option.string(optionLogDirectory, ""); customDir != "" {
		return customDir, nil
	}
	if !s.userService {
		return defaultDarwinLogDirectory, nil
	}
	return s.getHomeDir()
}

func (s *darwinLaunchdService) getLogPaths() (string, string, error) {
	logDir, err := s.logDir()
	if err != nil {
		return "", "", err
	}
	return s.getLogPath(logDir, "out"), s.getLogPath(logDir, "err"), nil
}

func (s *darwinLaunchdService) getLogPath(logDir, logType string) string {
	return fmt.Sprintf("%s/%s.%s.log", logDir, s.Name, logType)
}

// plistEscaper matches text/template's html escaper, which the launchd plist
// was previously rendered with.
var plistEscaper = strings.NewReplacer(
	`&`, "&amp;",
	`'`, "&#39;",
	`<`, "&lt;",
	`>`, "&gt;",
	`"`, "&#34;",
)

// launchdFuncs is the pipeline function map for the launchd plist: html escapes
// a value for XML.
var launchdFuncs = map[string]tmplFunc{
	"html": func(s string) (string, error) { return plistEscaper.Replace(s), nil },
}

var launchdTemplate = mustParse(launchdConfig)

func (s *darwinLaunchdService) template() (*tmpl, error) {
	if custom := s.Option.string(optionLaunchdConfig, ""); custom != "" {
		return parseTemplate(custom)
	}
	return launchdTemplate, nil
}

// launchdBool renders a Go bool as the "true"/"false" element name used in the
// plist (previously the text/template "bool" function).
func launchdBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func (s *darwinLaunchdService) Install() error {
	confPath, err := s.getServiceFilePath()
	if err != nil {
		return err
	}
	_, err = os.Stat(confPath)
	if err == nil {
		return fmt.Errorf("Init already exists: %s", confPath)
	}

	if s.userService {
		// Ensure that ~/Library/LaunchAgents exists.
		err = os.MkdirAll(filepath.Dir(confPath), 0700)
		if err != nil {
			return err
		}
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

	stdOutPath, stdErrPath, _ := s.getLogPaths()

	c := s.Config
	data := map[string]any{
		"Name":              c.Name,
		"Path":              path,
		"Arguments":         c.Arguments,
		"ChRoot":            c.ChRoot,
		"UserName":          c.UserName,
		"WorkingDirectory":  c.WorkingDirectory,
		"KeepAlive":         launchdBool(s.Option.bool(optionKeepAlive, optionKeepAliveDefault)),
		"RunAtLoad":         launchdBool(s.Option.bool(optionRunAtLoad, optionRunAtLoadDefault)),
		"SessionCreate":     launchdBool(s.Option.bool(optionSessionCreate, optionSessionCreateDefault)),
		"StandardOutPath":   stdOutPath,
		"StandardErrorPath": stdErrPath,
		// Each entry is the two escaped plist lines for one variable.
		"EnvVars": envVars(c.EnvVars, func(k, v string) string {
			return "\t\t<key>" + plistEscaper.Replace(k) + "</key>\n" +
				"\t\t<string>" + plistEscaper.Replace(v) + "</string>"
		}),
	}

	t, err := s.template()
	if err != nil {
		return err
	}
	out, err := t.render(data, launchdFuncs)
	if err != nil {
		return err
	}
	_, err = f.WriteString(out)
	return err
}

func (s *darwinLaunchdService) Uninstall() error {
	s.Stop()

	confPath, err := s.getServiceFilePath()
	if err != nil {
		return err
	}
	return os.Remove(confPath)
}

func (s *darwinLaunchdService) Status() (Status, error) {
	exitCode, out, err := runWithOutput("launchctl", "list", s.Name)
	if exitCode == 0 && err != nil {
		if !strings.Contains(err.Error(), "failed with stderr") {
			return StatusUnknown, err
		}
	}

	re := regexp.MustCompile(`"PID" = ([0-9]+);`)
	matches := re.FindStringSubmatch(out)
	if len(matches) == 2 {
		return StatusRunning, nil
	}

	confPath, err := s.getServiceFilePath()
	if err != nil {
		return StatusUnknown, err
	}

	if _, err = os.Stat(confPath); err == nil {
		return StatusStopped, nil
	}

	return StatusUnknown, ErrNotInstalled
}

func (s *darwinLaunchdService) Start() error {
	confPath, err := s.getServiceFilePath()
	if err != nil {
		return err
	}
	return run("launchctl", "load", confPath)
}

func (s *darwinLaunchdService) Stop() error {
	confPath, err := s.getServiceFilePath()
	if err != nil {
		return err
	}
	return run("launchctl", "unload", confPath)
}

func (s *darwinLaunchdService) Restart() error {
	err := s.Stop()
	if err != nil {
		return err
	}
	time.Sleep(50 * time.Millisecond)
	return s.Start()
}

func (s *darwinLaunchdService) Run() error {
	err := s.i.Start(s)
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

func (s *darwinLaunchdService) Logger(errs chan<- error) (Logger, error) {
	if interactive {
		return ConsoleLogger, nil
	}
	return s.SystemLogger(errs)
}

func (s *darwinLaunchdService) SystemLogger(errs chan<- error) (Logger, error) {
	return newSysLogger(s.Name, errs)
}

const launchdConfig = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Disabled</key>
	<false/>
	{{if EnvVars}}<key>EnvironmentVariables</key>
	<dict>
{{range EnvVars}}{{.}}
{{end}}	</dict>
	{{end}}<key>KeepAlive</key>
	<{{KeepAlive}}/>
	<key>Label</key>
	<string>{{Name | html}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{Path | html}}</string>
{{range Arguments}}		<string>{{. | html}}</string>
{{end}}	</array>
	{{if ChRoot}}<key>RootDirectory</key>
	<string>{{ChRoot | html}}</string>
	{{end}}<key>RunAtLoad</key>
	<{{RunAtLoad}}/>
	<key>SessionCreate</key>
	<{{SessionCreate}}/>
	{{if StandardErrorPath}}<key>StandardErrorPath</key>
	<string>{{StandardErrorPath | html}}</string>
	{{end}}{{if StandardOutPath}}<key>StandardOutPath</key>
	<string>{{StandardOutPath | html}}</string>
	{{end}}{{if UserName}}<key>UserName</key>
	<string>{{UserName | html}}</string>
	{{end}}{{if WorkingDirectory}}<key>WorkingDirectory</key>
	<string>{{WorkingDirectory | html}}</string>
	{{end}}</dict>
</plist>
`
