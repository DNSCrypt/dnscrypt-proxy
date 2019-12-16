// Copyright 2015 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"text/template"
	"time"
)

const maxPathSize = 32 * 1024

const version = "solaris-smf"

type solarisSystem struct{}

func (solarisSystem) String() string {
	return version
}
func (solarisSystem) Detect() bool {
	return true
}
func (solarisSystem) Interactive() bool {
	return interactive
}
func (solarisSystem) New(i Interface, c *Config) (Service, error) {
	s := &solarisService{
		i:      i,
		Config: c,

		Prefix: c.Option.string(optionPrefix, optionPrefixDefault),
	}

	return s, nil
}

func init() {
	ChooseSystem(solarisSystem{})
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
	// The PPid of a service process be 1 / init.
	return os.Getppid() != 1, nil
}

type solarisService struct {
	i Interface
	*Config

	Prefix string
}

func (s *solarisService) String() string {
	if len(s.DisplayName) > 0 {
		return s.DisplayName
	}
	return s.Name
}

func (s *solarisService) Platform() string {
	return version
}

func (s *solarisService) template() *template.Template {
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
		return template.Must(template.New("").Funcs(functions).Parse(manifest))
	}
}

func (s *solarisService) configPath() (string, error) {
	return "/lib/svc/manifest/" + s.Prefix + "/" + s.Config.Name + ".xml", nil
}

func (s *solarisService) getFMRI() string {
	return "svc:/" + s.Prefix + "/" + s.Config.Name + ":default"
}

func (s *solarisService) Install() error {
	// write start script
	confPath, err := s.configPath()
	if err != nil {
		return err
	}
	_, err = os.Stat(confPath)
	if err == nil {
		return fmt.Errorf("Manifest already exists: %s", confPath)
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
	Display := ""
	escaped := &bytes.Buffer{}
	if err := xml.EscapeText(escaped, []byte(s.DisplayName)); err == nil {
		Display = escaped.String()
	}
	var to = &struct {
		*Config
		Prefix string
		Display string
		Path string
	}{
		s.Config,
		s.Prefix,
		Display,
		path,
	}

	err = s.template().Execute(f, to)
	if err != nil {
		return err
	}

	// import service
	err = run("svcadm", "restart", "manifest-import" )
	if err != nil {
		return err
	}

	return nil
}

func (s *solarisService) Uninstall() error {
	s.Stop()

	confPath, err := s.configPath()
	if err != nil {
		return err
	}
	err = os.Remove(confPath)
	if err != nil {
		return err
	}

	// unregister service
	err = run("svcadm", "restart", "manifest-import" )
	if err != nil {
		return err
	}

	return nil
}

func (s *solarisService) Status() (Status, error) {
	fmri := s.getFMRI()
	exitCode, out, err := runWithOutput("svcs", fmri)
	if exitCode != 0 {
		return StatusUnknown, ErrNotInstalled
	}

	re := regexp.MustCompile(`(degraded|disabled|legacy_run|maintenance|offline|online)\s+\w+` + fmri)
	matches := re.FindStringSubmatch(out)
	if len(matches) == 2 {
		status := string(matches[1])
		if status == "online" {
			return StatusRunning, nil
		} else {
			return StatusStopped, nil
		}
	}
	return StatusUnknown, err
}

func (s *solarisService) Start() error {
	return run("/usr/sbin/svcadm", "enable", s.getFMRI())
}
func (s *solarisService) Stop() error {
	return run("/usr/sbin/svcadm", "disable", s.getFMRI())
}
func (s *solarisService) Restart() error {
	err := s.Stop()
	if err != nil {
		return err
	}
	time.Sleep(50 * time.Millisecond)
	return s.Start()
}

func (s *solarisService) Run() error {
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

func (s *solarisService) Logger(errs chan<- error) (Logger, error) {
	if interactive {
		return ConsoleLogger, nil
	}
	return s.SystemLogger(errs)
}
func (s *solarisService) SystemLogger(errs chan<- error) (Logger, error) {
	return newSysLogger(s.Name, errs)
}

var manifest = `<?xml version="1.0"?>
<!DOCTYPE service_bundle SYSTEM "/usr/share/lib/xml/dtd/service_bundle.dtd.1">

<service_bundle type='manifest' name='golang-{{.Name}}'>
<service
	name='{{.Prefix}}/{{.Name}}'
	type='service'
	version='1'>
	
	<create_default_instance enabled='false' />

	<single_instance />

	<!--
	  Wait for network interfaces to be initialized.
	-->
	<dependency name='network'
	    grouping='require_all'
	    restart_on='restart'
	    type='service'>
	    <service_fmri value='svc:/milestone/network:default'/>
	</dependency>

	<!--
	  Wait for all local filesystems to be mounted.
	-->
	<dependency name='filesystem-local'
	    grouping='require_all'
	    restart_on='none'
	    type='service'>
	    <service_fmri
		value='svc:/system/filesystem/local:default'/>
	</dependency>

	<exec_method
		type='method'
		name='start'
		exec='bash -c {{.Path}} &amp;'
		timeout_seconds='10' />

	<exec_method
		type='method'
		name='stop'
		exec='pkill -TERM -f {{.Path}}'
		timeout_seconds='60' />

	<!--
	<property_group name='startd' type='framework'>
                <propval name='duration' type='astring' value='transient' />
        </property_group>
	-->
	
	<stability value='Unstable' />

	<template>
                <common_name>
                        <loctext xml:lang='C'>
                                {{.Display}}
                        </loctext>
                </common_name>
        </template>
</service>

</service_bundle>
`
