package main

import (
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/facebookgo/pidfile"
	"github.com/jedisct1/dlog"
	"github.com/kardianos/service"
)

const (
	AppVersion            = "2.0.7"
	DefaultConfigFileName = "dnscrypt-proxy.toml"
)

type App struct {
	wg    sync.WaitGroup
	quit  chan struct{}
	proxy Proxy
}

func main() {
	dlog.Init("dnscrypt-proxy", dlog.SeverityNotice, "DAEMON")
	svcConfig := &service.Config{
		Name:        "dnscrypt-proxy",
		DisplayName: "DNSCrypt client proxy",
		Description: "Encrypted/authenticated DNS proxy",
	}
	svcFlag := flag.String("service", "", fmt.Sprintf("Control the system service: %q", service.ControlAction))
	app := &App{}
	svc, err := service.New(app, svcConfig)
	if err != nil {
		svc = nil
		dlog.Debug(err)
	}
	app.proxy = NewProxy()
	app.proxy.xTransport = NewXTransport(30*time.Second, true, false)

	if err := ConfigLoad(&app.proxy, svcFlag); err != nil {
		dlog.Fatal(err)
	}
	dlog.Noticef("dnscrypt-proxy %s", AppVersion)

	if len(*svcFlag) != 0 {
		if svc == nil {
			dlog.Fatal("Built-in service installation is not supported on this platform")
		}
		if err := service.Control(svc, *svcFlag); err != nil {
			dlog.Fatal(err)
		}
		if *svcFlag == "install" {
			dlog.Notice("Installed as a service. Use `-service start` to start")
		} else if *svcFlag == "uninstall" {
			dlog.Notice("Service uninstalled")
		} else if *svcFlag == "start" {
			dlog.Notice("Service started")
		} else if *svcFlag == "stop" {
			dlog.Notice("Service stopped")
		} else if *svcFlag == "restart" {
			dlog.Notice("Service restarted")
		}
		return
	}
	if svc != nil {
		if err = svc.Run(); err != nil {
			dlog.Fatal(err)
		}
	} else {
		app.Start(nil)
	}
}

func (app *App) Start(service service.Service) error {
	proxy := &app.proxy
	if err := InitPluginsGlobals(&proxy.pluginsGlobals, proxy); err != nil {
		dlog.Fatal(err)
	}
	if proxy.daemonize {
		Daemonize()
	}
	app.quit = make(chan struct{})
	app.wg.Add(1)
	if service != nil {
		go func() {
			app.AppMain(proxy)
		}()
	} else {
		app.AppMain(proxy)
	}
	return nil
}

func (app *App) AppMain(proxy *Proxy) {
	proxy.StartProxy()
	pidfile.Write()
	<-app.quit
	dlog.Notice("Quit signal received...")
	app.wg.Done()

}

func (app *App) Stop(service service.Service) error {
	if pidFilePath := pidfile.GetPidfilePath(); len(pidFilePath) > 1 {
		os.Remove(pidFilePath)
	}
	dlog.Notice("Stopped.")
	return nil
}
