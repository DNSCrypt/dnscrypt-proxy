package main

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/facebookgo/pidfile"
	"github.com/jedisct1/dlog"
	"github.com/kardianos/service"
)

const (
	AppVersion            = "2.0.29"
	DefaultConfigFileName = "dnscrypt-proxy.toml"
)

type App struct {
	wg    sync.WaitGroup
	quit  chan struct{}
	proxy *Proxy
}

func main() {
	dlog.Init("dnscrypt-proxy", dlog.SeverityNotice, "DAEMON")
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")

	seed := make([]byte, 8)
	crypto_rand.Read(seed)
	rand.Seed(int64(binary.LittleEndian.Uint64(seed[:])))

	pwd, err := os.Getwd()
	if err != nil {
		dlog.Fatal("Unable to find the path to the current directory")
	}
	svcConfig := &service.Config{
		Name:             "dnscrypt-proxy",
		DisplayName:      "DNSCrypt client proxy",
		Description:      "Encrypted/authenticated DNS proxy",
		WorkingDirectory: pwd,
	}
	svcFlag := flag.String("service", "", fmt.Sprintf("Control the system service: %q", service.ControlAction))
	app := &App{
		quit: make(chan struct{}),
	}
	svc, err := service.New(app, svcConfig)
	if err != nil {
		svc = nil
		dlog.Debug(err)
	}
	app.proxy = NewProxy()
	_ = ServiceManagerStartNotify()
	if err := ConfigLoad(app.proxy, svcFlag); err != nil {
		dlog.Fatal(err)
	}
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
	app.wg.Add(1)
	if svc != nil {
		if err = svc.Run(); err != nil {
			dlog.Fatal(err)
		}
	} else {
		app.signalWatch()
		app.Start(nil)
	}
	app.wg.Wait()
	dlog.Notice("Stopped.")
}

func (app *App) Start(service service.Service) error {
	if err := app.proxy.InitPluginsGlobals(); err != nil {
		dlog.Fatal(err)
	}
	go app.appMain()
	return nil
}

func (app *App) Stop(service service.Service) error {
	if pidFilePath := pidfile.GetPidfilePath(); len(pidFilePath) > 1 {
		os.Remove(pidFilePath)
	}
	dlog.Notice("Quit signal received...")
	close(app.quit)
	return nil
}

func (app *App) appMain() {
	pidfile.Write()
	app.proxy.StartProxy(app.quit)
	app.wg.Done()
}

func (app *App) signalWatch() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		signal.Stop(quit)
		close(app.quit)
	}()
}
