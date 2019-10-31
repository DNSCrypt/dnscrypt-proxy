package main

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"syscall"

	"github.com/facebookgo/pidfile"
	"github.com/jedisct1/dlog"
	"github.com/kardianos/service"
)

const (
	AppVersion            = "2.0.30"
	DefaultConfigFileName = "dnscrypt-proxy.toml"
)

type App struct {
	proxy *Proxy
	flags *ConfigFlags
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
	version := flag.Bool("version", false, "print current proxy version")
	resolve := flag.String("resolve", "", "resolve a name using system libraries")
	flags := ConfigFlags{}
	flags.List = flag.Bool("list", false, "print the list of available resolvers for the enabled filters")
	flags.ListAll = flag.Bool("list-all", false, "print the complete list of available resolvers, ignoring filters")
	flags.JsonOutput = flag.Bool("json", false, "output list as JSON")
	flags.Check = flag.Bool("check", false, "check the configuration file and exit")
	flags.ConfigFile = flag.String("config", DefaultConfigFileName, "Path to the configuration file")
	flags.Child = flag.Bool("child", false, "Invokes program as a child process")
	flags.NetprobeTimeoutOverride = flag.Int("netprobe-timeout", 60, "Override the netprobe timeout")
	flags.ShowCerts = flag.Bool("show-certs", false, "print DoH certificate chain hashes")

	flag.Parse()

	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}
	if resolve != nil && len(*resolve) > 0 {
		Resolve(*resolve)
		os.Exit(0)
	}

	app := &App{
		flags: &flags,
	}
	svc, err := service.New(app, svcConfig)
	if err != nil {
		svc = nil
		dlog.Debug(err)
	}
	app.proxy = NewProxy()
	_ = ServiceManagerStartNotify()
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
		if err := ConfigLoad(app.proxy, &flags); err != nil {
			dlog.Fatal(err)
		}
		app.signalWatch()
		app.Start(nil)
	}
	app.proxy.ConnCloseWait()
	dlog.Notice("Stopped.")
}

func (app *App) Start(service service.Service) error {
	go func() {
		if err := ConfigLoad(app.proxy, app.flags); err != nil {
			dlog.Fatal(err)
		}
		if err := app.proxy.InitPluginsGlobals(); err != nil {
			dlog.Fatal(err)
		}
		app.appMain()
	}()
	return nil
}

func (app *App) Stop(service service.Service) error {
	if pidFilePath := pidfile.GetPidfilePath(); len(pidFilePath) > 1 {
		os.Remove(pidFilePath)
	}
	dlog.Notice("Quit signal received...")
	app.proxy.Stop()
	return nil
}

func (app *App) appMain() {
	pidfile.Write()
	app.proxy.StartProxy()
}

func (app *App) signalWatch() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		signal.Stop(quit)
		app.proxy.Stop()
	}()
}
