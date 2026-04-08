package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jedisct1/dlog"
	"github.com/kardianos/service"
)

const (
	AppVersion            = "2.1.15"
	DefaultConfigFileName = "dnscrypt-proxy.toml"
)

type App struct {
	quit  chan os.Signal
	proxy *Proxy
	flags *ConfigFlags
}

func main() {
	tzErr := TimezoneSetup()
	dlog.Init("dnscrypt-proxy", dlog.SeverityNotice, "DAEMON")
	if tzErr != nil {
		dlog.Warnf("Timezone setup failed: [%v]", tzErr)
	}

	// Disable runtime memory profiling by default.
	runtime.MemProfileRate = 0

	pwd, err := os.Getwd()
	if err != nil {
		dlog.Fatal("Unable to find the path to the current directory")
	}

	svcFlag := flag.String("service", "", fmt.Sprintf("Control the system service: %q", service.ControlAction))
	version := flag.Bool("version", false, "print current proxy version")

	flags := ConfigFlags{}
	flags.Resolve = flag.String("resolve", "", "resolve a DNS name (string can be <name> or <name>,<resolver address>)")
	flags.List = flag.Bool("list", false, "print the list of available resolvers for the enabled filters")
	flags.ListAll = flag.Bool("list-all", false, "print the complete list of available resolvers, ignoring filters")
	flags.IncludeRelays = flag.Bool("include-relays", false, "include the list of available relays in the output of -list and -list-all")
	flags.JSONOutput = flag.Bool("json", false, "output list as JSON")
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

	if fullexecpath, err := os.Executable(); err == nil {
		WarnIfMaybeWritableByOtherUsers(fullexecpath)
	}

	// Ensure math/rand/v2 is linked and usable (it is auto-seeded).
	_ = rand.Uint64()

	app := &App{flags: &flags}

	svcOptions := make(service.KeyValue)
	svcOptions["ReloadSignal"] = "HUP"
	svcConfig := &service.Config{
		Name:             "dnscrypt-proxy",
		DisplayName:      "DNSCrypt client proxy",
		Description:      "Encrypted/authenticated DNS proxy",
		WorkingDirectory: pwd,
		Arguments:        []string{"-config", *flags.ConfigFile},
		Option:           svcOptions,
	}

	svc, err := service.New(app, svcConfig)
	if err != nil {
		svc = nil
		dlog.Debug(err)
	}

	app.proxy = NewProxy()
	_ = ServiceManagerStartNotify()

	if *svcFlag != "" {
		if svc == nil {
			dlog.Fatal("Built-in service installation is not supported on this platform")
		}
		if err := service.Control(svc, *svcFlag); err != nil {
			dlog.Fatal(err)
		}
		switch *svcFlag {
		case "install":
			dlog.Notice("Installed as a service. Use `-service start` to start")
		case "uninstall":
			dlog.Notice("Service uninstalled")
		case "start":
			dlog.Notice("Service started")
		case "stop":
			dlog.Notice("Service stopped")
		case "restart":
			dlog.Notice("Service restarted")
		}
		return
	}

	if svc != nil {
		if err := svc.Run(); err != nil {
			dlog.Fatal(err)
		}
		return
	}

	// Non-service mode.
	app.quit = make(chan os.Signal, 1)
	signal.Notify(app.quit, os.Interrupt, syscall.SIGTERM)
	go app.AppMain()
	<-app.quit
	dlog.Notice("Quit signal received...")
}

func (app *App) Start(service.Service) error {
	go app.AppMain()
	return nil
}

func (app *App) AppMain() {
	action, err := ConfigLoad(app.proxy, app.flags)
	if err != nil {
		dlog.Fatal(err)
	}
	if action == ConfigLoadActionExitSuccess {
		os.Exit(0)
	}
	if err := PidFileCreate(); err != nil {
		dlog.Errorf("Unable to create the PID file: [%v]", err)
	}
	if err := app.proxy.InitPluginsGlobals(); err != nil {
		dlog.Fatal(err)
	}
	if err := app.proxy.InitHotReload(); err != nil {
		dlog.Warnf("Failed to initialize hot-reloading: %v", err)
	}
	app.proxy.StartProxy()
	runtime.GC()
}

func (app *App) Stop(service.Service) error {
	if app.proxy != nil && app.proxy.udpConnPool != nil {
		app.proxy.udpConnPool.Close()
	}
	if err := PidFileRemove(); err != nil {
		dlog.Warnf("Failed to remove the PID file: [%v]", err)
	}
	dlog.Notice("Stopped.")
	return nil
}
