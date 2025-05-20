package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/jedisct1/dlog"
)

// InitHotReload sets up hot-reloading for configuration files
func (proxy *Proxy) InitHotReload() error {
	// Create a new configuration watcher
	configWatcher := NewConfigWatcher(1000) // Check every second

	// Find plugins that support hot-reloading
	plugins := []Plugin{}

	// Add query plugins
	proxy.pluginsGlobals.RLock()
	if proxy.pluginsGlobals.queryPlugins != nil {
		for _, plugin := range *proxy.pluginsGlobals.queryPlugins {
			plugins = append(plugins, plugin)
		}
	}

	// Add response plugins
	if proxy.pluginsGlobals.responsePlugins != nil {
		for _, plugin := range *proxy.pluginsGlobals.responsePlugins {
			plugins = append(plugins, plugin)
		}
	}
	proxy.pluginsGlobals.RUnlock()

	// Register plugins for config watching
	for _, plugin := range plugins {
		switch p := plugin.(type) {
		case *PluginAllowName:
			if len(p.configFile) > 0 {
				if err := configWatcher.AddFile(p.configFile, p.Reload); err != nil {
					dlog.Warnf("Failed to watch config file for plugin [%s]: %v", p.Name(), err)
				} else {
					p.SetConfigWatcher(configWatcher)
					dlog.Noticef("Watching config file for plugin [%s]: %s", p.Name(), p.configFile)
				}
			}
		case *PluginAllowedIP:
			if len(p.configFile) > 0 {
				if err := configWatcher.AddFile(p.configFile, p.Reload); err != nil {
					dlog.Warnf("Failed to watch config file for plugin [%s]: %v", p.Name(), err)
				} else {
					p.SetConfigWatcher(configWatcher)
					dlog.Noticef("Watching config file for plugin [%s]: %s", p.Name(), p.configFile)
				}
			}
		case *PluginBlockIP:
			if len(p.configFile) > 0 {
				if err := configWatcher.AddFile(p.configFile, p.Reload); err != nil {
					dlog.Warnf("Failed to watch config file for plugin [%s]: %v", p.Name(), err)
				} else {
					p.SetConfigWatcher(configWatcher)
					dlog.Noticef("Watching config file for plugin [%s]: %s", p.Name(), p.configFile)
				}
			}
		case *PluginBlockName:
			if len(p.configFile) > 0 {
				if err := configWatcher.AddFile(p.configFile, p.Reload); err != nil {
					dlog.Warnf("Failed to watch config file for plugin [%s]: %v", p.Name(), err)
				} else {
					p.SetConfigWatcher(configWatcher)
					dlog.Noticef("Watching config file for plugin [%s]: %s", p.Name(), p.configFile)
				}
			}
		case *PluginCloak:
			if len(p.configFile) > 0 {
				if err := configWatcher.AddFile(p.configFile, p.Reload); err != nil {
					dlog.Warnf("Failed to watch config file for plugin [%s]: %v", p.Name(), err)
				} else {
					p.SetConfigWatcher(configWatcher)
					dlog.Noticef("Watching config file for plugin [%s]: %s", p.Name(), p.configFile)
				}
			}
		case *PluginForward:
			if len(p.configFile) > 0 {
				if err := configWatcher.AddFile(p.configFile, p.Reload); err != nil {
					dlog.Warnf("Failed to watch config file for plugin [%s]: %v", p.Name(), err)
				} else {
					p.SetConfigWatcher(configWatcher)
					dlog.Noticef("Watching config file for plugin [%s]: %s", p.Name(), p.configFile)
				}
			}
		}
	}

	// Setup SIGHUP handler for manual reload
	setupSignalHandler(proxy, plugins)

	return nil
}

// setupSignalHandler sets up a SIGHUP handler to manually trigger reloads
func setupSignalHandler(proxy *Proxy, plugins []Plugin) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)

	go func() {
		for {
			sig := <-sigChan
			if sig == syscall.SIGHUP {
				dlog.Notice("Received SIGHUP signal, reloading configurations")

				// Reload each plugin that supports hot-reloading
				for _, plugin := range plugins {
					if err := plugin.Reload(); err != nil {
						dlog.Errorf("Failed to reload plugin [%s]: %v", plugin.Name(), err)
					} else {
						dlog.Noticef("Successfully reloaded plugin [%s]", plugin.Name())
					}
				}
			}
		}
	}()
}
