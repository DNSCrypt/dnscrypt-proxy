package main

import (
	"time"

	"github.com/jedisct1/dlog"
)

// InitHotReload sets up hot-reloading for configuration files
func (proxy *Proxy) InitHotReload() error {
	// Check if hot reload is enabled and platform has SIGHUP
	if !proxy.enableHotReload && !HasSIGHUP {
		dlog.Notice("Hot reload is disabled")
		return nil
	}

	// Find plugins that support hot-reloading
	plugins := []Plugin{}

	// Add query plugins
	proxy.pluginsGlobals.RLock()
	if proxy.pluginsGlobals.queryPlugins != nil {
		plugins = append(plugins, *proxy.pluginsGlobals.queryPlugins...)
	}

	// Add response plugins
	if proxy.pluginsGlobals.responsePlugins != nil {
		plugins = append(plugins, *proxy.pluginsGlobals.responsePlugins...)
	}
	proxy.pluginsGlobals.RUnlock()

	// Setup SIGHUP handler for manual reload
	setupSignalHandler(proxy, plugins)

	// Check if hot reload is enabled
	if !proxy.enableHotReload {
		dlog.Notice("Hot reload is disabled")
		return nil
	}

	dlog.Notice("Hot reload is enabled")

	// Create a new configuration watcher
	configWatcher := NewConfigWatcher(time.Second) // Check every second

	// Register plugins for config watching
	for _, plugin := range plugins {
		if rp, ok := plugin.(ReloadablePlugin); ok {
			configPath := rp.GetConfigPath()
			if len(configPath) > 0 {
				if err := configWatcher.AddFile(configPath, rp.Reload); err != nil {
					dlog.Warnf("Failed to watch config file for plugin [%s]: %v", rp.Name(), err)
				} else {
					rp.SetConfigWatcher(configWatcher)
					dlog.Noticef("Watching config file for plugin [%s]: %s", rp.Name(), configPath)
				}
			}
		}
	}

	return nil
}
