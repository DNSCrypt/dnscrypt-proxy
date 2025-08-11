package main

import (
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
	configWatcher := NewConfigWatcher(1000) // Check every second

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

	return nil
}
