package main

import (
	"errors"
	"fmt"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
)

// ReloadablePlugin is an interface for plugins that support hot-reloading
type ReloadablePlugin interface {
	// Plugin interface methods
	Name() string
	Description() string
	Init(proxy *Proxy) error
	Drop() error
	Reload() error
	Eval(pluginsState *PluginsState, msg *dns.Msg) error

	// ReloadablePlugin specific methods
	PrepareReload() error                    // Prepare new configuration but don't apply it yet
	ApplyReload() error                      // Apply prepared configuration
	CancelReload()                           // Cancel the prepared configuration
	GetConfigPath() string                   // Return path to the configuration file
	SetConfigWatcher(watcher *ConfigWatcher) // Set the config watcher
}

// SafeReadTextFile is similar to ReadTextFile but with additional safeguards
// to prevent reading partially written files
func SafeReadTextFile(filePath string) (string, error) {
	// First attempt to read the file
	content, err := ReadTextFile(filePath)
	if err != nil {
		return "", err
	}

	// Wait a short time to ensure the file isn't still being written
	time.Sleep(50 * time.Millisecond)

	// Read again and compare to first read
	content2, err := ReadTextFile(filePath)
	if err != nil {
		return "", err
	}

	// If content is different, the file might still be being written
	if content != content2 {
		return "", errors.New("file appears to be changing during read")
	}

	return content, nil
}

// StandardReloadPattern implements the common reload pattern used by most plugins
func StandardReloadPattern(pluginName string, reloadFunc func() error) error {
	dlog.Noticef("Reloading configuration for plugin [%s]", pluginName)

	// Execute the reload function
	if err := reloadFunc(); err != nil {
		return err
	}

	return nil
}

// StandardPrepareReloadPattern implements the common prepare-reload pattern
func StandardPrepareReloadPattern(pluginName, configFile string, prepareFunc func(string) error) error {
	// Read the configuration file
	lines, err := SafeReadTextFile(configFile)
	if err != nil {
		return fmt.Errorf("error reading config file during reload preparation: %w", err)
	}

	// Execute the prepare function with the file contents
	if err := prepareFunc(lines); err != nil {
		return fmt.Errorf("error parsing config during reload preparation: %w", err)
	}

	return nil
}

// StandardApplyReloadPattern implements the common apply-reload pattern
func StandardApplyReloadPattern(pluginName string, applyFunc func() error) error {
	if err := applyFunc(); err != nil {
		return err
	}

	dlog.Noticef("Applied new configuration for plugin [%s]", pluginName)
	return nil
}
