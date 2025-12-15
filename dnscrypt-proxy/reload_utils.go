package main

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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

// ReloadSafeguard provides atomic operations to ensure configuration reloading is safe
type ReloadSafeguard struct {
	isReloading     int32        // Flag indicating if a reload is in progress (0=false, 1=true)
	reloadMutex     sync.Mutex   // Mutex for reload operations
	activeConfigMu  sync.RWMutex // Read-write mutex for accessing active configuration
	activeTimestamp time.Time    // Timestamp when the active config was loaded
}

// NewReloadSafeguard creates a new reload safeguard
func NewReloadSafeguard() *ReloadSafeguard {
	return &ReloadSafeguard{
		activeTimestamp: time.Now(),
	}
}

// StartReload attempts to start a reload operation
// Returns true if reload can proceed, false if another reload is in progress
func (rs *ReloadSafeguard) StartReload() bool {
	// Try to set isReloading atomically, only succeeds if it was previously false
	if atomic.CompareAndSwapInt32(&rs.isReloading, 0, 1) {
		rs.reloadMutex.Lock()
		return true
	}
	return false
}

// FinishReload completes a reload operation, releasing locks
func (rs *ReloadSafeguard) FinishReload() {
	atomic.StoreInt32(&rs.isReloading, 0)
	rs.reloadMutex.Unlock()
}

// AcquireConfigRead acquires a read lock on the active configuration
func (rs *ReloadSafeguard) AcquireConfigRead() {
	rs.activeConfigMu.RLock()
}

// ReleaseConfigRead releases a read lock on the active configuration
func (rs *ReloadSafeguard) ReleaseConfigRead() {
	rs.activeConfigMu.RUnlock()
}

// AcquireConfigWrite acquires a write lock on the active configuration
func (rs *ReloadSafeguard) AcquireConfigWrite() {
	rs.activeConfigMu.Lock()
}

// ReleaseConfigWrite releases a write lock on the active configuration
func (rs *ReloadSafeguard) ReleaseConfigWrite() {
	rs.activeConfigMu.Unlock()
	rs.activeTimestamp = time.Now()
}

// SafeReload handles the entire reload process with proper locking
// The provided function is executed while holding the write lock
func (rs *ReloadSafeguard) SafeReload(reloadFunc func() error) error {
	if !rs.StartReload() {
		return errors.New("another reload operation is already in progress")
	}
	defer rs.FinishReload()

	// Acquire write lock for configuration update
	rs.AcquireConfigWrite()
	defer rs.ReleaseConfigWrite()

	// Execute the provided reload function
	return reloadFunc()
}

// RegisterPluginForReload adds a plugin to the config watcher for automatic reloading
func RegisterPluginForReload(plugin ReloadablePlugin, watcher *ConfigWatcher) error {
	configPath := plugin.GetConfigPath()
	if configPath == "" {
		return errors.New("empty configuration path for plugin: " + plugin.Name())
	}

	// Create a reload function closure that handles the complete reload process
	reloadFunc := func() error {
		dlog.Noticef("Reloading configuration for plugin [%s]", plugin.Name())

		// Prepare stage: Load and validate new configuration without applying it
		if err := plugin.PrepareReload(); err != nil {
			dlog.Errorf("Failed to prepare reload for plugin [%s]: %v", plugin.Name(), err)
			plugin.CancelReload() // Ensure cleanup of any temporary resources
			return err
		}

		// Apply stage: Switch to new configuration
		if err := plugin.ApplyReload(); err != nil {
			dlog.Errorf("Failed to apply reload for plugin [%s]: %v", plugin.Name(), err)
			plugin.CancelReload() // Ensure cleanup of any temporary resources
			return err
		}

		dlog.Noticef("Successfully reloaded plugin [%s]", plugin.Name())
		return nil
	}

	// Add the plugin's config file to the watcher
	if err := watcher.AddFile(configPath, reloadFunc); err != nil {
		return err
	}

	// Set the config watcher in the plugin
	plugin.SetConfigWatcher(watcher)

	return nil
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
