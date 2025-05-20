package main

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jedisct1/dlog"
)

// ConfigWatcher monitors configuration files for changes and safely reloads them
type ConfigWatcher struct {
	watchedFiles map[string]*WatchedFile
	mu           sync.RWMutex
	shutdownCh   chan struct{}
	interval     time.Duration
}

// WatchedFile stores information about a file being monitored for changes
type WatchedFile struct {
	path       string
	lastHash   []byte
	lastSize   int64
	lastMod    time.Time
	reloadFunc func() error
	mu         sync.Mutex
}

// NewConfigWatcher creates a new configuration file watcher
func NewConfigWatcher(interval time.Duration) *ConfigWatcher {
	if interval <= 0 {
		interval = 1 * time.Second
	}
	cw := &ConfigWatcher{
		watchedFiles: make(map[string]*WatchedFile),
		shutdownCh:   make(chan struct{}),
		interval:     interval,
	}
	go cw.watchLoop()
	return cw
}

// watchLoop periodically checks for file changes
func (cw *ConfigWatcher) watchLoop() {
	ticker := time.NewTicker(cw.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cw.checkFiles()
		case <-cw.shutdownCh:
			return
		}
	}
}

// checkFiles examines all watched files for changes
func (cw *ConfigWatcher) checkFiles() {
	cw.mu.RLock()
	files := make([]*WatchedFile, 0, len(cw.watchedFiles))
	for _, wf := range cw.watchedFiles {
		files = append(files, wf)
	}
	cw.mu.RUnlock()

	for _, wf := range files {
		cw.checkFile(wf)
	}
}

// checkFile checks if a specific file has changed and is stable
func (cw *ConfigWatcher) checkFile(wf *WatchedFile) {
	wf.mu.Lock()
	defer wf.mu.Unlock()

	// Get file information
	fileInfo, err := os.Stat(wf.path)
	if err != nil {
		// File might be temporarily unavailable during writes
		dlog.Debugf("Cannot stat file [%s]: %v", wf.path, err)
		return
	}

	// Check if modification time has changed
	if !fileInfo.ModTime().After(wf.lastMod) {
		// File hasn't been modified
		return
	}

	// File has been modified, but check if it's still being written
	// by taking two measurements with a short delay
	size1 := fileInfo.Size()
	hash1, err := getFileHash(wf.path)
	if err != nil {
		dlog.Debugf("Cannot read file [%s]: %v", wf.path, err)
		return
	}

	// Wait a moment to see if the file is still changing
	time.Sleep(100 * time.Millisecond)

	fileInfo, err = os.Stat(wf.path)
	if err != nil {
		return
	}

	size2 := fileInfo.Size()
	hash2, err := getFileHash(wf.path)
	if err != nil {
		return
	}

	// If file size or hash is still changing, it's still being written
	if size1 != size2 || !hashesEqual(hash1, hash2) {
		dlog.Debugf("File [%s] is still being modified, waiting for stability", wf.path)
		return
	}

	// The file appears stable, check if it's different from last loaded version
	if wf.lastSize == size2 && hashesEqual(wf.lastHash, hash2) {
		// Content hasn't changed despite mod time change
		wf.lastMod = fileInfo.ModTime()
		return
	}

	// File has changed and is stable, reload it
	dlog.Noticef("Configuration file [%s] has changed, reloading", wf.path)
	if err := wf.reloadFunc(); err != nil {
		dlog.Errorf("Failed to reload [%s]: %v", wf.path, err)
		return
	}

	// Update file info after successful reload
	wf.lastHash = hash2
	wf.lastSize = size2
	wf.lastMod = fileInfo.ModTime()
	dlog.Noticef("Successfully reloaded [%s]", wf.path)
}

// AddFile registers a file to be watched for changes
func (cw *ConfigWatcher) AddFile(path string, reloadFunc func() error) error {
	if path == "" {
		return errors.New("empty file path")
	}
	if reloadFunc == nil {
		return errors.New("reload function is nil")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	// Check if file exists and is readable
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		return err
	}
	if fileInfo.IsDir() {
		return errors.New("path is a directory, not a file")
	}

	// Calculate initial hash
	hash, err := getFileHash(absPath)
	if err != nil {
		return err
	}

	wf := &WatchedFile{
		path:       absPath,
		lastHash:   hash,
		lastSize:   fileInfo.Size(),
		lastMod:    fileInfo.ModTime(),
		reloadFunc: reloadFunc,
	}

	cw.mu.Lock()
	defer cw.mu.Unlock()

	cw.watchedFiles[absPath] = wf
	dlog.Noticef("Now watching [%s] for changes", absPath)
	return nil
}

// RemoveFile stops watching a file
func (cw *ConfigWatcher) RemoveFile(path string) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return
	}

	cw.mu.Lock()
	defer cw.mu.Unlock()

	if _, exists := cw.watchedFiles[absPath]; exists {
		delete(cw.watchedFiles, absPath)
		dlog.Noticef("Stopped watching [%s]", absPath)
	}
}

// Shutdown stops the watcher
func (cw *ConfigWatcher) Shutdown() {
	close(cw.shutdownCh)
}

// getFileHash calculates a SHA-256 hash of a file's contents
func getFileHash(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// hashesEqual compares two hashes for equality
func hashesEqual(h1, h2 []byte) bool {
	if len(h1) != len(h2) {
		return false
	}
	for i := range h1 {
		if h1[i] != h2[i] {
			return false
		}
	}
	return true
}
