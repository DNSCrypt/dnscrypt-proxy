package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/jedisct1/dlog"
)

const defaultDebounceDelay = 250 * time.Millisecond
const defaultPollInterval = 1 * time.Second
const stabilityDelay = 100 * time.Millisecond

// ConfigWatcher monitors configuration files for changes and safely reloads them.
//
// It primarily uses fsnotify (directory watches) and falls back to polling if fsnotify
// isn't available on the current platform.
type ConfigWatcher struct {
	mu           sync.RWMutex
	watchedFiles map[string]*WatchedFile
	filesByDir   map[string]map[string]struct{}
	watchedDirs  map[string]struct{}
	watcher      *fsnotify.Watcher
	timers       map[string]*time.Timer
	debounce     time.Duration

	ctx          context.Context
	cancel       context.CancelFunc
	shutdownOnce sync.Once
	wg           sync.WaitGroup

	pollInterval time.Duration
}

// WatchedFile stores information about a file being monitored for changes.
type WatchedFile struct {
	path       string
	lastHash   []byte
	lastSize   int64
	lastMod    time.Time
	reloadFunc func() error
	mu         sync.Mutex
}

// NewConfigWatcher creates a new configuration file watcher.
//
// The interval is used as a polling interval in fallback mode, and as a debounce delay in
// fsnotify mode when a positive value is provided.
func NewConfigWatcher(interval time.Duration) *ConfigWatcher {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		dlog.Errorf("Failed to create file system watcher: %v", err)
		dlog.Notice("Falling back to polling-based file monitoring")
		return newPollingConfigWatcher(interval)
	}

	debounce := defaultDebounceDelay
	if interval > 0 {
		debounce = interval
	}

	ctx, cancel := context.WithCancel(context.Background())
	cw := &ConfigWatcher{
		watchedFiles: make(map[string]*WatchedFile),
		filesByDir:   make(map[string]map[string]struct{}),
		watchedDirs:  make(map[string]struct{}),
		watcher:      watcher,
		timers:       make(map[string]*time.Timer),
		debounce:     debounce,
		ctx:          ctx,
		cancel:       cancel,
	}

	cw.wg.Add(1)
	go func() {
		defer cw.wg.Done()
		cw.watchLoop()
	}()

	return cw
}

func (cw *ConfigWatcher) watchLoop() {
	for {
		select {
		case event, ok := <-cw.watcher.Events:
			if !ok {
				return
			}
			// Many editors update config files via atomic rename; react to a broad set of events.
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
				cw.handleEvent(event.Name)
			}

		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}
			dlog.Errorf("File watcher error: %v", err)

		case <-cw.ctx.Done():
			return
		}
	}
}

func (cw *ConfigWatcher) handleEvent(path string) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		dlog.Debugf("Could not get absolute path for %s: %v", path, err)
		return
	}

	dir := filepath.Dir(absPath)
	cw.mu.RLock()
	filesInDir := cw.filesByDir[dir]
	cw.mu.RUnlock()
	if len(filesInDir) == 0 {
		return
	}
	for filePath := range filesInDir {
		cw.scheduleCheck(filePath)
	}
}

func (cw *ConfigWatcher) scheduleCheck(absPath string) {
	cw.mu.Lock()
	wf, exists := cw.watchedFiles[absPath]
	if !exists {
		cw.mu.Unlock()
		return
	}

	if t, ok := cw.timers[absPath]; ok {
		t.Reset(cw.debounce)
		cw.mu.Unlock()
		return
	}

	cw.timers[absPath] = time.AfterFunc(cw.debounce, func() {
		select {
		case <-cw.ctx.Done():
			return
		default:
		}
		cw.checkFile(wf)
	})
	cw.mu.Unlock()
}

// checkFile checks whether a file has changed and appears stable before calling its reload function.
func (cw *ConfigWatcher) checkFile(wf *WatchedFile) {
	wf.mu.Lock()
	defer wf.mu.Unlock()

	// First snapshot.
	_, hash1, size1, err := statAndHash(wf.path)
	if err != nil {
		// File may be temporarily unavailable during atomic replacement.
		dlog.Debugf("Cannot read file [%s]: %v", wf.path, err)
		return
	}

	// Wait briefly for stability, but allow shutdown to interrupt.
	t := time.NewTimer(stabilityDelay)
	select {
	case <-cw.ctx.Done():
		t.Stop()
		return
	case <-t.C:
	}

	// Second snapshot.
	info2, hash2, size2, err := statAndHash(wf.path)
	if err != nil {
		return
	}

	// If file size or hash is still changing, it's likely still being written.
	if size1 != size2 || !bytes.Equal(hash1, hash2) {
		dlog.Debugf("File [%s] is still being modified, waiting for stability", wf.path)
		return
	}

	// If content hasn't changed, only record the mod time.
	if wf.lastSize == size2 && bytes.Equal(wf.lastHash, hash2) {
		wf.lastMod = info2.ModTime()
		return
	}

	dlog.Noticef("Configuration file [%s] has changed, reloading", wf.path)
	if err := wf.reloadFunc(); err != nil {
		dlog.Errorf("Failed to reload [%s]: %v", wf.path, err)
		return
	}

	wf.lastHash = hash2
	wf.lastSize = size2
	wf.lastMod = info2.ModTime()
	dlog.Noticef("Successfully reloaded [%s]", wf.path)
}

// AddFile registers a file to be watched for changes.
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

	info, err := os.Stat(absPath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("path is a directory, not a file")
	}

	hash, err := getFileHash(absPath)
	if err != nil {
		return err
	}

	wf := &WatchedFile{
		path:       absPath,
		lastHash:   hash,
		lastSize:   info.Size(),
		lastMod:    info.ModTime(),
		reloadFunc: reloadFunc,
	}

	dir := filepath.Dir(absPath)

	var watchErr error
	func() {
		cw.mu.Lock()
		defer cw.mu.Unlock()
		cw.watchedFiles[absPath] = wf
		if _, ok := cw.filesByDir[dir]; !ok {
			cw.filesByDir[dir] = make(map[string]struct{})
		}
		cw.filesByDir[dir][absPath] = struct{}{}

		// Watch the directory containing the file to catch atomic replace patterns.
		if cw.watcher != nil {
			if _, ok := cw.watchedDirs[dir]; !ok {
				if err := cw.watcher.Add(dir); err != nil {
					delete(cw.watchedFiles, absPath)
					delete(cw.filesByDir[dir], absPath)
					watchErr = err
					return
				}
				cw.watchedDirs[dir] = struct{}{}
			}
		}
	}()

	if watchErr != nil {
		return watchErr
	}
	dlog.Noticef("Now watching [%s] for changes", absPath)
	return nil
}

// RemoveFile stops watching a file.
func (cw *ConfigWatcher) RemoveFile(path string) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return
	}

	cw.mu.Lock()
	if _, exists := cw.watchedFiles[absPath]; !exists {
		cw.mu.Unlock()
		return
	}
	delete(cw.watchedFiles, absPath)

	if t, ok := cw.timers[absPath]; ok {
		t.Stop()
		delete(cw.timers, absPath)
	}

	dir := filepath.Dir(absPath)
	if m, ok := cw.filesByDir[dir]; ok {
		delete(m, absPath)
		if len(m) == 0 {
			delete(cw.filesByDir, dir)
		}
	}
	cw.mu.Unlock()

	// We intentionally keep watching the directory; other files may still be watched.
	dlog.Noticef("Stopped watching [%s]", absPath)
}

// Shutdown stops the watcher.
func (cw *ConfigWatcher) Shutdown() {
	if cw == nil {
		return
	}
	cw.shutdownOnce.Do(func() {
		if cw.cancel != nil {
			cw.cancel()
		}

		cw.mu.Lock()
		for _, t := range cw.timers {
			t.Stop()
		}
		cw.timers = nil
		cw.mu.Unlock()

		if cw.watcher != nil {
			_ = cw.watcher.Close()
		}

		cw.wg.Wait()
	})
}

// newPollingConfigWatcher creates a polling-based watcher.
func newPollingConfigWatcher(interval time.Duration) *ConfigWatcher {
	poll := interval
	if poll <= 0 {
		poll = defaultPollInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	cw := &ConfigWatcher{
		watchedFiles: make(map[string]*WatchedFile),
		filesByDir:   make(map[string]map[string]struct{}),
		timers:       make(map[string]*time.Timer),
		ctx:          ctx,
		cancel:       cancel,
		pollInterval: poll,
	}

	cw.wg.Add(1)
	go func() {
		defer cw.wg.Done()
		ticker := time.NewTicker(poll)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cw.checkAllFiles()
			case <-cw.ctx.Done():
				return
			}
		}
	}()

	return cw
}

func (cw *ConfigWatcher) checkAllFiles() {
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

func statAndHash(path string) (os.FileInfo, []byte, int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, 0, err
	}
	h, err := getFileHash(path)
	if err != nil {
		return nil, nil, 0, err
	}
	return info, h, info.Size(), nil
}

// getFileHash calculates a SHA-256 hash of a file's contents.
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
