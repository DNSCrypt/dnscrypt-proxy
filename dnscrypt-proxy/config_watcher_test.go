package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestConfigWatcher tests the basic functionality of the ConfigWatcher
func TestConfigWatcher(t *testing.T) {
	// Create a temporary file for testing
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test_config.txt")

	// Create test file with initial content
	initialContent := "test content"
	if err := os.WriteFile(tempFile, []byte(initialContent), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Track reload calls
	var reloadCount int32

	// Create reload function that increments counter
	reloadFunc := func() error {
		atomic.AddInt32(&reloadCount, 1)
		return nil
	}

	// Create a config watcher with short interval for testing
	watcher := NewConfigWatcher(100) // 100ms interval

	// Add file to watcher
	if err := watcher.AddFile(tempFile, reloadFunc); err != nil {
		t.Fatalf("Failed to add file to watcher: %v", err)
	}

	// Wait a short period to ensure initial monitoring is set up
	time.Sleep(200 * time.Millisecond)

	// Initial load should not trigger reload
	if count := atomic.LoadInt32(&reloadCount); count != 0 {
		t.Errorf("Expected 0 reloads initially, got %d", count)
	}

	// Modify the file
	newContent := "updated content"
	if err := os.WriteFile(tempFile, []byte(newContent), 0o644); err != nil {
		t.Fatalf("Failed to update test file: %v", err)
	}

	// Wait for reload to be triggered
	time.Sleep(500 * time.Millisecond)

	// Check if reload was triggered
	if count := atomic.LoadInt32(&reloadCount); count != 1 {
		t.Errorf("Expected 1 reload after file change, got %d", count)
	}

	// Modify the file again
	newerContent := "newer content"
	if err := os.WriteFile(tempFile, []byte(newerContent), 0o644); err != nil {
		t.Fatalf("Failed to update test file again: %v", err)
	}

	// Wait for second reload to be triggered
	time.Sleep(500 * time.Millisecond)

	// Check if second reload was triggered
	if count := atomic.LoadInt32(&reloadCount); count != 2 {
		t.Errorf("Expected 2 reloads after second file change, got %d", count)
	}

	// Test that rapid changes are debounced
	for i := 0; i < 5; i++ {
		content := []byte(fmt.Sprintf("%d content", i))
		if err := os.WriteFile(tempFile, content, 0o644); err != nil {
			t.Fatalf("Failed to update test file in loop: %v", err)
		}
		time.Sleep(10 * time.Millisecond) // Very small delay between writes
	}

	// Wait for reload to be triggered
	time.Sleep(500 * time.Millisecond)

	// Should be at most one or two additional reloads, not 5
	finalCount := atomic.LoadInt32(&reloadCount)
	if finalCount < 3 || finalCount > 4 {
		t.Errorf("Expected 3-4 total reloads after rapid changes (debouncing), got %d", finalCount)
	}

	// Test removing file from watcher
	watcher.RemoveFile(tempFile)

	// Reset count
	atomic.StoreInt32(&reloadCount, 0)

	// Modify the file again
	if err := os.WriteFile(tempFile, []byte("final content"), 0o644); err != nil {
		t.Fatalf("Failed to update test file after removal: %v", err)
	}

	// Wait to see if reload is triggered
	time.Sleep(500 * time.Millisecond)

	// No reload should happen after removal
	if count := atomic.LoadInt32(&reloadCount); count != 0 {
		t.Errorf("Expected 0 reloads after file removal from watcher, got %d", count)
	}

	// Clean up
	watcher.Shutdown()
}
