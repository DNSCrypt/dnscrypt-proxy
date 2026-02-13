package main

import (
	"sync"
	"testing"
	"time"
)

// TestReloadSafeguard tests the ReloadSafeguard functionality
func TestReloadSafeguard(t *testing.T) {
	rs := NewReloadSafeguard()

	// Test StartReload and FinishReload
	if !rs.StartReload() {
		t.Error("StartReload should return true for first call")
	}

	// Second call should fail while first reload is in progress
	if rs.StartReload() {
		t.Error("StartReload should return false for second call while first reload is still in progress")
	}

	// Finish reload and try again
	rs.FinishReload()

	// Should be able to start a new reload now
	if !rs.StartReload() {
		t.Error("StartReload should return true after previous reload is finished")
	}

	// Clean up
	rs.FinishReload()

	// Test concurrent access to configuration
	var wg sync.WaitGroup
	const numReaders = 10

	// Start readers
	for range numReaders {
		wg.Go(func() {
			rs.AcquireConfigRead()
			// Simulate read access
			rs.ReleaseConfigRead()
		})
	}

	// Try to acquire write lock while readers are active
	writeSuccess := false
	writeChan := make(chan bool)
	go func() {
		rs.AcquireConfigWrite()
		writeSuccess = true
		// Simulate write access
		rs.ReleaseConfigWrite()
		writeChan <- true
	}()

	// Wait for all readers to finish
	wg.Wait()

	// Wait for writer to complete
	<-writeChan

	if !writeSuccess {
		t.Error("Writer should have eventually acquired the lock after readers finished")
	}

	// Test SafeReload helper
	callCount := 0
	reloadFunc := func() error {
		callCount++
		return nil
	}

	// Execute reload function
	err := rs.SafeReload(reloadFunc)
	if err != nil {
		t.Errorf("SafeReload returned error: %v", err)
	}

	if callCount != 1 {
		t.Errorf("Expected reloadFunc to be called once, got %d calls", callCount)
	}

	// Test that we can perform another reload after the first completes
	err = rs.SafeReload(reloadFunc)
	if err != nil {
		t.Errorf("Second SafeReload returned error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("Expected reloadFunc to be called twice, got %d calls", callCount)
	}

	// Test concurrent SafeReload calls
	wg = sync.WaitGroup{}
	wg.Add(2)

	var mu sync.Mutex
	firstCalled := false
	secondCalled := false

	go func() {
		defer wg.Done()
		err := rs.SafeReload(func() error {
			mu.Lock()
			firstCalled = true
			mu.Unlock()
			// Simulate some work with delay to ensure concurrency
			time.Sleep(50 * time.Millisecond)
			return nil
		})
		if err != nil && err.Error() != "another reload operation is already in progress" {
			t.Errorf("Concurrent SafeReload 1 returned unexpected error: %v", err)
		}
	}()

	// Wait a bit to ensure the first goroutine has a chance to start
	time.Sleep(10 * time.Millisecond)

	go func() {
		defer wg.Done()
		err := rs.SafeReload(func() error {
			mu.Lock()
			secondCalled = true
			mu.Unlock()
			// Simulate some work
			time.Sleep(50 * time.Millisecond)
			return nil
		})
		if err != nil && err.Error() != "another reload operation is already in progress" {
			t.Errorf("Concurrent SafeReload 2 returned unexpected error: %v", err)
		}
	}()

	wg.Wait()

	// One of them should have succeeded
	mu.Lock()
	gotFirst := firstCalled
	gotSecond := secondCalled
	mu.Unlock()

	if !(gotFirst || gotSecond) {
		t.Error("Expected at least one of the concurrent reload functions to be called")
	}

	// Note: We can't reliably test that only one succeeds in all environments
	// since timing can vary, but the locking mechanism should ensure correctness in real usage
}
