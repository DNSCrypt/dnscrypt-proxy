package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestServersInfo() *ServersInfo {
	s := NewServersInfo()
	return &s
}

func TestBeginODoHRefreshFirstCallSucceeds(t *testing.T) {
	s := newTestServersInfo()
	if !s.beginODoHRefresh("server-a", 10*time.Second) {
		t.Fatal("first claim should succeed")
	}
	s.endODoHRefresh("server-a", true)
}

func TestBeginODoHRefreshCoalescesInFlight(t *testing.T) {
	s := newTestServersInfo()
	if !s.beginODoHRefresh("server-a", 10*time.Second) {
		t.Fatal("first claim should succeed")
	}
	if s.beginODoHRefresh("server-a", 10*time.Second) {
		t.Fatal("second claim should be denied while a refresh is in flight")
	}
	s.endODoHRefresh("server-a", true)
	if !s.beginODoHRefresh("server-a", 10*time.Second) {
		t.Fatal("claim should succeed again after the in-flight slot is released on success")
	}
	s.endODoHRefresh("server-a", true)
}

func TestBeginODoHRefreshFailureCooldown(t *testing.T) {
	s := newTestServersInfo()
	if !s.beginODoHRefresh("server-a", time.Hour) {
		t.Fatal("first claim should succeed")
	}
	s.endODoHRefresh("server-a", false)
	if s.beginODoHRefresh("server-a", time.Hour) {
		t.Fatal("claim should be denied within the failure cooldown")
	}
	if !s.beginODoHRefresh("server-a", time.Nanosecond) {
		t.Fatal("claim should succeed once the failure cooldown has elapsed")
	}
	s.endODoHRefresh("server-a", false)
}

func TestEndODoHRefreshSuccessClearsCooldown(t *testing.T) {
	s := newTestServersInfo()
	if !s.beginODoHRefresh("server-a", time.Hour) {
		t.Fatal("first claim should succeed")
	}
	s.endODoHRefresh("server-a", false)
	s.odohRefreshMu.Lock()
	_, stamped := s.odohLastFailureAt["server-a"]
	s.odohRefreshMu.Unlock()
	if !stamped {
		t.Fatal("a failed refresh should stamp the failure timestamp")
	}
	if !s.beginODoHRefresh("server-a", time.Nanosecond) {
		t.Fatal("claim should succeed once the failure cooldown has elapsed")
	}
	s.endODoHRefresh("server-a", true)
	s.odohRefreshMu.Lock()
	_, stillStamped := s.odohLastFailureAt["server-a"]
	s.odohRefreshMu.Unlock()
	if stillStamped {
		t.Fatal("a successful refresh should clear the failure timestamp")
	}
	if !s.beginODoHRefresh("server-a", time.Hour) {
		t.Fatal("claim should succeed immediately after a successful refresh, even within a long cooldown")
	}
	s.endODoHRefresh("server-a", true)
}

func TestBeginODoHRefreshOnZeroValueDoesNotPanic(t *testing.T) {
	var s ServersInfo
	if !s.beginODoHRefresh("server-a", time.Second) {
		t.Fatal("first claim on a zero-value ServersInfo should succeed (lazy map init)")
	}
	s.endODoHRefresh("server-a", false)
	if s.beginODoHRefresh("server-a", time.Hour) {
		t.Fatal("failure cooldown should be active after endODoHRefresh(false)")
	}
}

func TestCancelODoHRefreshDoesNotStampFailure(t *testing.T) {
	s := newTestServersInfo()
	if !s.beginODoHRefresh("server-a", time.Hour) {
		t.Fatal("first claim should succeed")
	}
	s.cancelODoHRefresh("server-a")
	s.odohRefreshMu.Lock()
	_, stamped := s.odohLastFailureAt["server-a"]
	inFlight := s.odohRefreshInFlight["server-a"]
	s.odohRefreshMu.Unlock()
	if stamped {
		t.Fatal("cancel must not stamp a failure timestamp")
	}
	if inFlight {
		t.Fatal("cancel must release the in-flight slot")
	}
	if !s.beginODoHRefresh("server-a", time.Hour) {
		t.Fatal("a fresh claim should be available immediately after cancel")
	}
	s.endODoHRefresh("server-a", true)
}

func TestBeginODoHRefreshIsPerName(t *testing.T) {
	s := newTestServersInfo()
	if !s.beginODoHRefresh("server-a", time.Hour) {
		t.Fatal("server-a claim should succeed")
	}
	if !s.beginODoHRefresh("server-b", time.Hour) {
		t.Fatal("server-b claim should succeed independently of server-a")
	}
	s.endODoHRefresh("server-a", true)
	s.endODoHRefresh("server-b", false)
}

func TestBeginODoHRefreshConcurrentClaims(t *testing.T) {
	s := newTestServersInfo()
	const goroutines = 64
	var wins int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-start
			if s.beginODoHRefresh("server-a", time.Hour) {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := atomic.LoadInt64(&wins); got != 1 {
		t.Fatalf("expected exactly one winning claim under concurrency, got %d", got)
	}
}
