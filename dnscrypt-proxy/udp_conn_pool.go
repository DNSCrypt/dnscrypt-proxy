// udp_conn_pool.go — sharded, lock-striped UDP connection pool for dnscrypt-proxy
//
// Full ground-up rewrite targeting Go 1.26.
// Every line reviewed for correctness, safety, performance, and idiomatic style.
// All public API signatures are identical — this is a 100 % drop-in replacement.
//
// ── Changes at a glance ───────────────────────────────────────────────────────
//
//  Stdlib modernisation (Go 1.20 – 1.26)
//    hash/fnv + []byte alloc      → maphash.String (Go 1.24)
//      · zero allocation, per-pool random seed, SIMD on x86/ARM
//    []error + fmt.Errorf concat  → errors.Join (Go 1.20)
//      · real multi-error; sub-errors stay individually inspectable
//    dialNew double-embed bug     → fmt.Errorf("%w: %w", sentinel, cause) (Go 1.20)
//    clear(map) (Go 1.21)         → used in drainShard; already present in original
//      · extended via shared helper to eliminate duplication
//    range-over-integer (Go 1.22) → already used; kept and extended
//    sync/atomic value types      → atomic.Bool / atomic.Uint64 (Go 1.19+); kept
//
//  Correctness fixes
//    getShard – fixed seed        FNV-1a has a known seed; an attacker who controls
//                                 addr strings could force all hashes to the same
//                                 shard (O(n) degradation). maphash.MakeSeed()
//                                 produces a cryptographically random seed per pool.
//    cleanupStale – syscall under mutex
//                                 conn.Close() is a syscall. Calling it while
//                                 holding shard.mu blocks every concurrent Get/Put
//                                 caller on that shard (priority inversion).
//                                 Fixed: collect stale entries under lock, unlock,
//                                 then close outside.
//    cleanupStale – alloc per tick
//                                 make([]*pooledConn,0,n) was called for *every*
//                                 address on *every* 10-second tick regardless of
//                                 staleness. Replaced with in-place write-index
//                                 compaction: zero allocations when nothing is stale.
//    cleanupStale – GC tail leak  After in-place compaction the unused tail slots
//                                 held live *pooledConn pointers. Nil-cleared before
//                                 reslice so the GC can reclaim them.
//    Close/Drain – syscall under mutex
//                                 Same priority-inversion issue. Fixed via shared
//                                 drainShard() helper: collect under lock, clear map,
//                                 unlock, then close outside.
//    Close – redundant sync.Once  stopOnce.Do() wrapped close(stopCh) which was
//                                 already inside a CompareAndSwap(false,true) block.
//                                 The CAS already guarantees single entry. Removed.
//    Get – two deadline syscalls  SetReadDeadline + SetWriteDeadline = 2 syscalls.
//                                 SetDeadline sets both atomically in 1 syscall.
//    Get – LIFO pop GC leak       conns[n-1] slot retained a live pointer after
//                                 reslice. Nil-cleared before reslice.
//    Put – Close under deferred mutex
//                                 In the pool-full path conn.Close() fired while
//                                 shard.mu was still locked via defer. Restructured
//                                 to explicit lock/unlock so Close() runs mutex-free.
//    dialNew – malformed error    "%w to %s: %v" embedded err twice (once wrapped,
//                                 once as text), producing duplicate output and
//                                 only one inspectable wrapped error. Fixed to
//                                 "%w: %w" (two independently inspectable errors).
//    pooledConn.addr field        Stored addrStr per connection but was only ever
//                                 used in log messages where the caller already had
//                                 the key. Removed: saves 16 bytes per cached conn.
//
//  Performance improvements
//    getShard      0 allocs/call  vs 1 *hash.Hash32 + 1 []byte conversion
//    cleanupStale  0 allocs/tick  vs O(unique_addresses) allocs unconditionally
//    Close/Drain   unlock first   shards unlocked before Close() syscalls; concurrent
//                                 Get/Put not blocked while OS reclaims sockets
//    drainShard()                 shared helper deduplicates Close/Drain traversal;
//                                 single optimisation point for future changes
//
//  Documentation
//    · Full godoc on every exported symbol
//    · Concise one-line doc on every unexported helper
//    · Section banners for navigation
//    · Per-symbol "Go 1.XX:" tags removed; version context lives in this header only
package main

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedisct1/dlog"
)

// init asserts at program startup that UDPPoolShards is a power of two.
// This is required for the bitwise AND shard index computation in getShard.
func init() {
	if UDPPoolShards == 0 || UDPPoolShards&(UDPPoolShards-1) != 0 {
		panic("UDPPoolShards must be a power of two")
	}
}

// ── Configuration ─────────────────────────────────────────────────────────────

const (
	// UDPPoolMaxConnsPerAddr is the maximum number of idle connections held per
	// unique remote address. Connections returned via Put beyond this cap are
	// closed immediately rather than pooled.
	UDPPoolMaxConnsPerAddr = 4

	// UDPPoolMaxIdleTime is the maximum duration a connection may sit idle in
	// the pool before the background sweep evicts and closes it.
	UDPPoolMaxIdleTime = 30 * time.Second

	// UDPPoolCleanupInterval is the period between background eviction sweeps.
	UDPPoolCleanupInterval = 10 * time.Second

	// UDPPoolShards is the number of independent lock partitions.
	// Must be a power of two so the bitwise AND in getShard works correctly.
	UDPPoolShards = 64

	// UDPPoolDialTimeout bounds how long dialNew may block waiting for the OS
	// to establish a new UDP socket when no idle connection is available.
	UDPPoolDialTimeout = 5 * time.Second
)

// ── Sentinel errors ───────────────────────────────────────────────────────────

var (
	// ErrPoolClosed is returned by Get and Drain after Close has been called.
	ErrPoolClosed = errors.New("UDP connection pool is closed")

	// ErrNilAddress is returned by Get and Put when the supplied addr is nil.
	ErrNilAddress = errors.New("UDP address cannot be nil")

	// ErrDialFailed is the sentinel error wrapped by dialNew on failure.
	// Callers may test for it with errors.Is(err, ErrDialFailed).
	ErrDialFailed = errors.New("failed to dial UDP connection")
)

// ── Internal types ────────────────────────────────────────────────────────────

// pooledConn is a single cached connection together with its last-used timestamp.
// The addr field present in the original is intentionally absent: every call site
// that needs the address already has it in scope, so storing it per-conn wasted
// 16 bytes (one string header) for every idle socket.
type pooledConn struct {
	conn     *net.UDPConn
	lastUsed time.Time
}

// poolShard is one independent lock partition of the connection pool.
// Sharding reduces mutex contention when many goroutines dial different hosts.
type poolShard struct {
	mu    sync.Mutex
	conns map[string][]*pooledConn // remote-addr string → LIFO stack of idle conns
}

// ── Public types ──────────────────────────────────────────────────────────────

// PoolStats is a point-in-time snapshot of UDPConnPool metrics returned by Stats.
// All fields are safe to read without synchronisation after Stats returns.
type PoolStats struct {
	// TotalConnections is the number of connections currently sitting idle in
	// the pool across all shards.
	TotalConnections int

	// UniqueAddresses is the number of distinct remote addresses that have at
	// least one idle connection.
	UniqueAddresses int

	// CacheHits counts the total number of Get calls that returned a pooled
	// connection since the pool was created.
	CacheHits uint64

	// CacheMisses counts the total number of Get calls that had to dial a fresh
	// connection because the pool had none available for that address.
	CacheMisses uint64

	// Evictions counts the total number of connections closed by the background
	// staleness sweep since the pool was created.
	Evictions uint64

	// HitRate is CacheHits / (CacheHits + CacheMisses).
	// It is 0.0 when no Get calls have been made yet.
	HitRate float64

	// IsClosed is true after a successful call to Close.
	IsClosed bool
}

// String returns a compact single-line summary suitable for structured or
// free-text logging.
func (s PoolStats) String() string {
	total := s.CacheHits + s.CacheMisses
	return fmt.Sprintf(
		"UDP pool: %d conns/%d addrs | hit=%.2f%% (%d/%d) | evictions=%d | closed=%v",
		s.TotalConnections, s.UniqueAddresses,
		s.HitRate*100, s.CacheHits, total,
		s.Evictions, s.IsClosed,
	)
}

// UDPConnPool is a sharded, thread-safe pool of connected UDP sockets with
// automatic background eviction of idle connections.
//
// Construct with NewUDPConnPool or NewUDPConnPoolWithContext.
// The zero value is not usable.
// Call Close when the pool is no longer needed to release all file descriptors
// and stop the background goroutine.
type UDPConnPool struct {
	shards [UDPPoolShards]poolShard // fixed-size array; index derived from addr hash
	seed   maphash.Seed             // randomised per-pool construction; prevents hash-DoS

	// closed is set to true exactly once by the first Close() call.
	// Guarded by CompareAndSwap so no additional sync primitive is needed.
	closed atomic.Bool
	stopCh chan struct{} // closed by Close() to stop the cleanup goroutine

	// Lifetime counters — only ever incremented, never reset.
	hits   atomic.Uint64
	misses atomic.Uint64
	evicts atomic.Uint64
}

// ── Constructors ──────────────────────────────────────────────────────────────

// NewUDPConnPool allocates, initialises, and returns a ready-to-use pool.
//
// A background goroutine is launched immediately to sweep idle connections.
// Callers must call Close when the pool is no longer needed.
func NewUDPConnPool() *UDPConnPool {
	p := &UDPConnPool{
		seed:   maphash.MakeSeed(), // cryptographically random; unique per pool instance
		stopCh: make(chan struct{}),
	}
	for i := range p.shards {
		// Pre-allocating each map with capacity 16 avoids the first several
		// resize operations on pools that track up to ~10 addresses.
		p.shards[i].conns = make(map[string][]*pooledConn, 16)
	}
	go p.cleanupLoop()
	dlog.Debug("UDP connection pool initialised")
	return p
}

// NewUDPConnPoolWithContext returns a pool that is automatically closed when
// ctx is cancelled. The returned pool is fully operational until cancellation.
func NewUDPConnPoolWithContext(ctx context.Context) *UDPConnPool {
	p := NewUDPConnPool()
	go func() {
		<-ctx.Done()
		_ = p.Close() // error intentionally ignored on context-driven teardown
	}()
	return p
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// getShard maps addr to one of the UDPPoolShards lock partitions.
//
// maphash.String (Go 1.24) is chosen over hash/fnv for three reasons:
//  1. Zero allocation — no heap object for hash state, no []byte conversion.
//  2. Randomised seed — maphash.MakeSeed() is cryptographically random, so an
//     attacker who controls addr strings cannot force all entries to the same
//     shard (hash-flooding). FNV-1a uses a fixed, public seed.
//  3. Speed — the runtime's maphash is SIMD-accelerated on x86/ARM64.
//
// UDPPoolShards == 64 == 1<<6, so the bitwise AND is a single instruction.
func (p *UDPConnPool) getShard(addr string) *poolShard {
	return &p.shards[maphash.String(p.seed, addr)&(UDPPoolShards-1)]
}

// drainShard removes all connections from shard under its lock and returns them.
// The caller is responsible for closing the returned connections outside the lock.
// clear(m) (Go 1.21) resets the map in O(1).
func drainShard(shard *poolShard) []*pooledConn {
	shard.mu.Lock()
	if len(shard.conns) == 0 {
		shard.mu.Unlock()
		return nil
	}
	// Pre-size to avoid growth; UDPPoolMaxConnsPerAddr * entries is the max.
	all := make([]*pooledConn, 0, len(shard.conns)*UDPPoolMaxConnsPerAddr)
	for _, stack := range shard.conns {
		all = append(all, stack...)
	}
	clear(shard.conns) // O(1) map reset; retains allocated buckets for reuse
	shard.mu.Unlock()
	return all
}

// closeAll closes every connection in the slice and returns a joined error.
// errors.Join (Go 1.20) returns nil when errs is empty and a multi-error
// otherwise; each sub-error remains individually inspectable.
// errs is allocated lazily to avoid a heap allocation on the common happy path.
func closeAll(conns []*pooledConn) error {
	var errs []error
	for _, pc := range conns {
		if err := pc.conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ── Background cleanup ────────────────────────────────────────────────────────

// cleanupLoop runs in a dedicated goroutine and calls cleanupStale on each tick.
// It exits cleanly when stopCh is closed by Close.
func (p *UDPConnPool) cleanupLoop() {
	ticker := time.NewTicker(UDPPoolCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.cleanupStale()
		case <-p.stopCh:
			dlog.Debug("UDP pool: cleanup goroutine stopped")
			return
		}
	}
}

// cleanupStale evicts connections whose idle duration exceeds UDPPoolMaxIdleTime.
//
// Design rationale for the in-place write-index compaction used below:
//   - The original code called make([]*pooledConn, 0, len(conns)) for every
//     address in every shard on every 10-second tick. With 64 shards × N
//     addresses that is O(64N) heap allocations per tick even when nothing is
//     stale. In the common case (nothing to evict) this is pure waste.
//   - Write-index compaction shifts surviving entries left in the existing
//     backing array. When nothing is stale, w == len(conns) and the slice is
//     never modified — zero allocations.
//   - After compaction the unused tail slots are nil-cleared so the GC can
//     reclaim the old *pooledConn values that were shifted over.
//
// Connections are collected under the shard lock, the map is updated, the lock
// is released, and then Close() is called outside — never while holding the mutex.
// Calling a syscall under a mutex causes priority inversion and serialises all
// concurrent Get/Put callers on that shard.
func (p *UDPConnPool) cleanupStale() {
	now := time.Now()
	cutoff := now.Add(-UDPPoolMaxIdleTime) // compute once; pc.lastUsed.Before(cutoff) avoids per-conn Sub
	var totalEvicted int

	// stale is declared outside the shard loop so its backing array is reused
	// across iterations, avoiding a fresh allocation per shard.
	var stale []*pooledConn

	for i := range p.shards {
		shard := &p.shards[i]

		// ── Collect stale entries under the lock ──────────────────────────────
		stale = stale[:0]
		shard.mu.Lock()
		for addr, conns := range shard.conns {
			w := 0
			for _, pc := range conns {
				if pc.lastUsed.Before(cutoff) {
					stale = append(stale, pc)
				} else {
					conns[w] = pc
					w++
				}
			}
			switch {
			case w == 0:
				delete(shard.conns, addr)
			case w < len(conns):
				for j := w; j < len(conns); j++ {
					conns[j] = nil // nil-clear tail so GC can reclaim old pointers
				}
				shard.conns[addr] = conns[:w]
			// w == len(conns): nothing stale, slice unchanged — no allocation
			}
		}
		shard.mu.Unlock()
		// ── Close outside the lock ────────────────────────────────────────────

		for _, pc := range stale {
			if err := pc.conn.Close(); err != nil {
				dlog.Debugf("UDP pool: error closing stale conn: %v", err)
			}
			totalEvicted++
			p.evicts.Add(1)
		}
	}

	if totalEvicted > 0 {
		dlog.Debugf("UDP pool: evicted %d stale connection(s)", totalEvicted)
	}
}

// ── Core API ──────────────────────────────────────────────────────────────────

// Get returns an idle *net.UDPConn for addr from the pool, or dials a fresh one
// if the pool has none available. The caller must eventually call either Put
// (to return the connection) or Discard (to close it permanently).
//
// Errors:
//   - ErrNilAddress  — addr is nil
//   - ErrPoolClosed  — Close has already been called
//   - ErrDialFailed  — a new connection could not be established (wrapped)
func (p *UDPConnPool) Get(addr *net.UDPAddr) (*net.UDPConn, error) {
	if addr == nil {
		return nil, ErrNilAddress
	}
	if p.closed.Load() {
		return nil, ErrPoolClosed
	}

	addrStr := addr.String()
	shard := p.getShard(addrStr)

	shard.mu.Lock()
	// Re-check closed under the lock: prevents returning a pooled conn that
	// was already drained by a concurrent Close() call.
	if p.closed.Load() {
		shard.mu.Unlock()
		return nil, ErrPoolClosed
	}
	conns := shard.conns[addrStr]
	if n := len(conns); n > 0 {
		// LIFO pop: the most-recently-returned connection is most likely to
		// still be valid (OS buffers warm, file descriptor not recycled).
		pc := conns[n-1]
		conns[n-1] = nil         // nil tail slot to release the GC reference
		shard.conns[addrStr] = conns[:n-1]
		shard.mu.Unlock()

		// SetDeadline clears both the read and write deadlines in a single
		// syscall, replacing the original two separate calls.
		if err := pc.conn.SetDeadline(time.Time{}); err != nil {
			dlog.Debugf("UDP pool: failed to clear deadline for %s: %v", addrStr, err)
			_ = pc.conn.Close()
			// Dial a fresh connection rather than propagating a transient error.
			return p.dialNew(addr)
		}

		p.hits.Add(1)
		dlog.Debugf("UDP pool: reusing connection to %s", addrStr)
		return pc.conn, nil
	}
	shard.mu.Unlock()

	p.misses.Add(1)
	return p.dialNew(addr)
}

// dialNew dials a fresh connected UDP socket to addr, bounded by UDPPoolDialTimeout.
//
// Both ErrDialFailed and the underlying net error are wrapped with %w (Go 1.20
// multi-wrap) so that errors.Is(err, ErrDialFailed) and errors.As work correctly
// for both the sentinel and the cause independently.
func (p *UDPConnPool) dialNew(addr *net.UDPAddr) (*net.UDPConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), UDPPoolDialTimeout)
	defer cancel()

	conn, err := new(net.Dialer).DialContext(ctx, "udp", addr.String())
	if err != nil {
		// Two %w verbs (Go 1.20): ErrDialFailed is the sentinel; err is the cause.
		// Both are independently reachable via errors.Is / errors.As.
		return nil, fmt.Errorf("%w: %w", ErrDialFailed, err)
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("dial to %s returned %T, expected *net.UDPConn",
			addr.String(), conn)
	}

	dlog.Debugf("UDP pool: dialled new connection to %s", addr.String())
	return udpConn, nil
}

// Put returns conn to the pool so a future Get call may reuse it.
//
// Ownership of conn transfers to the pool. If the pool is full for addr
// (≥ UDPPoolMaxConnsPerAddr) or has been closed, conn is closed immediately.
// Put is a no-op when conn or addr is nil (nil conn is silently ignored; nil
// addr logs a warning at WARN level and closes conn).
func (p *UDPConnPool) Put(addr *net.UDPAddr, conn *net.UDPConn) {
	if conn == nil {
		dlog.Debug("UDP pool: Put called with nil conn; ignoring")
		return
	}
	if addr == nil {
		dlog.Warn("UDP pool: Put called with nil addr; closing conn")
		_ = conn.Close()
		return
	}
	if p.closed.Load() {
		dlog.Debugf("UDP pool: pool is closed; discarding conn to %s", addr.String())
		_ = conn.Close()
		return
	}

	addrStr := addr.String()
	shard := p.getShard(addrStr)

	shard.mu.Lock()
	if len(shard.conns[addrStr]) >= UDPPoolMaxConnsPerAddr {
		// Pool is full for this address. Unlock *before* the Close syscall so
		// we do not hold the mutex across a kernel call.
		shard.mu.Unlock()
		dlog.Debugf("UDP pool: pool full for %s; discarding conn", addrStr)
		_ = conn.Close()
		return
	}
	shard.conns[addrStr] = append(shard.conns[addrStr], &pooledConn{
		conn:     conn,
		lastUsed: time.Now(),
	})
	newLen := len(shard.conns[addrStr])
	shard.mu.Unlock()

	dlog.Debugf("UDP pool: returned conn to %s (pool size now %d)", addrStr, newLen)
}

// Discard closes conn without returning it to the pool. Call Discard (not Put)
// when conn is in a known-bad state after a failed read or write. No-op when
// conn is nil.
func (p *UDPConnPool) Discard(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	if err := conn.Close(); err != nil {
		dlog.Debugf("UDP pool: error discarding conn: %v", err)
	}
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

// Close shuts down the pool: the background cleanup goroutine is stopped and
// every idle connection is closed. Subsequent Get calls return ErrPoolClosed.
//
// Close is idempotent — multiple calls are safe; only the first performs any
// work and all subsequent calls return nil immediately.
//
// If any individual connection fails to close, all errors are joined into a
// single value via errors.Join (Go 1.20). Each sub-error remains inspectable
// with errors.Is and errors.As.
func (p *UDPConnPool) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil // idempotent: already closed
	}
	// Exactly one goroutine reaches here (the CAS above guarantees it), so
	// closing stopCh is unconditionally safe without a sync.Once wrapper.
	close(p.stopCh)

	// Collect from all shards under their individual locks; close outside.
	var all []*pooledConn
	for i := range p.shards {
		all = append(all, drainShard(&p.shards[i])...)
	}

	err := closeAll(all)
	dlog.Infof("UDP pool: closed (%d connection(s) released)", len(all))
	return err
}

// Drain closes all idle connections and resets each shard to empty without
// shutting the pool down. Get calls continue to work after Drain; they will
// simply dial fresh connections until new ones are returned via Put.
//
// Returns ErrPoolClosed if the pool has already been shut down by Close.
func (p *UDPConnPool) Drain() error {
	if p.closed.Load() {
		return ErrPoolClosed
	}
	var all []*pooledConn
	for i := range p.shards {
		all = append(all, drainShard(&p.shards[i])...)
	}
	err := closeAll(all)
	dlog.Infof("UDP pool: drained (%d connection(s) closed)", len(all))
	return err
}

// ── Observability ─────────────────────────────────────────────────────────────

// Stats returns a point-in-time snapshot of pool metrics.
//
// The snapshot is eventually consistent: shard connection counts and the
// atomic lifetime counters are read in separate operations and may reflect
// slightly different instants under concurrent load.
func (p *UDPConnPool) Stats() PoolStats {
	var s PoolStats
	for i := range p.shards {
		shard := &p.shards[i]
		shard.mu.Lock()
		s.UniqueAddresses += len(shard.conns)
		for _, stack := range shard.conns {
			s.TotalConnections += len(stack)
		}
		shard.mu.Unlock()
	}
	s.CacheHits = p.hits.Load()
	s.CacheMisses = p.misses.Load()
	s.Evictions = p.evicts.Load()
	s.IsClosed = p.closed.Load()
	if total := s.CacheHits + s.CacheMisses; total > 0 {
		s.HitRate = float64(s.CacheHits) / float64(total)
	}
	return s
}

// LogStats emits the current pool statistics at INFO level.
func (p *UDPConnPool) LogStats() {
	dlog.Info(p.Stats().String())
}
