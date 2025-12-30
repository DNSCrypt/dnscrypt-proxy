package main

import (
    "encoding/binary"
    "net"
    "sync"
    "sync/atomic"
    "time"

    "github.com/jedisct1/dlog"
)

// UDPPoolConfig allows tuning for specific network environments
type UDPPoolConfig struct {
    MaxConnsPerAddr int
    MaxIdleTime     time.Duration
    CleanupInterval time.Duration
}

// DefaultUDPPoolConfig optimizes for general high-throughput
func DefaultUDPPoolConfig() UDPPoolConfig {
    return UDPPoolConfig{
        MaxConnsPerAddr: 1000,
        MaxIdleTime:     120 * time.Second, // Lowered to 120s for safer NAT traversal
        CleanupInterval: 10 * time.Second,
    }
}

type pooledConn struct {
    conn     *net.UDPConn
    lastUsed int64 // unix nanos
}

type connKey struct {
    ip   [16]byte
    port int
    zone string
    net  string
}

type poolShard struct {
    sync.Mutex
    conns map[connKey][]pooledConn
    // Padding to prevent false sharing on cache lines.
    // sync.Mutex (8) + map (8) = 16 bytes.
    // Padding fills the remaining 48 bytes of a 64-byte cache line.
    _ [48]byte
}

type UDPConnPool struct {
    // 1. Hot Fields Grouping: Kept in a single cache line to minimize misses.
    // Stats placed first to ensure 64-bit alignment on 32-bit architectures.
    stats struct {
        Hits      int64
        Misses    int64
        Evicted   int64
        TotalOpen int64
    }

    // Coarse-grained timestamp to avoid time.Now() syscalls in hot paths
    now int64 

    closed int32
    stopCh chan struct{}
    once   sync.Once

    config UDPPoolConfig

    // Padding ensures shards start on a fresh cache line, avoiding false sharing
    // with the frequently updated stats/timer fields.
    _ [64]byte

    shards [64]poolShard
}

// NewUDPConnPool creates a pool with default optimized settings.
func NewUDPConnPool() *UDPConnPool {
    pool := &UDPConnPool{
        config: DefaultUDPPoolConfig(),
        stopCh: make(chan struct{}),
    }
    // Initialize atomic timestamp immediately
    atomic.StoreInt64(&pool.now, time.Now().UnixNano())

    for i := range pool.shards {
        pool.shards[i].conns = make(map[connKey][]pooledConn)
    }
    go pool.loop()
    return pool
}

// getShard uses unrolled FNV-1a hashing for maximum speed
func (p *UDPConnPool) getShard(key *connKey) *poolShard {
    h := uint32(2166136261)
    
    // Hash IP (16 bytes) using 2x 64-bit reads
    v1 := binary.LittleEndian.Uint64(key.ip[:8])
    h = (h ^ uint32(v1)) * 16777619
    h = (h ^ uint32(v1>>32)) * 16777619

    v2 := binary.LittleEndian.Uint64(key.ip[8:])
    h = (h ^ uint32(v2)) * 16777619
    h = (h ^ uint32(v2>>32)) * 16777619

    h = (h ^ uint32(key.port)) * 16777619
    
    return &p.shards[h&(uint32(len(p.shards))-1)]
}

func (p *UDPConnPool) makeKey(network string, addr *net.UDPAddr) connKey {
    k := connKey{
        net:  network,
        port: addr.Port,
        zone: addr.Zone,
    }
    ip := addr.IP
    // Zero-allocation IP normalization.
    if len(ip) == 4 {
        k.ip[10] = 0xff
        k.ip[11] = 0xff
        copy(k.ip[12:], ip)
    } else if len(ip) == 16 {
        copy(k.ip[:], ip)
    }
    return k
}

// loop handles both time updates and connection cleanup
func (p *UDPConnPool) loop() {
    cleanupTicker := time.NewTicker(p.config.CleanupInterval)
    timeTicker := time.NewTicker(1 * time.Second)
    defer cleanupTicker.Stop()
    defer timeTicker.Stop()

    for {
        select {
        case <-timeTicker.C:
            // Update coarse time lock-free
            atomic.StoreInt64(&p.now, time.Now().UnixNano())
        
        case <-cleanupTicker.C:
            p.cleanupStale()
        
        case <-p.stopCh:
            return
        }
    }
}

func (p *UDPConnPool) cleanupStale() {
    // Use cached time to avoid syscalls
    now := atomic.LoadInt64(&p.now)
    maxIdle := int64(p.config.MaxIdleTime)
    var toClose []*net.UDPConn

    for i := range p.shards {
        shard := &p.shards[i]
        shard.Lock()

        for key, conns := range shard.conns {
            n := 0
            for _, pc := range conns {
                if now-pc.lastUsed > maxIdle {
                    toClose = append(toClose, pc.conn)
                    continue
                }
                conns[n] = pc
                n++
            }

            if n == 0 {
                delete(shard.conns, key)
            } else {
                // Memory Hygiene: Shrink slice if capacity is too large
                if cap(conns) > 64 && n < cap(conns)/4 {
                    newConns := make([]pooledConn, n)
                    copy(newConns, conns[:n])
                    shard.conns[key] = newConns
                } else {
                    // Nil out unused slots to help GC
                    for k := n; k < len(conns); k++ {
                        conns[k] = pooledConn{}
                    }
                    shard.conns[key] = conns[:n]
                }
            }
        }
        shard.Unlock()
    }

    if len(toClose) > 0 {
        atomic.AddInt64(&p.stats.Evicted, int64(len(toClose)))
        atomic.AddInt64(&p.stats.TotalOpen, -int64(len(toClose)))
        for _, conn := range toClose {
            _ = conn.Close()
        }
        dlog.Debugf("UDP pool: evicted %d stale connections", len(toClose))
    }
}

func (p *UDPConnPool) GetNet(network string, addr *net.UDPAddr) (*net.UDPConn, error) {
    key := p.makeKey(network, addr)
    shard := p.getShard(&key)

    shard.Lock()
    conns := shard.conns[key]
    if n := len(conns); n > 0 {
        pc := conns[n-1]
        conns[n-1] = pooledConn{} // Zero out to avoid leak
        shard.conns[key] = conns[:n-1]
        shard.Unlock()

        atomic.AddInt64(&p.stats.Hits, 1)

        // Optimization: SetDeadline syscalls removed.
        // Caller MUST set a deadline before reading.
        return pc.conn, nil
    }
    shard.Unlock()

    atomic.AddInt64(&p.stats.Misses, 1)
    conn, err := net.DialUDP(network, nil, addr)
    if err == nil {
        atomic.AddInt64(&p.stats.TotalOpen, 1)
    }
    return conn, err
}

func (p *UDPConnPool) PutNet(network string, addr *net.UDPAddr, conn *net.UDPConn) {
    if conn == nil {
        return
    }
    if atomic.LoadInt32(&p.closed) != 0 {
        _ = conn.Close()
        atomic.AddInt64(&p.stats.TotalOpen, -1)
        return
    }

    key := p.makeKey(network, addr)
    shard := p.getShard(&key)

    shard.Lock()
    if atomic.LoadInt32(&p.closed) != 0 {
        shard.Unlock()
        _ = conn.Close()
        atomic.AddInt64(&p.stats.TotalOpen, -1)
        return
    }

    conns := shard.conns[key]
    if len(conns) >= p.config.MaxConnsPerAddr {
        shard.Unlock()
        _ = conn.Close()
        atomic.AddInt64(&p.stats.TotalOpen, -1)
        return
    }

    // Use lock-free coarse time
    now := atomic.LoadInt64(&p.now)
    shard.conns[key] = append(conns, pooledConn{conn: conn, lastUsed: now})
    shard.Unlock()
}

func (p *UDPConnPool) Close() {
    p.once.Do(func() {
        close(p.stopCh)
        atomic.StoreInt32(&p.closed, 1)

        for i := range p.shards {
            shard := &p.shards[i]
            shard.Lock()
            for _, conns := range shard.conns {
                for _, pc := range conns {
                    _ = pc.conn.Close()
                }
            }
            shard.conns = nil
            shard.Unlock()
        }
        dlog.Debug("UDP connection pool closed")
    })
}

// Stats returns a snapshot of the pool metrics (Lock-Free)
func (p *UDPConnPool) Stats() map[string]int64 {
    return map[string]int64{
        "hits":       atomic.LoadInt64(&p.stats.Hits),
        "misses":     atomic.LoadInt64(&p.stats.Misses),
        "evicted":    atomic.LoadInt64(&p.stats.Evicted),
        "total_open": atomic.LoadInt64(&p.stats.TotalOpen),
    }
}

// Helpers
func (p *UDPConnPool) Get(addr *net.UDPAddr) (*net.UDPConn, error) { return p.GetNet("udp", addr) }
func (p *UDPConnPool) Put(addr *net.UDPAddr, conn *net.UDPConn)    { p.PutNet("udp", addr, conn) }
func (p *UDPConnPool) Discard(conn *net.UDPConn) {
    if conn != nil {
        _ = conn.Close()
        atomic.AddInt64(&p.stats.TotalOpen, -1)
    }
}
