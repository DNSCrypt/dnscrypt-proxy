package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedisct1/dlog"
)

const (
	UDPPoolMaxConnsPerAddr = 1000
	UDPPoolMaxIdleTime     = 360 * time.Second
	UDPPoolCleanupInterval = 10 * time.Second
	UDPPoolShards          = 64
)

type pooledConn struct {
	conn     *net.UDPConn
	lastUsed int64 // unix nanos
}

type poolShard struct {
	sync.Mutex
	conns map[string][]pooledConn
}

type UDPConnPool struct {
	shards   [UDPPoolShards]poolShard
	closed   int32 // atomic
	stopOnce sync.Once
	stopCh   chan struct{}
}

func NewUDPConnPool() *UDPConnPool {
	pool := &UDPConnPool{stopCh: make(chan struct{})}
	for i := range pool.shards {
		pool.shards[i].conns = make(map[string][]pooledConn)
	}
	go pool.cleanupLoop()
	return pool
}

func (p *UDPConnPool) getShard(key string) *poolShard {
	h := uint32(0)
	for i := 0; i < len(key); i++ {
		h = h*31 + uint32(key[i])
	}
	return &p.shards[h%UDPPoolShards]
}

func (p *UDPConnPool) cleanupLoop() {
	ticker := time.NewTicker(UDPPoolCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.cleanupStale()
		case <-p.stopCh:
			return
		}
	}
}

func (p *UDPConnPool) cleanupStale() {
	now := time.Now().UnixNano()
	maxIdle := int64(UDPPoolMaxIdleTime)
	for i := range p.shards {
		shard := &p.shards[i]
		shard.Lock()
		for key, conns := range shard.conns {
			n := 0
			for _, pc := range conns {
				if now-pc.lastUsed > maxIdle {
					_ = pc.conn.Close()
					dlog.Debugf("UDP pool: closed stale connection to %s", key)
					continue
				}
				conns[n] = pc
				n++
			}
			if n == 0 {
				delete(shard.conns, key)
			} else {
				shard.conns[key] = conns[:n]
			}
		}
		shard.Unlock()
	}
}

func (p *UDPConnPool) GetNet(network string, addr *net.UDPAddr) (*net.UDPConn, error) {
	key := network + "|" + addr.String()
	shard := p.getShard(key)
	shard.Lock()
	conns := shard.conns[key]
	if len(conns) > 0 {
		pc := conns[len(conns)-1]
		shard.conns[key] = conns[:len(conns)-1]
		shard.Unlock()
		_ = pc.conn.SetReadDeadline(time.Time{})
		_ = pc.conn.SetWriteDeadline(time.Time{})
		return pc.conn, nil
	}
	shard.Unlock()
	return net.DialUDP(network, nil, addr)
}

func (p *UDPConnPool) PutNet(network string, addr *net.UDPAddr, conn *net.UDPConn) {
	if conn == nil {
		return
	}
	if atomic.LoadInt32(&p.closed) != 0 {
		_ = conn.Close()
		return
	}
	key := network + "|" + addr.String()
	shard := p.getShard(key)
	shard.Lock()
	conns := shard.conns[key]
	if len(conns) >= UDPPoolMaxConnsPerAddr {
		shard.Unlock()
		_ = conn.Close()
		return
	}
	shard.conns[key] = append(conns, pooledConn{conn: conn, lastUsed: time.Now().UnixNano()})
	shard.Unlock()
}

// Backwards-compatible wrappers.
func (p *UDPConnPool) Get(addr *net.UDPAddr) (*net.UDPConn, error) { return p.GetNet("udp", addr) }
func (p *UDPConnPool) Put(addr *net.UDPAddr, conn *net.UDPConn) { p.PutNet("udp", addr, conn) }

func (p *UDPConnPool) Discard(conn *net.UDPConn) {
	if conn != nil {
		_ = conn.Close()
	}
}

func (p *UDPConnPool) Close() {
	p.stopOnce.Do(func() { close(p.stopCh) })
	atomic.StoreInt32(&p.closed, 1)
	for i := range p.shards {
		shard := &p.shards[i]
		shard.Lock()
		for key, conns := range shard.conns {
			for _, pc := range conns {
				_ = pc.conn.Close()
			}
			delete(shard.conns, key)
		}
		shard.Unlock()
	}
	dlog.Debug("UDP connection pool closed")
}

func (p *UDPConnPool) Stats() (totalConns int, addrCount int) {
	for i := range p.shards {
		shard := &p.shards[i]
		shard.Lock()
		addrCount += len(shard.conns)
		for _, conns := range shard.conns {
			totalConns += len(conns)
		}
		shard.Unlock()
	}
	return
}
