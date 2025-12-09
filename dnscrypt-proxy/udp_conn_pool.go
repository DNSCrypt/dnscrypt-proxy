package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedisct1/dlog"
)

const (
	UDPPoolMaxConnsPerAddr = 4
	UDPPoolMaxIdleTime     = 30 * time.Second
	UDPPoolCleanupInterval = 10 * time.Second
	UDPPoolShards          = 64
)

type pooledConn struct {
	conn     *net.UDPConn
	lastUsed time.Time
}

type poolShard struct {
	sync.Mutex
	conns map[string][]*pooledConn
}

type UDPConnPool struct {
	shards   [UDPPoolShards]poolShard
	closed   int32 // atomic
	stopOnce sync.Once
	stopCh   chan struct{}
}

func NewUDPConnPool() *UDPConnPool {
	pool := &UDPConnPool{
		stopCh: make(chan struct{}),
	}
	for i := range pool.shards {
		pool.shards[i].conns = make(map[string][]*pooledConn)
	}
	go pool.cleanupLoop()
	return pool
}

func (p *UDPConnPool) getShard(addr string) *poolShard {
	h := uint32(0)
	for i := 0; i < len(addr); i++ {
		h = h*31 + uint32(addr[i])
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
	now := time.Now()
	for i := range p.shards {
		shard := &p.shards[i]
		shard.Lock()
		for addr, conns := range shard.conns {
			var active []*pooledConn
			for _, pc := range conns {
				if now.Sub(pc.lastUsed) > UDPPoolMaxIdleTime {
					pc.conn.Close()
					dlog.Debugf("UDP pool: closed stale connection to %s", addr)
				} else {
					active = append(active, pc)
				}
			}
			if len(active) == 0 {
				delete(shard.conns, addr)
			} else {
				shard.conns[addr] = active
			}
		}
		shard.Unlock()
	}
}

func (p *UDPConnPool) Get(addr *net.UDPAddr) (*net.UDPConn, error) {
	addrStr := addr.String()
	shard := p.getShard(addrStr)

	shard.Lock()
	conns := shard.conns[addrStr]
	if len(conns) > 0 {
		pc := conns[len(conns)-1]
		shard.conns[addrStr] = conns[:len(conns)-1]
		shard.Unlock()
		pc.conn.SetReadDeadline(time.Time{})
		pc.conn.SetWriteDeadline(time.Time{})
		return pc.conn, nil
	}
	shard.Unlock()

	return net.DialUDP("udp", nil, addr)
}

func (p *UDPConnPool) Put(addr *net.UDPAddr, conn *net.UDPConn) {
	if conn == nil {
		return
	}
	if atomic.LoadInt32(&p.closed) != 0 {
		conn.Close()
		return
	}

	addrStr := addr.String()
	shard := p.getShard(addrStr)

	shard.Lock()
	conns := shard.conns[addrStr]
	if len(conns) >= UDPPoolMaxConnsPerAddr {
		shard.Unlock()
		conn.Close()
		return
	}
	shard.conns[addrStr] = append(conns, &pooledConn{
		conn:     conn,
		lastUsed: time.Now(),
	})
	shard.Unlock()
}

func (p *UDPConnPool) Discard(conn *net.UDPConn) {
	if conn != nil {
		conn.Close()
	}
}

func (p *UDPConnPool) Close() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
	})
	atomic.StoreInt32(&p.closed, 1)

	for i := range p.shards {
		shard := &p.shards[i]
		shard.Lock()
		for addr, conns := range shard.conns {
			for _, pc := range conns {
				pc.conn.Close()
			}
			delete(shard.conns, addr)
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
