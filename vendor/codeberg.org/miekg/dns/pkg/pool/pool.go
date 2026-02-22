package pool

import (
	"strings"
	"sync"
)

// Pooler is an interface that mimics a sync.Pool, but allows for different implementation.
type Pooler interface {
	// Get returns a (newly allocated) byte slice.
	Get() []byte
	// Put returns the byte slice. This uses cap to determine the size of the buffer.
	Put([]byte)
}

// Pool is the default pool used. The allocation size used is [server.UDPSize], if TCP allocations stay below
// this value too, it is also used for that, otherwise they escape and are garbage collected.
type Pool struct {
	size int
	pool sync.Pool
}

func (p *Pool) Get() []byte { return p.pool.Get().([]byte) }

func (p *Pool) Put(b []byte) {
	if cap(b) > p.size {
		return
	}
	p.pool.Put(b[:cap(b)])
}

// New returns a new Pooler of size.
func New(size int) *Pool {
	return &Pool{
		size: size,
		pool: sync.Pool{
			New: func() any { return make([]byte, size) },
		},
	}
}

// Noop is a Pooler that just allocates and does not cache.
type Noop struct {
	size int
}

func (n *Noop) Get() []byte { return make([]byte, n.size) }
func (n *Noop) Put([]byte)  {}

// NewNoop returns a new noop pool.
func NewNoop(size int) *Noop { return &Noop{size: size} }

// Builder is a pool used by the String methods.
type Builder struct {
	sync.Pool
}

// NewBuilder returns a new builder pool.
func NewBuilder() *Builder {
	return &Builder{Pool: sync.Pool{New: func() any { return strings.Builder{} }}}
}

func (s *Builder) Get() strings.Builder   { return s.Pool.Get().(strings.Builder) }
func (s *Builder) Put(sb strings.Builder) { sb.Reset(); s.Pool.Put(sb) }
