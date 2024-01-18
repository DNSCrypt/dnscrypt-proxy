// sieve.go - SIEVE - a simple and efficient cache
//
// (c) 2024 Sudhi Herle <sudhi@herle.net>
//
// Copyright 2024- Sudhi Herle <sw-at-herle-dot-net>
// License: BSD-2-Clause
//
// If you need a commercial license for this work, please contact
// the author.
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

// This is golang implementation of the SIEVE cache eviction algorithm
// The original paper is:
//	https://yazhuozhang.com/assets/pdf/nsdi24-sieve.pdf
//
// This implementation closely follows the paper - but uses golang generics
// for an ergonomic interface.

// Package sieve implements the SIEVE cache eviction algorithm.
// SIEVE stands in contrast to other eviction algorithms like LRU, 2Q, ARC
// with its simplicity. The original paper is in:
// https://yazhuozhang.com/assets/pdf/nsdi24-sieve.pdf
//
// SIEVE is built on a FIFO queue - with an extra pointer (called "hand") in
// the paper. This "hand" plays a crucial role in determining who to evict
// next.
package sieve

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// node contains the <key, val> tuple as a node in a linked list.
type node[K comparable, V any] struct {
	sync.Mutex
	key     K
	val     V
	visited atomic.Bool
	next    *node[K, V]
	prev    *node[K, V]
}

// Sieve represents a cache mapping the key of type 'K' with
// a value of type 'V'. The type 'K' must implement the
// comparable trait. An instance of Sieve has a fixed max capacity;
// new additions to the cache beyond the capacity will cause cache
// eviction of other entries - as determined by the SIEVE algorithm.
type Sieve[K comparable, V any] struct {
	mu       sync.Mutex
	cache    *syncMap[K, *node[K, V]]
	head     *node[K, V]
	tail     *node[K, V]
	hand     *node[K, V]
	size     int
	capacity int

	pool *syncPool[node[K, V]]
}

// New creates a new cache of size 'capacity' mapping key 'K' to value 'V'
func New[K comparable, V any](capacity int) *Sieve[K, V] {
	s := &Sieve[K, V]{
		cache:    newSyncMap[K, *node[K, V]](),
		capacity: capacity,
		pool:     newSyncPool[node[K, V]](),
	}
	return s
}

// Get fetches the value for a given key in the cache.
// It returns true if the key is in the cache, false otherwise.
// The zero value for 'V' is returned when key is not in the cache.
func (s *Sieve[K, V]) Get(key K) (V, bool) {

	if v, ok := s.cache.Get(key); ok {
		v.visited.Store(true)
		return v.val, true
	}

	var x V
	return x, false
}

// Add adds a new element to the cache or overwrite one if it exists
// Return true if we replaced, false otherwise
func (s *Sieve[K, V]) Add(key K, val V) bool {

	if v, ok := s.cache.Get(key); ok {
		v.visited.Store(true)
		v.Lock()
		v.val = val
		v.Unlock()
		return true
	}

	s.mu.Lock()
	s.add(key, val)
	s.mu.Unlock()
	return false
}

// Probe adds <key, val> if not present in the cache.
// Returns:
//
//	<cached-val, true> when key is present in the cache
//	<val, false> when key is not present in the cache
func (s *Sieve[K, V]) Probe(key K, val V) (V, bool) {

	if v, ok := s.cache.Get(key); ok {
		v.visited.Store(true)
		return v.val, true
	}

	s.mu.Lock()
	s.add(key, val)
	s.mu.Unlock()
	return val, false
}

// Delete deletes the named key from the cache
// It returns true if the item was in the cache and false otherwise
func (s *Sieve[K, V]) Delete(key K) bool {

	if v, ok := s.cache.Del(key); ok {
		s.mu.Lock()
		s.remove(v)
		s.mu.Unlock()
		return true
	}

	return false
}

// Purge resets the cache
func (s *Sieve[K, V]) Purge() {
	s.mu.Lock()
	s.cache = newSyncMap[K, *node[K, V]]()
	s.head = nil
	s.tail = nil
	s.mu.Unlock()
}

// Len returns the current cache utilization
func (s *Sieve[K, V]) Len() int {
	return s.size
}

// Cap returns the max cache capacity
func (s *Sieve[K, V]) Cap() int {
	return s.capacity
}

// String returns a string description of the sieve cache
func (s *Sieve[K, V]) String() string {
	s.mu.Lock()
	m := s.desc()
	s.mu.Unlock()
	return m
}

// Dump dumps all the cache contents as a newline delimited
// string.
func (s *Sieve[K, V]) Dump() string {
	var b strings.Builder

	s.mu.Lock()
	b.WriteString(s.desc())
	b.WriteRune('\n')
	for n := s.head; n != nil; n = n.next {
		h := "  "
		if n == s.hand {
			h = ">>"
		}
		b.WriteString(fmt.Sprintf("%svisited=%v, key=%v, val=%v\n", h, n.visited.Load(), n.key, n.val))
	}
	s.mu.Unlock()
	return b.String()
}

// -- internal methods --

// add a new tuple to the cache and evict as necessary
// caller must hold lock.
func (s *Sieve[K, V]) add(key K, val V) {
	// cache miss; we evict and fnd a new node
	if s.size == s.capacity {
		s.evict()
	}

	n := s.newNode(key, val)

	// Eviction is guaranteed to remove one node; so this should never happen.
	if n == nil {
		msg := fmt.Sprintf("%T: add <%v>: objpool empty after eviction", s, key)
		panic(msg)
	}

	s.cache.Put(key, n)

	// insert at the head of the list
	n.next = s.head
	n.prev = nil
	if s.head != nil {
		s.head.prev = n
	}
	s.head = n
	if s.tail == nil {
		s.tail = n
	}

	s.size += 1
}

// evict an item from the cache.
// NB: Caller must hold the lock
func (s *Sieve[K, V]) evict() {
	hand := s.hand
	if hand == nil {
		hand = s.tail
	}

	for hand != nil {
		if !hand.visited.Load() {
			s.cache.Del(hand.key)
			s.remove(hand)
			s.hand = hand.prev
			return
		}
		hand.visited.Store(false)
		hand = hand.prev
		// wrap around and start again
		if hand == nil {
			hand = s.tail
		}
	}
	s.hand = hand
}

func (s *Sieve[K, V]) remove(n *node[K, V]) {
	s.size -= 1

	// remove node from list
	if n.prev != nil {
		n.prev.next = n.next
	} else {
		s.head = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	} else {
		s.tail = n.prev
	}

	s.pool.Put(n)
}

func (s *Sieve[K, V]) newNode(key K, val V) *node[K, V] {
	n := s.pool.Get()
	n.key, n.val = key, val
	n.next, n.prev = nil, nil
	n.visited.Store(false)

	return n
}

// desc describes the properties of the sieve
func (s *Sieve[K, V]) desc() string {
	m := fmt.Sprintf("cache<%T>: size %d, cap %d, head=%p, tail=%p, hand=%p",
		s, s.size, s.capacity, s.head, s.tail, s.hand)
	return m
}

// Generic sync.Pool
type syncPool[T any] struct {
	pool sync.Pool
}

func newSyncPool[T any]() *syncPool[T] {
	p := &syncPool[T]{
		pool: sync.Pool{
			New: func() any { return new(T) },
		},
	}
	return p
}

func (s *syncPool[T]) Get() *T {
	p := s.pool.Get()
	return p.(*T)
}

func (s *syncPool[T]) Put(n *T) {
	s.pool.Put(n)
}

// generic sync.Map
type syncMap[K comparable, V any] struct {
	m sync.Map
}

func newSyncMap[K comparable, V any]() *syncMap[K, V] {
	m := syncMap[K, V]{}
	return &m
}

func (m *syncMap[K, V]) Get(key K) (V, bool) {
	v, ok := m.m.Load(key)
	if ok {
		return v.(V), true
	}

	var z V
	return z, false
}

func (m *syncMap[K, V]) Put(key K, val V) {
	m.m.Store(key, val)
}

func (m *syncMap[K, V]) Del(key K) (V, bool) {
	x, ok := m.m.LoadAndDelete(key)
	if ok {
		return x.(V), true
	}

	var z V
	return z, false
}
