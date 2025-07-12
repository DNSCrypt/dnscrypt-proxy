package sievecache

import (
	"sync"
)

// SyncSieveCache is a thread-safe wrapper around SieveCache.
// It provides the same functionality but with thread safety guarantees.
type SyncSieveCache[K comparable, V any] struct {
	cache *SieveCache[K, V]
	mutex sync.RWMutex
}

// NewSync creates a new thread-safe cache with the given capacity.
func NewSync[K comparable, V any](capacity int) (*SyncSieveCache[K, V], error) {
	cache, err := New[K, V](capacity)
	if err != nil {
		return nil, err
	}

	return &SyncSieveCache[K, V]{
		cache: cache,
		mutex: sync.RWMutex{},
	}, nil
}

// DefaultSync creates a new thread-safe cache with a default capacity of 100.
func DefaultSync[K comparable, V any]() *SyncSieveCache[K, V] {
	cache, err := NewSync[K, V](100)
	if err != nil {
		// This should never happen with non-zero capacity
		panic("Failed to create cache with default capacity")
	}
	return cache
}

// FromSieveCache creates a new thread-safe cache from an existing SieveCache.
func FromSieveCache[K comparable, V any](cache *SieveCache[K, V]) *SyncSieveCache[K, V] {
	return &SyncSieveCache[K, V]{
		cache: cache,
		mutex: sync.RWMutex{},
	}
}

// Capacity returns the maximum number of entries the cache can hold.
func (c *SyncSieveCache[K, V]) Capacity() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.cache.Capacity()
}

// Len returns the number of cached values.
func (c *SyncSieveCache[K, V]) Len() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.cache.Len()
}

// IsEmpty returns true when no values are currently cached.
func (c *SyncSieveCache[K, V]) IsEmpty() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.cache.IsEmpty()
}

// ContainsKey returns true if there is a value in the cache mapped to by key.
func (c *SyncSieveCache[K, V]) ContainsKey(key K) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.cache.ContainsKey(key)
}

// Get returns the value in the cache mapped to by key.
// Unlike the unwrapped SieveCache, this returns a copy of the value
// rather than a reference, since the mutex guard is released after this method returns.
func (c *SyncSieveCache[K, V]) Get(key K) (V, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.cache.Get(key)
}

// GetMut gets a mutable reference to the value in the cache mapped to by key via a callback function.
// Returns true if the key exists and the callback was invoked, false otherwise.
func (c *SyncSieveCache[K, V]) GetMut(key K, f func(*V)) bool {
	// First get a copy of the value to avoid holding the lock during callback
	c.mutex.Lock()
	var valueCopy V
	var exists bool
	ptr := c.cache.GetPointer(key)
	if ptr != nil {
		valueCopy = *ptr
		exists = true
	}
	c.mutex.Unlock()

	if !exists {
		return false
	}

	// Execute callback on the copy
	f(&valueCopy)

	// Update the value back in the cache
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if the key still exists
	ptr = c.cache.GetPointer(key)
	if ptr != nil {
		*ptr = valueCopy
		return true
	}

	return false
}

// Insert maps key to value in the cache, possibly evicting old entries.
func (c *SyncSieveCache[K, V]) Insert(key K, value V) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.cache.Insert(key, value)
}

// Remove removes the cache entry mapped to by key.
func (c *SyncSieveCache[K, V]) Remove(key K) (V, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.cache.Remove(key)
}

// Evict removes and returns a value from the cache that was not recently accessed.
func (c *SyncSieveCache[K, V]) Evict() (V, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.cache.Evict()
}

// Clear removes all entries from the cache.
func (c *SyncSieveCache[K, V]) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cache.Clear()
}

// Keys returns a slice of all keys in the cache.
func (c *SyncSieveCache[K, V]) Keys() []K {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.cache.Keys()
}

// Values returns a slice of all values in the cache.
func (c *SyncSieveCache[K, V]) Values() []V {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.cache.Values()
}

// Items returns a slice of all key-value pairs in the cache.
func (c *SyncSieveCache[K, V]) Items() []struct {
	Key   K
	Value V
} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.cache.Items()
}

// ForEachValue applies a function to all values in the cache.
// The function receives and can modify a copy of each value, and changes will be saved back to the cache.
func (c *SyncSieveCache[K, V]) ForEachValue(f func(*V)) {
	// First collect all items under the read lock
	c.mutex.RLock()
	items := c.cache.Items()
	c.mutex.RUnlock()

	// Process each value without holding the lock
	// Pre-allocate map with the expected size to prevent resizing
	updatedItems := make(map[K]V, len(items))
	for _, item := range items {
		valueCopy := item.Value
		f(&valueCopy)
		updatedItems[item.Key] = valueCopy
	}

	// Update any changed values back to the cache
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for k, v := range updatedItems {
		if c.cache.ContainsKey(k) {
			c.cache.Insert(k, v)
		}
	}
}

// ForEachEntry applies a function to all key-value pairs in the cache.
// The function receives the key and can modify a copy of each value, and changes will be saved back to the cache.
func (c *SyncSieveCache[K, V]) ForEachEntry(f func(K, *V)) {
	// First collect all items under the read lock
	c.mutex.RLock()
	items := c.cache.Items()
	c.mutex.RUnlock()

	// Process each entry without holding the lock
	// Pre-allocate map with the expected size to prevent resizing
	updatedItems := make(map[K]V, len(items))
	for _, item := range items {
		valueCopy := item.Value
		f(item.Key, &valueCopy)
		updatedItems[item.Key] = valueCopy
	}

	// Update any changed values back to the cache
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for k, v := range updatedItems {
		if c.cache.ContainsKey(k) {
			c.cache.Insert(k, v)
		}
	}
}

// WithLock gets exclusive access to the underlying cache to perform multiple operations atomically.
// This is useful when you need to perform a series of operations that depend on each other.
func (c *SyncSieveCache[K, V]) WithLock(f func(*SieveCache[K, V])) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	f(c.cache)
}

// Retain only keeps elements specified by the predicate.
// Removes all entries for which f returns false.
func (c *SyncSieveCache[K, V]) Retain(f func(K, V) bool) {
	// First collect all items under the read lock
	c.mutex.RLock()
	items := c.cache.Items()
	c.mutex.RUnlock()

	// Estimate number of elements to remove - pre-allocate with a reasonable capacity
	estimatedRemoveCount := len(items) / 4 // Assume about 25% will be removed
	if estimatedRemoveCount < 8 {
		estimatedRemoveCount = 8 // Minimum size for small caches
	}
	if estimatedRemoveCount > 1024 {
		estimatedRemoveCount = 1024 // Cap at reasonable maximum
	}

	// Check each entry against the predicate without holding the lock
	keysToRemove := make([]K, 0, estimatedRemoveCount)
	for _, item := range items {
		if !f(item.Key, item.Value) {
			keysToRemove = append(keysToRemove, item.Key)
		}
	}

	// Remove entries that don't match the predicate
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for _, key := range keysToRemove {
		c.cache.Remove(key)
	}
}

// RetainBatch is an optimized version of Retain that collects all keys to remove first,
// then removes them in a single batch operation with a single lock acquisition.
func (c *SyncSieveCache[K, V]) RetainBatch(f func(K, V) bool) {
	// First collect all items under the read lock
	c.mutex.RLock()
	items := c.cache.Items()
	c.mutex.RUnlock()

	// Estimate number of elements to remove - pre-allocate with a reasonable capacity
	estimatedRemoveCount := len(items) / 4 // Assume about 25% will be removed
	if estimatedRemoveCount < 8 {
		estimatedRemoveCount = 8 // Minimum size for small caches
	}
	if estimatedRemoveCount > 1024 {
		estimatedRemoveCount = 1024 // Cap at reasonable maximum
	}

	// Collect keys to remove without holding the lock
	keysToRemove := make([]K, 0, estimatedRemoveCount)
	for _, item := range items {
		if !f(item.Key, item.Value) {
			keysToRemove = append(keysToRemove, item.Key)
		}
	}

	// If there are keys to remove, do it in a single batch operation
	if len(keysToRemove) > 0 {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		for _, key := range keysToRemove {
			c.cache.Remove(key)
		}
	}
}

// RecommendedCapacity analyzes the current cache utilization and recommends a new capacity.
func (c *SyncSieveCache[K, V]) RecommendedCapacity(minFactor, maxFactor, lowThreshold, highThreshold float64) int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.cache.RecommendedCapacity(minFactor, maxFactor, lowThreshold, highThreshold)
}
