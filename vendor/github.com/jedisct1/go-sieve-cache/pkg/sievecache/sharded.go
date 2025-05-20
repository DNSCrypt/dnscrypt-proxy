package sievecache

import (
	"errors"
	"fmt"
	"hash/fnv"
)

// Default number of shards to use if not specified explicitly.
const DefaultShards = 16

// ShardedSieveCache is a thread-safe implementation of SieveCache that uses multiple shards to reduce contention.
type ShardedSieveCache[K comparable, V any] struct {
	// Array of shard mutexes, each containing a separate SieveCache instance
	shards []*SyncSieveCache[K, V]
	// Number of shards in the cache
	numShards int
}

// NewSharded creates a new sharded cache with the specified capacity, using the default number of shards.
func NewSharded[K comparable, V any](capacity int) (*ShardedSieveCache[K, V], error) {
	return NewShardedWithShards[K, V](capacity, DefaultShards)
}

// NewShardedWithShards creates a new sharded cache with the specified capacity and number of shards.
func NewShardedWithShards[K comparable, V any](capacity int, numShards int) (*ShardedSieveCache[K, V], error) {
	if capacity <= 0 {
		return nil, errors.New("ShardedSieveCache: capacity must be greater than 0")
	}
	if numShards <= 0 {
		return nil, errors.New("ShardedSieveCache: number of shards must be greater than 0")
	}

	// Calculate per-shard capacity
	baseCapacityPerShard := capacity / numShards
	remaining := capacity % numShards

	shards := make([]*SyncSieveCache[K, V], numShards)
	for i := 0; i < numShards; i++ {
		// Distribute the remaining capacity to the first 'remaining' shards
		shardCapacity := baseCapacityPerShard
		if i < remaining {
			shardCapacity++
		}

		// Ensure at least capacity 1 per shard
		if shardCapacity < 1 {
			shardCapacity = 1
		}

		cache, err := NewSync[K, V](shardCapacity)
		if err != nil {
			return nil, err
		}
		shards[i] = cache
	}

	return &ShardedSieveCache[K, V]{
		shards:    shards,
		numShards: numShards,
	}, nil
}

// DefaultSharded creates a new sharded cache with a default capacity of 100 and default shard count.
func DefaultSharded[K comparable, V any]() *ShardedSieveCache[K, V] {
	cache, err := NewSharded[K, V](100)
	if err != nil {
		// This should never happen with non-zero capacity
		panic("Failed to create cache with default capacity")
	}
	return cache
}

// FromSync creates a new sharded cache from an existing SyncSieveCache.
func FromSync[K comparable, V any](syncCache *SyncSieveCache[K, V]) *ShardedSieveCache[K, V] {
	// Create a new sharded cache with the same capacity
	capacity := syncCache.Capacity()
	shardedCache, err := NewSharded[K, V](capacity)
	if err != nil {
		// This should never happen with valid capacity
		panic("Failed to create sharded cache")
	}

	// Transfer all entries
	items := syncCache.Items()
	for _, item := range items {
		shardedCache.Insert(item.Key, item.Value)
	}

	return shardedCache
}

// getShard returns the shard index for a given key.
func (c *ShardedSieveCache[K, V]) getShardIndex(key K) int {
	h := fnv.New32a()
	// Use type switch to handle different key types efficiently
	switch k := any(key).(type) {
	case string:
		h.Write([]byte(k))
	case []byte:
		h.Write(k)
	case int:
		var buf [8]byte
		buf[0] = byte(k)
		buf[1] = byte(k >> 8)
		buf[2] = byte(k >> 16)
		buf[3] = byte(k >> 24)
		h.Write(buf[:4])
	case int64:
		var buf [8]byte
		buf[0] = byte(k)
		buf[1] = byte(k >> 8)
		buf[2] = byte(k >> 16)
		buf[3] = byte(k >> 24)
		buf[4] = byte(k >> 32)
		buf[5] = byte(k >> 40)
		buf[6] = byte(k >> 48)
		buf[7] = byte(k >> 56)
		h.Write(buf[:])
	default:
		// For other types, convert to string
		h.Write([]byte(ToString(k)))
	}
	return int(h.Sum32()) % c.numShards
}

// ToString converts a value to string for hashing.
// This is a simple implementation that should be customized for better performance
// with specific key types.
func ToString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if stringer, ok := v.(interface{ String() string }); ok {
		return stringer.String()
	}
	// For other types, just use %v formatting
	return fmt.Sprintf("%v", v)
}

// getShard returns the shard for a given key.
func (c *ShardedSieveCache[K, V]) getShard(key K) *SyncSieveCache[K, V] {
	index := c.getShardIndex(key)
	return c.shards[index]
}

// Capacity returns the total capacity of the cache (sum of all shard capacities).
func (c *ShardedSieveCache[K, V]) Capacity() int {
	total := 0
	for _, shard := range c.shards {
		total += shard.Capacity()
	}
	return total
}

// Len returns the total number of entries in the cache (sum of all shard lengths).
func (c *ShardedSieveCache[K, V]) Len() int {
	total := 0
	for _, shard := range c.shards {
		total += shard.Len()
	}
	return total
}

// IsEmpty returns true when no values are currently cached in any shard.
func (c *ShardedSieveCache[K, V]) IsEmpty() bool {
	for _, shard := range c.shards {
		if !shard.IsEmpty() {
			return false
		}
	}
	return true
}

// ContainsKey returns true if there is a value in the cache mapped to by key.
func (c *ShardedSieveCache[K, V]) ContainsKey(key K) bool {
	return c.getShard(key).ContainsKey(key)
}

// Get returns the value in the cache mapped to by key.
func (c *ShardedSieveCache[K, V]) Get(key K) (V, bool) {
	return c.getShard(key).Get(key)
}

// GetMut gets a mutable reference to the value in the cache mapped to by key via a callback function.
func (c *ShardedSieveCache[K, V]) GetMut(key K, f func(*V)) bool {
	return c.getShard(key).GetMut(key, f)
}

// Insert maps key to value in the cache, possibly evicting old entries from the appropriate shard.
func (c *ShardedSieveCache[K, V]) Insert(key K, value V) bool {
	return c.getShard(key).Insert(key, value)
}

// Remove removes the cache entry mapped to by key.
func (c *ShardedSieveCache[K, V]) Remove(key K) (V, bool) {
	return c.getShard(key).Remove(key)
}

// Evict removes and returns a value from the cache that was not recently accessed.
// It tries each shard in turn until it finds a value to evict.
func (c *ShardedSieveCache[K, V]) Evict() (V, bool) {
	var zero V

	// Try each shard in turn
	for _, shard := range c.shards {
		value, found := shard.Evict()
		if found {
			return value, true
		}
	}

	return zero, false
}

// Clear removes all entries from the cache.
func (c *ShardedSieveCache[K, V]) Clear() {
	for _, shard := range c.shards {
		shard.Clear()
	}
}

// Keys returns a slice of all keys in the cache.
func (c *ShardedSieveCache[K, V]) Keys() []K {
	var allKeys []K

	// Collect keys from all shards
	for _, shard := range c.shards {
		allKeys = append(allKeys, shard.Keys()...)
	}

	return allKeys
}

// Values returns a slice of all values in the cache.
func (c *ShardedSieveCache[K, V]) Values() []V {
	var allValues []V

	// Collect values from all shards
	for _, shard := range c.shards {
		allValues = append(allValues, shard.Values()...)
	}

	return allValues
}

// Items returns a slice of all key-value pairs in the cache.
func (c *ShardedSieveCache[K, V]) Items() []struct {
	Key   K
	Value V
} {
	var allItems []struct {
		Key   K
		Value V
	}

	// Collect items from all shards
	for _, shard := range c.shards {
		allItems = append(allItems, shard.Items()...)
	}

	return allItems
}

// ForEachValue applies a function to all values in the cache across all shards.
func (c *ShardedSieveCache[K, V]) ForEachValue(f func(*V)) {
	// Process each shard sequentially
	for _, shard := range c.shards {
		shard.ForEachValue(f)
	}
}

// ForEachEntry applies a function to all key-value pairs in the cache across all shards.
func (c *ShardedSieveCache[K, V]) ForEachEntry(f func(K, *V)) {
	// Process each shard sequentially
	for _, shard := range c.shards {
		shard.ForEachEntry(f)
	}
}

// WithKeyLock gets exclusive access to a specific shard based on the key.
// This can be useful for performing multiple operations atomically on entries
// that share the same shard.
func (c *ShardedSieveCache[K, V]) WithKeyLock(key K, f func(*SieveCache[K, V])) {
	c.getShard(key).WithLock(f)
}

// NumShards returns the number of shards in this cache.
func (c *ShardedSieveCache[K, V]) NumShards() int {
	return c.numShards
}

// GetShardByIndex gets a specific shard by index.
// Returns nil if the index is out of bounds.
func (c *ShardedSieveCache[K, V]) GetShardByIndex(index int) *SyncSieveCache[K, V] {
	if index < 0 || index >= c.numShards {
		return nil
	}
	return c.shards[index]
}

// Retain only keeps elements specified by the predicate.
// Removes all entries for which f returns false.
func (c *ShardedSieveCache[K, V]) Retain(f func(K, V) bool) {
	// Process each shard sequentially
	for _, shard := range c.shards {
		shard.Retain(f)
	}
}

// RecommendedCapacity analyzes the current cache utilization and recommends a new capacity.
func (c *ShardedSieveCache[K, V]) RecommendedCapacity(minFactor, maxFactor, lowThreshold, highThreshold float64) int {
	// For each shard, calculate the recommended capacity
	totalRecommended := 0

	for _, shard := range c.shards {
		shardRecommended := shard.RecommendedCapacity(minFactor, maxFactor, lowThreshold, highThreshold)
		totalRecommended += shardRecommended
	}

	// Ensure we return at least the original capacity for an empty cache
	// and at least the number of shards otherwise
	if c.IsEmpty() {
		return c.Capacity()
	}

	return max(c.numShards, totalRecommended)
}

// Using fmt.Sprintf instead of a custom implementation for better reliability
