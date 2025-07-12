package sievecache

import (
	"errors"
	"math"
)

// SieveCache provides an efficient in-memory cache with the SIEVE eviction algorithm.
// This is the single-threaded implementation.
type SieveCache[K comparable, V any] struct {
	// Map of keys to indices in the nodes slice (pointer, 8 bytes)
	indices map[K]int
	// Slice of all cache nodes (pointer + len + cap, 24 bytes)
	nodes []Node[K, V]
	// Bit array for visited flags using 1 bit per entry (pointer, 8 bytes)
	visited *BitSet
	// Grouping integer fields together for better memory alignment (each 8 bytes)
	capacity int
	hand     int
	// Place smaller fields last to minimize padding (bool is 1 byte)
	handInitialized bool
}

// New creates a new cache with the given capacity.
// Returns an error if capacity is less than or equal to zero.
func New[K comparable, V any](capacity int) (*SieveCache[K, V], error) {
	if capacity <= 0 {
		return nil, errors.New("SieveCache: capacity must be greater than 0")
	}

	return &SieveCache[K, V]{
		indices:         make(map[K]int, capacity),
		nodes:           make([]Node[K, V], 0, capacity),
		visited:         NewBitSet(capacity),
		hand:            0,
		handInitialized: false,
		capacity:        capacity,
	}, nil
}

// Capacity returns the maximum number of entries the cache can hold.
func (c *SieveCache[K, V]) Capacity() int {
	return c.capacity
}

// Len returns the number of cached values.
func (c *SieveCache[K, V]) Len() int {
	return len(c.nodes)
}

// IsEmpty returns true when no values are currently cached.
func (c *SieveCache[K, V]) IsEmpty() bool {
	return len(c.nodes) == 0
}

// ContainsKey returns true if there is a value in the cache mapped to by key.
func (c *SieveCache[K, V]) ContainsKey(key K) bool {
	_, exists := c.indices[key]
	return exists
}

// Get returns the value in the cache mapped to by key.
// If no value exists for key, returns the zero value of V and false.
// This operation marks the entry as "visited" in the SIEVE algorithm,
// which affects eviction decisions.
func (c *SieveCache[K, V]) Get(key K) (V, bool) {
	var zero V
	idx, exists := c.indices[key]
	if !exists {
		return zero, false
	}

	// Mark as visited for the SIEVE algorithm
	c.visited.Set(idx, true)
	return c.nodes[idx].Value, true
}

// GetPointer returns a pointer to the value in the cache mapped to by key.
// If no value exists for key, returns nil.
// This operation marks the entry as "visited" in the SIEVE algorithm,
// which affects eviction decisions.
func (c *SieveCache[K, V]) GetPointer(key K) *V {
	idx, exists := c.indices[key]
	if !exists {
		return nil
	}

	// Mark as visited for the SIEVE algorithm
	c.visited.Set(idx, true)
	return &c.nodes[idx].Value
}

// Insert maps key to value in the cache, possibly evicting old entries.
// If the key already exists, its value is updated and the entry is marked as visited.
// Returns true when this is a new entry, and false if an existing entry was updated.
func (c *SieveCache[K, V]) Insert(key K, value V) bool {
	// Check if key already exists
	if idx, exists := c.indices[key]; exists {
		// Update existing entry
		c.visited.Set(idx, true)
		c.nodes[idx].Value = value
		return false
	}

	// Evict if at capacity
	if len(c.nodes) >= c.capacity {
		c.Evict()
	}

	// Add new node to the end
	node := NewNode(key, value)
	c.nodes = append(c.nodes, node)
	idx := len(c.nodes) - 1
	c.visited.Append(false) // Initialize as not visited
	c.indices[key] = idx
	return true
}

// Remove removes the cache entry mapped to by key.
// Returns the value removed from the cache and true if the key was present.
// If key did not map to any value, returns the zero value of V and false.
func (c *SieveCache[K, V]) Remove(key K) (V, bool) {
	var zero V
	idx, exists := c.indices[key]
	if !exists {
		return zero, false
	}

	delete(c.indices, key)

	// If this is the last element, just remove it
	if idx == len(c.nodes)-1 {
		node := c.nodes[len(c.nodes)-1]
		c.nodes = c.nodes[:len(c.nodes)-1]
		c.visited.Truncate(len(c.nodes))
		return node.Value, true
	}

	// Update hand if needed
	if c.handInitialized {
		if c.hand == idx {
			// Move hand to the previous node or wrap to end
			if idx > 0 {
				c.hand = idx - 1
			} else {
				c.hand = len(c.nodes) - 2
			}
		} else if c.hand == len(c.nodes)-1 {
			// If hand points to the last element (which will be moved to idx)
			c.hand = idx
		}
	}

	// Remove the node by replacing it with the last one and updating the map
	removedNode := c.nodes[idx]
	lastIdx := len(c.nodes) - 1
	lastNode := c.nodes[lastIdx]

	// Move the last node to the removed position
	c.nodes[idx] = lastNode
	c.visited.Set(idx, c.visited.Get(lastIdx))

	// Truncate slices
	c.nodes = c.nodes[:lastIdx]
	c.visited.Truncate(lastIdx)

	// Update the indices map for the moved node
	if idx < len(c.nodes) {
		c.indices[lastNode.Key] = idx
	}

	return removedNode.Value, true
}

// Evict removes and returns a value from the cache that was not recently accessed.
// This method implements the SIEVE eviction algorithm.
// Returns the evicted value and true if a suitable entry was found, or the zero
// value of V and false if all entries have been recently accessed or the cache is empty.
func (c *SieveCache[K, V]) Evict() (V, bool) {
	var zero V
	if len(c.nodes) == 0 {
		return zero, false
	}

	// Start from the hand pointer or the end if hand is not initialized
	var currentIdx int
	if c.handInitialized {
		currentIdx = c.hand
	} else {
		currentIdx = len(c.nodes) - 1
	}
	startIdx := currentIdx

	// Track whether we've wrapped around
	wrapped := false
	foundIdx := -1

	// Scan for a non-visited entry
	for {
		// If current node is not visited, mark it for eviction
		if !c.visited.Get(currentIdx) {
			foundIdx = currentIdx
			break
		}

		// Mark as non-visited for next scan
		c.visited.Set(currentIdx, false)

		// Move to previous node or wrap to end
		if currentIdx > 0 {
			currentIdx--
		} else {
			// Wrap around to end of slice
			if wrapped {
				// If we've already wrapped, break to avoid infinite loop
				break
			}
			wrapped = true
			currentIdx = len(c.nodes) - 1
		}

		// If we've looped back to start, we've checked all nodes
		if currentIdx == startIdx {
			break
		}
	}

	// If we found a node to evict
	if foundIdx >= 0 {
		evictIdx := foundIdx

		// Update the hand pointer to the previous node or wrap to end
		if evictIdx > 0 {
			c.hand = evictIdx - 1
		} else if len(c.nodes) > 1 {
			c.hand = len(c.nodes) - 2
		} else {
			// Keep hand at 0 but mark as not initialized
			c.handInitialized = false
		}
		c.handInitialized = true

		// Remove the key from the map
		delete(c.indices, c.nodes[evictIdx].Key)

		// Remove the node and return its value
		nodeToEvict := c.nodes[evictIdx]

		if evictIdx == len(c.nodes)-1 {
			// If last node, just remove it
			c.nodes = c.nodes[:len(c.nodes)-1]
			c.visited.Truncate(len(c.nodes))
			return nodeToEvict.Value, true
		}

		// Otherwise swap with the last node
		lastIdx := len(c.nodes) - 1
		lastNode := c.nodes[lastIdx]
		c.nodes[evictIdx] = lastNode
		c.visited.Set(evictIdx, c.visited.Get(lastIdx))
		c.nodes = c.nodes[:lastIdx]
		c.visited.Truncate(lastIdx)

		// Update the indices map for the moved node
		c.indices[lastNode.Key] = evictIdx

		return nodeToEvict.Value, true
	}

	return zero, false
}

// Clear removes all entries from the cache.
func (c *SieveCache[K, V]) Clear() {
	// Pre-allocate map with capacity hint to avoid rehashing during growth
	c.indices = make(map[K]int, c.capacity)
	// Pre-allocate slice with capacity hint to minimize reallocations
	c.nodes = make([]Node[K, V], 0, c.capacity)
	// Initialize bit set
	c.visited = NewBitSet(c.capacity)
	c.hand = 0
	c.handInitialized = false
}

// Keys returns a slice of all keys in the cache.
func (c *SieveCache[K, V]) Keys() []K {
	// Pre-allocate with exact capacity
	keys := make([]K, len(c.nodes))
	for i, node := range c.nodes {
		keys[i] = node.Key
	}
	return keys
}

// Values returns a slice of all values in the cache.
func (c *SieveCache[K, V]) Values() []V {
	// Pre-allocate with exact capacity
	values := make([]V, len(c.nodes))
	for i, node := range c.nodes {
		values[i] = node.Value
	}
	return values
}

// Items returns a slice of all key-value pairs in the cache.
func (c *SieveCache[K, V]) Items() []struct {
	Key   K
	Value V
} {
	// Pre-allocate with exact capacity
	items := make([]struct {
		Key   K
		Value V
	}, len(c.nodes))

	for i, node := range c.nodes {
		items[i].Key = node.Key
		items[i].Value = node.Value
	}

	return items
}

// ForEach iterates over all entries in the cache and applies the function f to each pair.
// The iteration order is not specified and should not be relied upon.
func (c *SieveCache[K, V]) ForEach(f func(k K, v V)) {
	for _, node := range c.nodes {
		f(node.Key, node.Value)
	}
}

// ForEachValue iterates over all values in the cache and applies the function f to each.
// This allows modifying the values in-place.
func (c *SieveCache[K, V]) ForEachValue(f func(v *V)) {
	for i := range c.nodes {
		f(&c.nodes[i].Value)
	}
}

// Retain only keeps elements specified by the predicate.
// Removes all entries for which f returns false.
func (c *SieveCache[K, V]) Retain(f func(k K, v V) bool) {
	// Use a more efficient allocation strategy for the removal list
	nodeCount := len(c.nodes)
	if nodeCount == 0 {
		return
	}

	// Start with a small capacity and grow as needed
	// This avoids over-allocation for large caches with few removals
	initialCap := min(32, nodeCount/4)
	if initialCap < 8 {
		initialCap = 8
	}

	// Collect indices to remove
	toRemove := make([]int, 0, initialCap)

	for i, node := range c.nodes {
		if !f(node.Key, node.Value) {
			toRemove = append(toRemove, i)
		}
	}

	// Remove indices from highest to lowest to avoid invalidating other indices
	for i := len(toRemove) - 1; i >= 0; i-- {
		idx := toRemove[i]

		// Remove from map
		delete(c.indices, c.nodes[idx].Key)

		// If it's the last element, just remove it
		if idx == len(c.nodes)-1 {
			c.nodes = c.nodes[:len(c.nodes)-1]
			c.visited.Truncate(len(c.nodes))
		} else {
			// Replace with the last element
			lastIdx := len(c.nodes) - 1
			lastNode := c.nodes[lastIdx]

			// Move the last node to the removed position
			c.nodes[idx] = lastNode
			c.visited.Set(idx, c.visited.Get(lastIdx))
			c.nodes = c.nodes[:lastIdx]
			c.visited.Truncate(lastIdx)

			// Update indices map if not removed
			if idx < len(c.nodes) {
				c.indices[lastNode.Key] = idx
			}

			// Update hand if needed
			if c.handInitialized {
				if c.hand == idx {
					// Hand was pointing to the removed node, move it to previous
					if idx > 0 {
						c.hand = idx - 1
					} else if len(c.nodes) > 0 {
						c.hand = len(c.nodes) - 1
					} else {
						c.handInitialized = false
					}
				} else if c.hand == lastIdx {
					// Hand was pointing to the last node that was moved
					c.hand = idx
				}
			}
		}
	}
}

// RecommendedCapacity analyzes the current cache utilization and recommends a new capacity.
// Parameters:
// - minFactor: Minimum scaling factor (e.g., 0.5 means recommend at least 50% of current capacity)
// - maxFactor: Maximum scaling factor (e.g., 2.0 means recommend at most 200% of current capacity)
// - lowThreshold: Utilization threshold below which capacity is reduced
// - highThreshold: Utilization threshold above which capacity is increased
func (c *SieveCache[K, V]) RecommendedCapacity(minFactor, maxFactor, lowThreshold, highThreshold float64) int {
	// If the cache is empty, return the current capacity
	if len(c.nodes) == 0 {
		return c.capacity
	}

	// Count entries with visited flag set
	visitedCount := c.visited.CountSetBits()

	// Calculate the utilization ratio (visited entries / total entries)
	utilizationRatio := float64(visitedCount) / float64(len(c.nodes))

	// Calculate fill ratio (total entries / capacity)
	fillRatio := float64(len(c.nodes)) / float64(c.capacity)

	// Low fill ratio threshold (consider the cache underfilled below this)
	lowFillThreshold := 0.1 // 10% filled

	// Fill ratio takes precedence over utilization:
	// If the cache is severely underfilled, we should decrease capacity
	// regardless of utilization
	if fillRatio < lowFillThreshold {
		// Calculate how much to decrease based on how empty the cache is
		fillBelowThreshold := 0.0
		if fillRatio > 0.0 {
			fillBelowThreshold = (lowFillThreshold - fillRatio) / lowFillThreshold
		} else {
			fillBelowThreshold = 1.0
		}
		// Apply the minFactor as a floor
		scalingFactor := 1.0 - (1.0-minFactor)*fillBelowThreshold

		// Apply the scaling factor to current capacity and ensure it's at least 1
		return max(1, int(math.Round(float64(c.capacity)*scalingFactor)))
	}

	// For normal fill levels, use the original logic based on utilization
	var scalingFactor float64
	if utilizationRatio >= highThreshold {
		// High utilization - recommend increasing the capacity
		// Scale between 1.0 and maxFactor based on utilization above the high threshold
		utilizationAboveThreshold := (utilizationRatio - highThreshold) / (1.0 - highThreshold)
		scalingFactor = 1.0 + (maxFactor-1.0)*utilizationAboveThreshold
	} else if utilizationRatio <= lowThreshold {
		// Low utilization - recommend decreasing capacity
		// Scale between minFactor and 1.0 based on how far below the low threshold
		utilizationBelowThreshold := (lowThreshold - utilizationRatio) / lowThreshold
		scalingFactor = 1.0 - (1.0-minFactor)*utilizationBelowThreshold
	} else {
		// Normal utilization - keep current capacity
		scalingFactor = 1.0
	}

	// Apply the scaling factor to current capacity and ensure it's at least 1
	return max(1, int(math.Round(float64(c.capacity)*scalingFactor)))
}
