/*
Package sievecache provides thread-safe, high-performance implementations of the SIEVE cache replacement algorithm in Go.

# Overview

SIEVE (Simple, space-efficient, In-memory, EViction mEchanism) is a cache eviction
algorithm that maintains a single bit per entry to track whether an item has been
"visited" since it was last considered for eviction. This approach requires less
state than LRU but achieves excellent performance, especially on skewed workloads.

The package offers three implementations to address different concurrency needs:

  - SieveCache: Non-thread-safe implementation for single-threaded use
  - SyncSieveCache: Thread-safe wrapper with mutex locking
  - ShardedSieveCache: High-concurrency implementation with data sharding

# Cache Implementation Details

The cache is implemented as a combination of:

 1. A map for O(1) key lookups
 2. A slice-based ordered collection for managing entries
 3. A "visited" flag on each entry to track recent access
 4. A "hand" pointer that indicates the next eviction candidate

When the cache is full and a new item is inserted, the eviction algorithm:

 1. Starts from the "hand" position (eviction candidate)
 2. Finds the first non-visited entry, evicting it
 3. Marks all visited entries as non-visited while searching
 4. Updates the hand to point to the position before the evicted entry

Performance Characteristics

  - All basic operations (Get, Insert, Remove) are O(1) in the common case
  - Memory overhead is minimal (1 bit per entry plus standard Go overhead)
  - Thread-safe implementations provide atomic multi-operation capabilities
  - Sharded implementation reduces lock contention for high-concurrency scenarios

Choosing the Right Implementation

  - Use SieveCache for single-threaded applications
  - Use SyncSieveCache for multi-threaded applications with moderate concurrency
  - Use ShardedSieveCache for applications with high concurrency where operations
    are distributed across many different keys

The package also provides a RecommendedCapacity method to dynamically adjust cache
size based on access patterns, which can help optimize memory usage over time.
*/
package sievecache
