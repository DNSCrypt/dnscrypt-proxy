# go-sieve - SIEVE is simpler than LRU

## What is it?

`go-sieve` is a golang implementation of the
[SIEVE](https://yazhuozhang.com/assets/pdf/nsdi24-sieve.pdf) cache
eviction algorithm.

This implementation closely follows the paper's pseudo-code - but uses
golang generics to provide an ergonomic interface.

## Key Design Features

### Custom Memory Allocator for Reduced GC Pressure

This implementation uses a custom memory allocator designed to minimize
GC pressure:

- **Pre-allocated Node Pool**: Rather than allocating nodes
  individually, the cache pre-allocates all nodes at initialization time
  in a single contiguous array based on cache capacity.

- **Efficient Freelist**: Recycled nodes are managed through a
  zero-overhead freelist that repurposes the existing node pointers,
  avoiding the need for auxiliary data structures.

- **Single-Allocation Strategy**: By allocating all memory upfront in a
  single operation, the implementation reduces heap fragmentation and
  minimizes the number of objects the garbage collector must track.


## Usage

The API is designed to be simple and intuitive. See the test files for
examples of how to use the cache in your applications.
