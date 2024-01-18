# go-sieve - SIEVE is simpler than LRU

## What is it?
`go-sieve` is golang implementation of the [SIEVE](https://yazhuozhang.com/assets/pdf/nsdi24-sieve.pdf)
cache eviction algorithm.

This implementation closely follows the paper's pseudo-code - but
uses golang generics to provide an ergonomic interface.

