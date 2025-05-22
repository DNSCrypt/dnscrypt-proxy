package sievecache

// Node represents an internal cache entry
type Node[K comparable, V any] struct {
	Key   K
	Value V
}

// NewNode creates a new cache node
func NewNode[K comparable, V any](key K, value V) Node[K, V] {
	return Node[K, V]{
		Key:   key,
		Value: value,
	}
}
