package minheap

import "cmp"

type entry[K, V any] struct {
	key   K
	value V
}

// A Heap is a minimum heap ordered by key.
type Heap[K cmp.Ordered, V any] []entry[K, V]

func (h Heap[K, V]) Len() int    { return len(h) }
func (h Heap[K, V]) Empty() bool { return len(h) == 0 }

// Peek returns the smallest element in the heap.
// It must not be called when the heap is empty.
func (h Heap[K, V]) Peek() (K, V) {
	v := h[0]
	return v.key, v.value
}

// Push adds an element to the heap.
func (h *Heap[K, V]) Push(key K, value V) {
	*h = append(*h, entry[K, V]{key: key, value: value})
	(*h).up(len(*h) - 1)
}

// Pop removes and returns the smallest element in the heap.
// It must not be called when the heap is empty.
func (h *Heap[K, V]) Pop() (K, V) {
	values := *h
	last := len(values) - 1
	v := values[0]
	values[0] = values[last]
	var zero entry[K, V]
	values[last] = zero
	values = values[:last]
	if last > 0 {
		values.down(0)
	}
	*h = values
	return v.key, v.value
}

// Clear removes all elements from the heap.
func (h *Heap[K, V]) Clear() {
	clear(*h)
	*h = (*h)[:0]
}

func (h Heap[K, V]) up(i int) {
	for i > 0 {
		parent := (i - 1) / 2
		if h[parent].key <= h[i].key {
			return
		}
		h[parent], h[i] = h[i], h[parent]
		i = parent
	}
}

func (h Heap[K, V]) down(i int) {
	for {
		child := 2*i + 1
		if child >= len(h) {
			break
		}
		if right := child + 1; right < len(h) && h[right].key < h[child].key {
			child = right
		}
		if h[i].key <= h[child].key {
			break
		}
		h[i], h[child] = h[child], h[i]
		i = child
	}
}
