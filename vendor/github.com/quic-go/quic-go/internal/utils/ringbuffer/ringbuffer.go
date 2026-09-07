package ringbuffer

// RingBuffer is a growable FIFO queue that reuses its backing storage.
// The slice length stores the queue length, so wrapped positions are accessed by reslicing to capacity.
type RingBuffer[T any] struct {
	ring    []T // len is the number of queued elements; cap is the storage size
	headPos int // index of the first element in the full backing storage
}

// Init preallocates a buffer with a certain size.
func (r *RingBuffer[T]) Init(size int) {
	r.ring = make([]T, 0, size)
	r.headPos = 0
}

// Len returns the number of elements in the ring buffer.
func (r *RingBuffer[T]) Len() int {
	return len(r.ring)
}

// Empty says if the ring buffer is empty.
func (r *RingBuffer[T]) Empty() bool {
	return len(r.ring) == 0
}

// PushBack adds a new element.
// If the ring buffer is full, its capacity is increased first.
func (r *RingBuffer[T]) PushBack(t T) {
	if len(r.ring) == cap(r.ring) {
		r.grow()
	}
	tailPos := r.headPos + len(r.ring)
	if tailPos >= cap(r.ring) {
		// both values in the sum are smaller than cap, so one subtraction wraps the index
		tailPos -= cap(r.ring)
	}
	// r.ring's length is the element count, so tailPos may be beyond it after a wrap.
	// Grow the length before temporarily exposing the whole backing array; this order
	// lets the compiler eliminate a bounds check.
	r.ring = r.ring[:len(r.ring)+1]
	r.ring[:cap(r.ring)][tailPos] = t
}

// PopFront returns the next element.
// It must not be called when the buffer is empty, that means that
// callers might need to check if there are elements in the buffer first.
func (r *RingBuffer[T]) PopFront() T {
	if r.Empty() {
		panic("github.com/quic-go/quic-go/internal/utils/ringbuffer: pop from an empty queue")
	}
	// Shrink first. The backing storage remains accessible through cap,
	// and this ordering avoids an extra bounds check.
	r.ring = r.ring[:len(r.ring)-1]
	t := r.ring[:cap(r.ring)][r.headPos]
	clear(r.ring[:cap(r.ring)][r.headPos : r.headPos+1])
	r.headPos++
	if r.headPos == cap(r.ring) {
		r.headPos = 0
	}
	return t
}

// PeekFront returns the next element.
// It must not be called when the buffer is empty, that means that
// callers might need to check if there are elements in the buffer first.
func (r *RingBuffer[T]) PeekFront() T {
	if r.Empty() {
		panic("github.com/quic-go/quic-go/internal/utils/ringbuffer: peek from an empty queue")
	}
	return r.ring[:cap(r.ring)][r.headPos]
}

// grow doubles the storage and copies the queued elements into FIFO order.
func (r *RingBuffer[T]) grow() {
	oldRing := r.ring
	newSize := cap(oldRing) * 2
	if newSize == 0 {
		newSize = 1
	}
	newRing := make([]T, len(oldRing), newSize)
	headLen := copy(newRing, oldRing[r.headPos:])
	copy(newRing[headLen:], oldRing[:r.headPos])
	r.ring = newRing
	r.headPos = 0
}

// Clear removes all elements while retaining the allocated storage.
func (r *RingBuffer[T]) Clear() {
	clear(r.ring[:cap(r.ring)])
	r.ring = r.ring[:0]
	r.headPos = 0
}
