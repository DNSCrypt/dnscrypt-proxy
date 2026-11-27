package quic

import (
	"errors"
	"iter"
	"slices"
	"sort"

	"github.com/quic-go/quic-go/internal/protocol"
)

const (
	// maxStreamFrameSorterGaps is the maximum number of gaps in the received data.
	// It protects against DoS attacks.
	maxStreamFrameSorterGaps = 4096
	// maxGapChunkLen is the maximum number of gaps in a chunk of frameSorter.gaps.
	maxGapChunkLen = 64
)

// byteInterval is an interval from one ByteCount to the other
type byteInterval struct {
	Start protocol.ByteCount
	End   protocol.ByteCount
}

// gapPos is the position of a gap in frameSorter.gaps.
type gapPos struct {
	Chunk int
	Index int
}

type frameSorterEntry struct {
	Data   []byte
	DoneCb func()
}

// frameSorter reassembles STREAM frame data that arrives out of order.
//
// queue holds the received frames, keyed by offset.
// gaps holds the byte ranges not received yet, the last one ending at protocol.MaxByteCount.
// It is a two-level tree: the sorted gaps are split into non-empty chunks of at most maxGapChunkLen gaps.
//
//	[ [g0 g1 g2 g3] [g4 g5] [g6 g7 g8] ]
//
// A chunk is split in half when it grows too large,
// and merged with a neighbor when they hold at most maxGapChunkLen/2 gaps together.
type frameSorter struct {
	queue   map[protocol.ByteCount]frameSorterEntry
	readPos protocol.ByteCount
	gaps    [][]byteInterval
	numGaps int // the number of gaps in all chunks
}

var errDuplicateStreamData = errors.New("duplicate stream data")

func newFrameSorter() *frameSorter {
	return &frameSorter{
		queue:   make(map[protocol.ByteCount]frameSorterEntry),
		gaps:    [][]byteInterval{{{Start: 0, End: protocol.MaxByteCount}}},
		numGaps: 1,
	}
}

func (s *frameSorter) Push(data []byte, offset protocol.ByteCount, doneCb func()) error {
	err := s.push(data, offset, doneCb)
	if err == errDuplicateStreamData {
		if doneCb != nil {
			doneCb()
		}
		return nil
	}
	return err
}

func (s *frameSorter) push(data []byte, offset protocol.ByteCount, doneCb func()) error {
	if len(data) == 0 {
		return errDuplicateStreamData
	}

	start := offset
	end := offset + protocol.ByteCount(len(data))

	// the frame can only cover the gaps from startGap to endGap
	startPos := s.findGap(start)
	startGap := s.gaps[startPos.Chunk][startPos.Index]
	if end <= startGap.Start {
		return errDuplicateStreamData
	}
	endPos := startPos
	endGap := startGap
	if end > startGap.End {
		endPos = s.findLastGap(end)
		endGap = s.gaps[endPos.Chunk][endPos.Index]
	}
	startsInGap := start >= startGap.Start
	endsInGap := end < endGap.End

	var wasCut bool
	pos := start
	var hasReplacedAtLeastOne bool
	for {
		oldEntry, ok := s.queue[pos]
		if !ok {
			break
		}
		oldEntryLen := protocol.ByteCount(len(oldEntry.Data))
		if end-pos > oldEntryLen || (hasReplacedAtLeastOne && end-pos == oldEntryLen) {
			// The existing frame is shorter than the new frame. Replace it.
			delete(s.queue, pos)
			pos += oldEntryLen
			hasReplacedAtLeastOne = true
			if oldEntry.DoneCb != nil {
				oldEntry.DoneCb()
			}
		} else {
			if !hasReplacedAtLeastOne {
				return errDuplicateStreamData
			}
			// The existing frame is longer than the new frame.
			// Cut the new frame such that the end aligns with the start of the existing frame.
			data = data[:pos-start]
			end = pos
			wasCut = true
			break
		}
	}

	if !startsInGap && !hasReplacedAtLeastOne {
		// cut the frame, such that it starts at the start of the gap
		data = data[startGap.Start-start:]
		start = startGap.Start
		wasCut = true
	}

	if startPos != endPos {
		// The frame replaces the frames between the gaps it covers.
		for gap := range s.gapsBetween(startPos, endPos) {
			s.deleteConsecutive(gap.End)
		}
	}

	if !endsInGap && start != endGap.End && end > endGap.End {
		// cut the frame, such that it ends at the end of the gap
		data = data[:endGap.End-start]
		end = endGap.End
		wasCut = true
	}

	if startPos == endPos && start <= startGap.Start && end < startGap.End {
		// The frame covers the front of a single gap.
		// This is the common case for in-order data.
		s.gaps[startPos.Chunk][startPos.Index].Start = end
	} else {
		// The gaps from startGap to endGap are replaced by what the frame leaves of them.
		// The gaps in between are fully covered, so at most two pieces remain:
		//
		//	   startGap                    endGap
		//	|============|     ...     |============|
		//	      |-------- frame --------|
		//	|=====|                       |=========|
		//	 before                          after
		//
		// There is no piece before the frame if the frame starts at or before the start of startGap,
		// and no piece after the frame if it ends at or after the end of endGap.
		remaining := make([]byteInterval, 0, 2)
		if startGap.Start < start {
			remaining = append(remaining, byteInterval{Start: startGap.Start, End: start})
		}
		if end < endGap.End {
			remaining = append(remaining, byteInterval{Start: end, End: endGap.End})
		}
		s.replaceGaps(startPos, endPos, remaining)
	}

	if wasCut && len(data) < protocol.MinStreamFrameBufferSize {
		newData := make([]byte, len(data))
		copy(newData, data)
		data = newData
		if doneCb != nil {
			doneCb()
			doneCb = nil
		}
	}

	if s.numGaps > maxStreamFrameSorterGaps {
		return errors.New("too many gaps in received data")
	}

	s.queue[start] = frameSorterEntry{Data: data, DoneCb: doneCb}
	return nil
}

// findGap returns the first gap that ends at or after offset.
func (s *frameSorter) findGap(offset protocol.ByteCount) gapPos {
	// fast path: new data lands in the last gap
	last := len(s.gaps) - 1
	if i := len(s.gaps[last]) - 1; offset >= s.gaps[last][i].Start {
		return gapPos{Chunk: last, Index: i}
	}
	c := sort.Search(len(s.gaps), func(c int) bool { return s.gaps[c][len(s.gaps[c])-1].End >= offset })
	i := sort.Search(len(s.gaps[c]), func(i int) bool { return s.gaps[c][i].End >= offset })
	return gapPos{Chunk: c, Index: i}
}

// findLastGap returns the last gap that starts at or before offset.
func (s *frameSorter) findLastGap(offset protocol.ByteCount) gapPos {
	c := sort.Search(len(s.gaps), func(c int) bool { return s.gaps[c][0].Start > offset }) - 1
	i := sort.Search(len(s.gaps[c]), func(i int) bool { return s.gaps[c][i].Start > offset }) - 1
	return gapPos{Chunk: c, Index: i}
}

// gapsBetween iterates over the gaps from from up to, but not including, to.
func (s *frameSorter) gapsBetween(from, to gapPos) iter.Seq[byteInterval] {
	return func(yield func(byteInterval) bool) {
		for c := from.Chunk; c <= to.Chunk; c++ {
			// the chunks in between are iterated over completely
			var start int
			end := len(s.gaps[c])
			// in from's chunk, skip the gaps before from
			if c == from.Chunk {
				start = from.Index
			}
			// in to's chunk, stop before to
			if c == to.Chunk {
				end = to.Index
			}
			for _, gap := range s.gaps[c][start:end] {
				if !yield(gap) {
					return
				}
			}
		}
	}
}

// replaceGaps replaces the gaps from from to to (inclusive) with newGaps (at most two, sorted).
// The result ends up in from's chunk, and the chunks after it, up to and including to's chunk, are removed.
// For example, a frame that starts in gap g2 and ends in gap g6 leaves g2' (the part of g2 before the frame)
// and g6' (the part of g6 after the frame):
//
//	        from             to
//	         v               v
//	[ [g0 g1 g2 g3] [g4 g5] [g6 g7 g8] ]   =>   [ [g0 g1 g2' g6' g7 g8] ]
func (s *frameSorter) replaceGaps(from, to gapPos, newGaps []byteInterval) {
	c := from.Chunk
	// the chunks from c up to and including to's chunk are replaced by chunk c
	for _, chunk := range s.gaps[c : to.Chunk+1] {
		s.numGaps -= len(chunk)
	}
	if c == to.Chunk {
		// Within one chunk, appending newGaps could overwrite the gaps after to before they're moved.
		s.gaps[c] = slices.Replace(s.gaps[c], from.Index, to.Index+1, newGaps...)
	} else {
		// chunk c keeps the gaps before from, followed by newGaps and the gaps after to
		tail := s.gaps[to.Chunk][to.Index+1:]
		s.gaps[c] = append(append(s.gaps[c][:from.Index], newGaps...), tail...)
		s.gaps = slices.Delete(s.gaps, c+1, to.Chunk+1)
	}
	s.numGaps += len(s.gaps[c])
	s.rebalance(c)
}

// rebalance restores the chunk invariants after chunk c changed size:
// every chunk holds between 1 and maxGapChunkLen gaps,
// and any two neighboring chunks hold more than maxGapChunkLen/2 gaps together.
func (s *frameSorter) rebalance(c int) {
	if chunk := s.gaps[c]; len(chunk) > maxGapChunkLen {
		// Split the chunk in half, allocating the full capacity, so that the new chunk never needs to grow.
		// Each half holds at least maxGapChunkLen/2 gaps, so it is too large to be merged with a neighbor.
		next := append(make([]byteInterval, 0, maxGapChunkLen+1), chunk[len(chunk)/2:]...)
		s.gaps[c] = chunk[:len(chunk)/2]
		s.gaps = slices.Insert(s.gaps, c+1, next)
		return
	}
	if len(s.gaps[c]) == 0 {
		// The next chunk moves to c. It is never empty, since the last chunk holds the last gap.
		s.gaps = slices.Delete(s.gaps, c, c+1)
	}
	// Merge chunk c with its neighbors, if they hold at most maxGapChunkLen/2 gaps together.
	// Merging only at half capacity, and not whenever two chunks fit into one,
	// prevents a chunk from being split and merged back over and over again.
	if c > 0 && len(s.gaps[c-1])+len(s.gaps[c]) <= maxGapChunkLen/2 {
		c--
		s.gaps[c] = append(s.gaps[c], s.gaps[c+1]...)
		s.gaps = slices.Delete(s.gaps, c+1, c+2)
	}
	if c+1 < len(s.gaps) && len(s.gaps[c])+len(s.gaps[c+1]) <= maxGapChunkLen/2 {
		s.gaps[c] = append(s.gaps[c], s.gaps[c+1]...)
		s.gaps = slices.Delete(s.gaps, c+1, c+2)
	}
}

// deleteConsecutive deletes consecutive frames from the queue, starting at pos
func (s *frameSorter) deleteConsecutive(pos protocol.ByteCount) {
	for {
		oldEntry, ok := s.queue[pos]
		if !ok {
			break
		}
		oldEntryLen := protocol.ByteCount(len(oldEntry.Data))
		delete(s.queue, pos)
		if oldEntry.DoneCb != nil {
			oldEntry.DoneCb()
		}
		pos += oldEntryLen
	}
}

func (s *frameSorter) Pop() (protocol.ByteCount, []byte, func()) {
	entry, ok := s.queue[s.readPos]
	if !ok {
		return s.readPos, nil, nil
	}
	delete(s.queue, s.readPos)
	offset := s.readPos
	s.readPos += protocol.ByteCount(len(entry.Data))
	if s.gaps[0][0].End <= s.readPos {
		panic("frame sorter BUG: read position higher than a gap")
	}
	return offset, entry.Data, entry.DoneCb
}

// ReadPos returns the offset of the next byte that will be popped.
func (s *frameSorter) ReadPos() protocol.ByteCount {
	return s.readPos
}

// HasMoreData says if there is any more data queued at *any* offset.
func (s *frameSorter) HasMoreData() bool {
	return len(s.queue) > 0
}

var errTooLittleData = errors.New("too little data")

// Peek copies len(p) consecutive bytes starting at offset into p, without removing them.
// It is only possible to peek from an offset where a frame starts.
//
// If there isn't enough consecutive data available, errTooLittleData is returned.
func (s *frameSorter) Peek(offset protocol.ByteCount, p []byte) error {
	if len(p) == 0 {
		return nil
	}

	// first, check if we have enough consecutive data available
	pos := offset
	remaining := len(p)
	for remaining > 0 {
		entry, ok := s.queue[pos]
		if !ok {
			return errTooLittleData
		}
		entryLen := len(entry.Data)
		if remaining <= entryLen {
			break // enough data available
		}
		remaining -= entryLen
		pos += protocol.ByteCount(entryLen)
	}

	pos = offset
	var copied int
	for copied < len(p) {
		entry := s.queue[pos] // the entry is guaranteed to exist from the check above
		copied += copy(p[copied:], entry.Data)
		pos += protocol.ByteCount(len(entry.Data))
	}
	return nil
}
