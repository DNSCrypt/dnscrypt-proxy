package revera

// This file holds the phase A executor.
// It scans the subject once, runs every viable automaton path in lockstep, and returns the selected match start and end.
// Thread payloads hold the match start and the minimal repetition counters.
// Captures are the job of phase B.
//
// Merging keeps the best (start, counters) payload per instruction and position.
// Futures from a shared instruction are identical, and counters only grow.
// The merge therefore keeps the selected candidate.
//
// The workspace is a fresh value per Exec call, so a compiled Regexp stays read-only during execution.
// Ring slots travel by index, never by pointer.

// maxElemAhead is the largest character count one transition can consume.
// localeLoad rejects data whose longest collating element would not fit.
const maxElemAhead = 8

// slotTable holds the payloads for one character boundary.
type slotTable struct {
	stamp  []uint32
	starts []int32
	ctr    []uint32
	active []uint32
	gen    uint32
}

type engineWS struct {
	slots []slotTable
	queue []uint32
	// onq is scratch for compactQueue.
	// It is all false between calls.
	onq     []uint8
	bestCtr []uint32
	ctrBuf  []uint32
	zeros   []uint32
	ahead   []int32
}

// prepare sizes the workspace for a program of n instructions with k counter slots and the given ring size.
// workspaceHeapBound mirrors this sizing for the resource contract, so the two must stay in step.
func prepare(ws *engineWS, n int, k int, ring int) {
	ws.slots = make([]slotTable, ring)
	for i := 0; i < ring; i++ {
		ws.slots[i].stamp = make([]uint32, n)
		ws.slots[i].starts = make([]int32, n)
		if k > 0 {
			ws.slots[i].ctr = make([]uint32, n*k)
		}
	}
	ws.onq = make([]uint8, n)
	if k > 0 {
		ws.bestCtr = make([]uint32, k)
		ws.ctrBuf = make([]uint32, k)
		ws.zeros = make([]uint32, k)
	}
	ws.queue = make([]uint32, 0, 16)
}

// workspaceHeapBound bounds the bytes prepare, the active lists, the closure queue and the lookahead can allocate.
// It covers a program of n instructions with k counter slots and the given ring size.
// It uses fixed 64-bit sizes, so the resource contract reports the same figure on every platform.
// It must change together with prepare and the workspace fields.
//
// The figure is heapFigure of lean/Vego/PhaseA.lean, which lean/Vego/PhaseAProofs.lean proves for every
// program and subject under the portable growth rule: the bytes of prepare, then for every ring slot the
// active list growing to n entries, the queue growing to 2n+1 entries, and the lookahead.
func workspaceHeapBound(n int64, k int64, ring int64) int64 {
	// prepare: the slot structs, the stamp, start and counter arrays, the compaction marks, the counter
	// vectors, and the queue with its initial capacity of 16.
	perSlot := cMul(8, n)
	if k > 0 {
		perSlot = cAdd(perSlot, cMul(4, cMul(n, k)))
	}
	heap := cAdd(cMul(ring, 104), cMul(ring, perSlot))
	heap = cAdd(heap, n)
	if k > 0 {
		heap = cAdd(heap, 12*k)
	}
	heap = cAdd(heap, 64)
	// The growth of every active list, of the queue, and of the lookahead, at twice the final capacity.
	heap = cAdd(heap, cMul(ring, cAdd(cMul(16, n), 64)))
	heap = cAdd(heap, cAdd(cMul(32, n), 272))
	return heap
}

// ctrLess compares two counter vectors lexicographically.
func ctrLess(a []uint32, b []uint32) bool {
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func trailingZeros64(x uint64) int {
	n := 0
	if x&0xffffffff == 0 {
		n += 32
		x >>= 32
	}
	if x&0xffff == 0 {
		n += 16
		x >>= 16
	}
	if x&0xff == 0 {
		n += 8
		x >>= 8
	}
	if x&0xf == 0 {
		n += 4
		x >>= 4
	}
	if x&3 == 0 {
		n += 2
		x >>= 2
	}
	if x&1 == 0 {
		n++
	}
	return n
}

// engineResult reports the phase A outcome in byte offsets.
type engineResult struct {
	matched bool
	so      int
	eo      int
}

// phaseAState carries the per-call executor scalars.
// The regexp and the workspace travel as separate borrowed parameters.
type phaseAState struct {
	subject string
	eflags  uint32
	k       int
	ring    int
	nlMode  bool

	ci   int
	pos  int
	bol  bool
	eol  bool
	cur  int32
	size int

	matched bool
	so      int
	eo      int
}

func runPhaseA(re *Regexp, subject string, eflags uint32) engineResult {
	var ws engineWS
	var e phaseAState
	e.subject = subject
	e.eflags = eflags
	e.k = re.minSlots
	e.ring = 2
	e.nlMode = re.flags&FlagNewline != 0
	if re.prog.multi {
		e.ring = maxElemAhead + 1
	}
	prepare(&ws, len(re.prog.ins), e.k, e.ring)
	paRun(&e, &ws, re)
	var result engineResult
	result.matched = e.matched
	result.so = e.so
	result.eo = e.eo
	return result
}

// paGen returns the generation stamp of one boundary.
// Stamps start at one, so the zeroed slot tables never collide with them.
func paGen(boundary int) uint32 {
	return uint32(boundary) + 1
}

// paConsider records a match candidate.
// It prefers the earliest start, then the smallest counters, then the longest end.
func paConsider(e *phaseAState, ws *engineWS, start int32, ctr []uint32, end int) {
	if !e.matched || int(start) < e.so {
		e.matched = true
		e.so = int(start)
		e.eo = end
		copy(ws.bestCtr[:e.k], ctr)
		return
	}
	if int(start) > e.so {
		return
	}
	if e.k > 0 {
		if ctrLess(ctr, ws.bestCtr[:e.k]) {
			e.eo = end
			copy(ws.bestCtr[:e.k], ctr)
			return
		}
		if ctrLess(ws.bestCtr[:e.k], ctr) {
			return
		}
	}
	if end > e.eo {
		e.eo = end
	}
}

// paPrune reports whether a payload can no longer beat the best candidate.
// Counters only grow, so a lexicographically larger vector stays larger.
func paPrune(e *phaseAState, ws *engineWS, start int32, ctr []uint32) bool {
	if !e.matched {
		return false
	}
	if int(start) > e.so {
		return true
	}
	if int(start) < e.so || e.k == 0 {
		return false
	}
	return ctrLess(ws.bestCtr[:e.k], ctr)
}

// paStore merges a payload into the slot table si.
// It reports whether the payload stayed.
func paStore(e *phaseAState, ws *engineWS, si int, pc uint32, start int32, ctr []uint32) bool {
	if paPrune(e, ws, start, ctr) {
		return false
	}
	if ws.slots[si].stamp[pc] == ws.slots[si].gen {
		oldStart := ws.slots[si].starts[pc]
		if oldStart < start {
			return false
		}
		if oldStart == start {
			if e.k == 0 {
				return false
			}
			base := int(pc) * e.k
			if !ctrLess(ctr, ws.slots[si].ctr[base:base+e.k]) {
				return false
			}
		}
	} else {
		ws.slots[si].stamp[pc] = ws.slots[si].gen
		ws.slots[si].active = append(ws.slots[si].active, pc)
	}
	ws.slots[si].starts[pc] = start
	if e.k > 0 {
		base := int(pc) * e.k
		copy(ws.slots[si].ctr[base:base+e.k], ctr)
	}
	return true
}

// paRelax merges a payload at the current boundary and queues it for the epsilon closure.
func paRelax(e *phaseAState, ws *engineWS, si int, pc uint32, start int32, ctr []uint32) {
	if paStore(e, ws, si, pc, start, ctr) {
		ws.queue = append(ws.queue, pc)
	}
}

// queueCompactFactor sets the compaction threshold as a multiple of the program length.
// The queue can pass that threshold by two pushes before the next pop checks it.
// Append doubling can also leave twice the needed room.
// workspaceHeapBound and the queue test derive their figures from this factor.
const queueCompactFactor = 2

// compactQueue drops duplicate queue entries.
// A duplicate does no harm, because a pop reads the current slot payload.
// One entry per instruction therefore does the same work.
// Dropping the duplicates keeps the queue linear in the program, a bound the resource contract needs.
// The onq marks live only inside this function.
func compactQueue(ws *engineWS) {
	w := 0
	for r := 0; r < len(ws.queue); r++ {
		pc := ws.queue[r]
		if ws.onq[pc] == 0 {
			ws.onq[pc] = 1
			ws.queue[w] = pc
			w++
		}
	}
	ws.queue = ws.queue[:w]
	for i := 0; i < len(ws.queue); i++ {
		ws.onq[ws.queue[i]] = 0
	}
}

// paClosure drains the relaxation queue over the epsilon instructions.
// The queue may hold duplicates, and it compacts past twice the program length.
// Its memory therefore stays linear, and the hot push stays a bare append.
func paClosure(e *phaseAState, ws *engineWS, re *Regexp, si int) {
	limit := queueCompactFactor * len(re.prog.ins)
	for len(ws.queue) > 0 {
		if len(ws.queue) > limit {
			compactQueue(ws)
		}
		pc := ws.queue[len(ws.queue)-1]
		ws.queue = ws.queue[:len(ws.queue)-1]
		if ws.slots[si].stamp[pc] != ws.slots[si].gen {
			continue
		}
		start := ws.slots[si].starts[pc]
		base := int(pc) * e.k
		ctr := ws.slots[si].ctr[base : base+e.k]
		switch re.prog.ins[pc].op {
		case iSplit:
			paRelax(e, ws, si, re.prog.ins[pc].next, start, ctr)
			paRelax(e, ws, si, re.prog.ins[pc].alt, start, ctr)
		case iJmp:
			paRelax(e, ws, si, re.prog.ins[pc].next, start, ctr)
		case iBOL:
			if e.bol {
				paRelax(e, ws, si, re.prog.ins[pc].next, start, ctr)
			}
		case iEOL:
			if e.eol {
				paRelax(e, ws, si, re.prog.ins[pc].next, start, ctr)
			}
		case iMatch:
			paConsider(e, ws, start, ctr, e.pos)
		}
	}
}

// paArrive files a consuming transition into a future boundary slot.
// delta counts the consumed characters.
// Those characters also increment the counters that the instruction's mask selects.
func paArrive(e *phaseAState, ws *engineWS, re *Regexp, pc uint32, delta int, start int32, ctr []uint32) {
	fi := (e.ci + delta) % e.ring
	g := paGen(e.ci + delta)
	if ws.slots[fi].gen != g {
		ws.slots[fi].gen = g
		ws.slots[fi].active = ws.slots[fi].active[:0]
	}
	newCtr := ctr
	mask := re.prog.ins[pc].mask
	hasExtra := len(re.prog.ins[pc].extra) > 0
	if e.k > 0 && (mask != 0 || hasExtra) {
		buffer := ws.ctrBuf[:e.k]
		copy(buffer, ctr)
		for m := mask; m != 0; m &= m - 1 {
			buffer[trailingZeros64(m)] += uint32(delta)
		}
		for i := 0; i < len(re.prog.ins[pc].extra); i++ {
			buffer[re.prog.ins[pc].extra[i]] += uint32(delta)
		}
		newCtr = buffer
	}
	paStore(e, ws, fi, re.prog.ins[pc].next, start, newCtr)
}

// paConsume advances every consuming instruction over the current character or collating element.
func paConsume(e *phaseAState, ws *engineWS, re *Regexp, si int) {
	aheadReady := false
	for ai := 0; ai < len(ws.slots[si].active); ai++ {
		pc := ws.slots[si].active[ai]
		if ws.slots[si].stamp[pc] != ws.slots[si].gen {
			continue
		}
		start := ws.slots[si].starts[pc]
		base := int(pc) * e.k
		ctr := ws.slots[si].ctr[base : base+e.k]
		switch re.prog.ins[pc].op {
		case iRune:
			if e.cur == int32(re.prog.ins[pc].arg) {
				paArrive(e, ws, re, pc, 1, start, ctr)
			}
		case iRuneFold:
			if runesContain(re.prog.foldSets[re.prog.ins[pc].arg], e.cur) {
				paArrive(e, ws, re, pc, 1, start, ctr)
			}
		case iAny:
			if anyMatches(re, e.cur) {
				paArrive(e, ws, re, pc, 1, start, ctr)
			}
		case iBracket:
			bi := int32(re.prog.ins[pc].arg)
			if bracketMatchesOne(re.brackets, bi, &re.loc, e.cur) {
				paArrive(e, ws, re, pc, 1, start, ctr)
			}
			if re.brackets[bi].multiLens == 0 {
				continue
			}
			if !aheadReady {
				decodeAhead(e, ws)
				aheadReady = true
			}
			for length := 2; length <= len(ws.ahead); length++ {
				if re.brackets[bi].multiLens&(1<<length) == 0 {
					continue
				}
				if bracketMatchesMulti(re.brackets, bi, &re.loc, ws.ahead[:length]) {
					paArrive(e, ws, re, pc, length, start, ctr)
				}
			}
		}
	}
}

// decodeAhead fills the lookahead buffer with up to maxElemAhead characters, starting at the current position.
func decodeAhead(e *phaseAState, ws *engineWS) {
	ws.ahead = ws.ahead[:0]
	at := e.pos
	for len(ws.ahead) < maxElemAhead && at < len(e.subject) {
		r, size := decodeRuneAt(e.subject, at)
		ws.ahead = append(ws.ahead, r)
		at += size
	}
}

// scanAhead returns the offset of the next byte in the stop set, or the subject length.
// Stop bytes are ASCII or UTF-8 lead bytes.
// The returned offset is therefore always a boundary that the sequential scan would visit.
func scanAhead(e *phaseAState, re *Regexp) int {
	if re.prog.scan.single {
		idx := indexOfByte(e.subject[e.pos:], re.prog.scan.b)
		if idx < 0 {
			return len(e.subject)
		}
		return e.pos + idx
	}
	for i := e.pos; i < len(e.subject); i++ {
		if re.prog.scan.stop[e.subject[i]] {
			return i
		}
	}
	return len(e.subject)
}

// bolAt reports whether a line begins at the current position, for the given preceding character.
func bolAt(e *phaseAState, prev int32) bool {
	return (e.pos == 0 && e.eflags&ExecNotBOL == 0) ||
		(e.nlMode && prev == '\n')
}

// continuationFlags adapts eflags for a search that restarts at pos on a sliced subject.
// It keeps the bolAt rule above.
// A restart is never the true start.
// Only a preceding newline in newline mode leaves a line boundary before it.
func continuationFlags(re *Regexp, subject string, pos int, eflags uint32) uint32 {
	if pos == 0 {
		return eflags
	}
	if re.flags&FlagNewline != 0 && subject[pos-1] == '\n' {
		return eflags &^ ExecNotBOL
	}
	return eflags | ExecNotBOL
}

func paRun(e *phaseAState, ws *engineWS, re *Regexp) {
	var prev int32 = -2
	zeros := ws.zeros[:e.k]
	for {
		si := e.ci % e.ring
		g := paGen(e.ci)
		ws.slots[si].gen = g
		w := 0
		for r := 0; r < len(ws.slots[si].active); r++ {
			pc := ws.slots[si].active[r]
			if ws.slots[si].stamp[pc] == g {
				ws.slots[si].active[w] = pc
				w++
			}
		}
		ws.slots[si].active = ws.slots[si].active[:w]

		if w == 0 && !e.matched && re.prog.scan.enabled &&
			e.pos < len(e.subject) {
			if !bolAt(e, prev) {
				// No thread is live, and no match can begin on a byte outside the filter.
				// The scan therefore jumps to the next stop byte.
				next := scanAhead(e, re)
				if next > e.pos {
					e.pos = next
					e.ci++
					prev = 'x'
					if e.pos > 0 && e.subject[e.pos-1] == '\n' {
						prev = '\n'
					}
					continue
				}
			}
		}

		atEnd := e.pos == len(e.subject)
		e.cur = -2
		e.size = 0
		if !atEnd {
			e.cur, e.size = decodeRuneAt(e.subject, e.pos)
		}
		e.bol = bolAt(e, prev)
		e.eol = (atEnd && e.eflags&ExecNotEOL == 0) ||
			(e.nlMode && e.cur == '\n')

		ws.queue = append(ws.queue[:0], ws.slots[si].active...)
		if !e.matched {
			paRelax(e, ws, si, re.prog.start, int32(e.pos), zeros)
		}
		paClosure(e, ws, re, si)

		if atEnd {
			return
		}
		paConsume(e, ws, re, si)

		// Stop when nothing is in flight and spawning has stopped.
		if e.matched {
			// Use si and g, because e.ci+delta can overflow a 32-bit int at the end of a huge subject.
			pendingWork := false
			for delta := 1; delta < e.ring; delta++ {
				fi := (si + delta) % e.ring
				if ws.slots[fi].gen == g+uint32(delta) &&
					len(ws.slots[fi].active) > 0 {
					pendingWork = true
					break
				}
			}
			if !pendingWork {
				return
			}
		}

		prev = e.cur
		e.pos += e.size
		e.ci++
	}
}
