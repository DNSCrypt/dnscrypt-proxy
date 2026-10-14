package revera

// This file holds the phase B capture solver.
// Phase A fixed the match span.
// This solver finds the best parse of that span under the selection order.
// It then reads the group spans from the winning parse.
//
// Sibling segments of the comparison vector are independent.
// The best parse of a node over a span therefore does not depend on its context.
// Memoization per (node, span) is valid.
//
// Parse trees live in a flat arena.
// A tree is an index into trees, and a child list is a (kidsOff, kidsLen) window of kidStore.
// The memo tables key on packed int32 tuples.

// ptree is one parse of a pattern node over a character span.
type ptree struct {
	n      int32 // pattern node index
	i      int32 // span start, in characters
	j      int32 // span end
	branch int32 // opAlt: index of the selected branch
	// kidsOff and kidsLen window the child list inside kidStore.
	kidsOff int32
	kidsLen int32
}

type capSolver struct {
	eflags uint32
	// memo caches bestParse: (node, i, j) to a tree index or -1.
	memo memoTab
	// cmemo caches bestConcat: (node, idx, i, j) to a kid window.
	cmemo memoTab
	// rmemo caches bestRep: (node, i, j, state) to a kid window.
	rmemo memoTab
	ctrA  []int
	ctrB  []int
	work  int
	// failed becomes true when the search passes the work limit.
	failed   bool
	trees    []ptree
	kidStore []int32
}

// capWorkLimit bounds the polynomial parse search.
// A search that reaches it reports ESpace instead of looping for a very long time.
const capWorkLimit = 50000000

func capStep(s *capSolver) bool {
	s.work++
	if s.work > capWorkLimit {
		s.failed = true
	}
	return !s.failed
}

// solverArenaLimit caps each arena's entry count.
// A search that needs more reports ESpace, exactly like one that passes the work limit.
// The int32 arena offsets can therefore never overflow.
const solverArenaLimit = 1 << 26

// seedArenas gives each arena one scratch entry at offset zero.
// After a failure, the allocators keep handing out offset zero.
// Candidate comparisons then still read valid records, so the search unwinds without extra guards.
// The failure wins at the end.
func seedArenas(s *capSolver) {
	var scratch ptree
	s.trees = append(s.trees, scratch)
	s.kidStore = append(s.kidStore, -1)
}

// newTree appends one parse-tree node to the arena.
func newTree(s *capSolver, t ptree) int32 {
	if s.failed || len(s.trees) >= solverArenaLimit {
		s.failed = true
		s.trees[0] = t
		return 0
	}
	s.trees = append(s.trees, t)
	return int32(len(s.trees) - 1)
}

// kidAlloc reserves a child window of the given length and returns its offset.
// The caller overwrites every entry.
func kidAlloc(s *capSolver, length int) int {
	if s.failed || len(s.kidStore)+length > solverArenaLimit {
		s.failed = true
		for len(s.kidStore) < length {
			s.kidStore = append(s.kidStore, -1)
		}
		return 0
	}
	off := len(s.kidStore)
	if off+length <= cap(s.kidStore) {
		// The caller fills the window, so the grown entries need no clearing.
		s.kidStore = s.kidStore[:off+length]
		return off
	}
	for i := 0; i < length; i++ {
		s.kidStore = append(s.kidStore, -1)
	}
	return off
}

// kidAlloc1 reserves a one-child window holding t.
func kidAlloc1(s *capSolver, t int32) int {
	off := kidAlloc(s, 1)
	s.kidStore[off] = t
	return off
}

// kidPrepend builds a new window that holds head, followed by a copy of an existing tail window.
func kidPrepend(s *capSolver, head int32, tailOff int, tailLen int) int {
	off := kidAlloc(s, tailLen+1)
	s.kidStore[off] = head
	copy(s.kidStore[off+1:off+1+tailLen],
		s.kidStore[tailOff:tailOff+tailLen])
	return off
}

func setMatch(caps []Match, idx int, so int, eo int) {
	caps[idx].So = so
	caps[idx].Eo = eo
}

// addCounters accumulates the consumed totals of every shortest-preferring repetition, by counter slot.
func addCounters(s *capSolver, re *Regexp, t int32, out []int) {
	ni := s.trees[t].n
	if re.nodes[ni].op == opRepeat && re.nodes[ni].minimal {
		out[re.nodes[ni].index] += int(s.trees[t].j - s.trees[t].i)
	}
	off := int(s.trees[t].kidsOff)
	count := int(s.trees[t].kidsLen)
	for k := 0; k < count; k++ {
		addCounters(s, re, s.kidStore[off+k], out)
	}
}

// structCmp compares two parses of the same pattern node in pre-order.
// It returns a negative value when a wins, and a positive value when b wins.
func structCmp(s *capSolver, re *Regexp, a int32, b int32) int {
	spanA := int(s.trees[a].j - s.trees[a].i)
	spanB := int(s.trees[b].j - s.trees[b].i)
	ni := s.trees[a].n
	if spanA != spanB {
		if re.nodes[ni].op == opRepeat && re.nodes[ni].minimal {
			return spanA - spanB
		}
		return spanB - spanA
	}
	offA := int(s.trees[a].kidsOff)
	offB := int(s.trees[b].kidsOff)
	lenA := int(s.trees[a].kidsLen)
	lenB := int(s.trees[b].kidsLen)
	switch re.nodes[ni].op {
	case opAlt:
		if s.trees[a].branch != s.trees[b].branch {
			// The outer results are equal.
			// The earlier branch takes part at an earlier pre-order position, so it wins.
			return int(s.trees[a].branch - s.trees[b].branch)
		}
		return structCmp(s, re, s.kidStore[offA], s.kidStore[offB])
	case opConcat, opGroup:
		for idx := 0; idx < lenA; idx++ {
			c := structCmp(s, re, s.kidStore[offA+idx], s.kidStore[offB+idx])
			if c != 0 {
				return c
			}
		}
	case opRepeat:
		limit := min(lenA, lenB)
		for idx := 0; idx < limit; idx++ {
			ka := s.kidStore[offA+idx]
			kb := s.kidStore[offB+idx]
			sa := int(s.trees[ka].j - s.trees[ka].i)
			sb := int(s.trees[kb].j - s.trees[kb].i)
			if sa != sb {
				if re.nodes[ni].minimal {
					return sa - sb
				}
				return sb - sa
			}
		}
		if lenA != lenB {
			return lenA - lenB
		}
		for idx := 0; idx < lenA; idx++ {
			c := structCmp(s, re, s.kidStore[offA+idx], s.kidStore[offB+idx])
			if c != 0 {
				return c
			}
		}
	}
	return 0
}

// cmpCand compares two parses of the same pattern node over the same span.
// It compares the minimal repetition counters first, then the structure.
// A negative result means a wins.
//
// After a failure, every allocator hands out offset zero, so a record can name itself as its own child and a walk would never end.
// The failure decides the outcome anyway, so the comparison stops there.
func cmpCand(s *capSolver, re *Regexp, a int32, b int32) int {
	if s.failed {
		return 1
	}
	if re.minSlots > 0 {
		for idx := 0; idx < re.minSlots; idx++ {
			s.ctrA[idx] = 0
			s.ctrB[idx] = 0
		}
		addCounters(s, re, a, s.ctrA)
		addCounters(s, re, b, s.ctrB)
		for idx := 0; idx < re.minSlots; idx++ {
			if s.ctrA[idx] != s.ctrB[idx] {
				return s.ctrA[idx] - s.ctrB[idx]
			}
		}
	}
	return structCmp(s, re, a, b)
}

// bestParse returns the arena index of the best parse of node ni over exactly [i, j), or -1.
func bestParse(s *capSolver, re *Regexp, d *decoded, ni int32, i int, j int) int32 {
	// A saturated maxL means unbounded, never an actual limit.
	span := j - i
	if span < re.nodes[ni].minL ||
		(re.nodes[ni].maxL < lenInf && span > re.nodes[ni].maxL) {
		return -1
	}
	var key memoKey
	key.a = ni
	key.b = int32(i)
	key.c = int32(j)
	cached, hit := memoGet(&s.memo, key)
	if hit {
		return cached.x
	}
	if !capStep(s) {
		return -1
	}
	best := int32(-1)
	switch re.nodes[ni].op {
	case opChar:
		if j == i+1 && charMatches(re, ni, d.runes[i]) {
			best = newTree(s, ptree{n: ni, i: int32(i), j: int32(j)})
		}
	case opAny:
		if j == i+1 && anyMatches(re, d.runes[i]) {
			best = newTree(s, ptree{n: ni, i: int32(i), j: int32(j)})
		}
	case opBracket:
		if bracketMatchesSpan(re.brackets, re.nodes[ni].br, &re.loc,
			d.runes, i, j) {
			best = newTree(s, ptree{n: ni, i: int32(i), j: int32(j)})
		}
	case opBOL:
		if j == i && atBOL(re, d, i, s.eflags) {
			best = newTree(s, ptree{n: ni, i: int32(i), j: int32(j)})
		}
	case opEOL:
		if j == i && atEOL(re, d, i, s.eflags) {
			best = newTree(s, ptree{n: ni, i: int32(i), j: int32(j)})
		}
	case opGroup:
		sub := bestParse(s, re, d, re.nodes[ni].ch[0], i, j)
		if sub >= 0 {
			off := kidAlloc1(s, sub)
			best = newTree(s, ptree{n: ni, i: int32(i), j: int32(j),
				kidsOff: int32(off), kidsLen: 1})
		}
	case opAlt:
		for bi := 0; bi < len(re.nodes[ni].ch); bi++ {
			sub := bestParse(s, re, d, re.nodes[ni].ch[bi], i, j)
			if sub < 0 {
				continue
			}
			off := kidAlloc1(s, sub)
			candidate := newTree(s, ptree{n: ni, i: int32(i), j: int32(j),
				branch: int32(bi), kidsOff: int32(off), kidsLen: 1})
			if best < 0 || cmpCand(s, re, candidate, best) < 0 {
				best = candidate
			}
		}
	case opConcat:
		off, count := bestConcat(s, re, d, ni, 0, i, j)
		if off >= 0 {
			best = newTree(s, ptree{n: ni, i: int32(i), j: int32(j),
				kidsOff: int32(off), kidsLen: int32(count)})
		}
	case opRepeat:
		if i == j && re.nodes[ni].min == 0 {
			// This mirrors the reference matcher.
			// It takes one null occurrence when the operand has a null match and the maximum is not zero.
			sub := int32(-1)
			if re.nodes[ni].max != 0 {
				sub = bestParse(s, re, d, re.nodes[ni].ch[0], i, i)
			}
			if sub >= 0 {
				off := kidAlloc1(s, sub)
				best = newTree(s, ptree{n: ni, i: int32(i), j: int32(j),
					kidsOff: int32(off), kidsLen: 1})
			} else {
				best = newTree(s, ptree{n: ni, i: int32(i), j: int32(j)})
			}
		} else {
			win := bestRep(s, re, d, ni, i, j, 0, false)
			if win.ok {
				best = newTree(s, ptree{n: ni, i: int32(i), j: int32(j),
					kidsOff: int32(win.off), kidsLen: int32(win.length)})
			}
		}
	}
	var val memoVal
	val.x = best
	memoPut(&s.memo, key, val)
	return best
}

// bestConcat returns the kid window of the best child parses of ni.ch[idx:] that cover [i, j).
// It returns a negative offset when no such parse exists.
func bestConcat(s *capSolver, re *Regexp, d *decoded, ni int32, idx int, i int, j int) (int, int) {
	if idx == len(re.nodes[ni].ch)-1 {
		sub := bestParse(s, re, d, re.nodes[ni].ch[idx], i, j)
		if sub < 0 {
			return -1, 0
		}
		return kidAlloc1(s, sub), 1
	}
	var key memoKey
	key.a = ni
	key.b = int32(idx)
	key.c = int32(i)
	key.d = int32(j)
	cached, hit := memoGet(&s.cmemo, key)
	if hit {
		return int(cached.x), int(cached.y)
	}
	if !capStep(s) {
		return -1, 0
	}
	bestOff := -1
	bestLen := 0
	bestTree := int32(-1)
	head0 := re.nodes[ni].ch[idx]
	lo := i + re.nodes[head0].minL
	if re.nodes[ni].sufMax[idx+1] < lenInf {
		lo = max(lo, j-re.nodes[ni].sufMax[idx+1])
	}
	hi := j - re.nodes[ni].sufMin[idx+1]
	if re.nodes[head0].maxL < lenInf {
		hi = min(hi, i+re.nodes[head0].maxL)
	}
	for m := lo; m <= hi; m++ {
		if !capStep(s) {
			return -1, 0
		}
		head := bestParse(s, re, d, head0, i, m)
		if head < 0 {
			continue
		}
		tailOff, tailLen := bestConcat(s, re, d, ni, idx+1, m, j)
		if tailOff < 0 {
			continue
		}
		off := kidPrepend(s, head, tailOff, tailLen)
		candidate := newTree(s, ptree{n: ni, i: int32(i), j: int32(j),
			kidsOff: int32(off), kidsLen: int32(tailLen + 1)})
		if bestTree < 0 || cmpCand(s, re, candidate, bestTree) < 0 {
			bestTree = candidate
			bestOff = off
			bestLen = tailLen + 1
		}
	}
	var val memoVal
	val.x = int32(bestOff)
	val.y = int32(bestLen)
	memoPut(&s.cmemo, key, val)
	return bestOff, bestLen
}

// repBest tracks the winning instance list while bestRep scans the split points.
type repBest struct {
	off    int
	length int
	tree   int32
	found  bool
}

func repTry(s *capSolver, re *Regexp, ni int32, i int, j int, off int, length int, best *repBest) {
	candidate := newTree(s, ptree{n: ni, i: int32(i), j: int32(j),
		kidsOff: int32(off), kidsLen: int32(length)})
	if !best.found || cmpCand(s, re, candidate, best.tree) < 0 {
		best.off = off
		best.length = length
		best.tree = candidate
		best.found = true
	}
}

// repWin is the outcome of one bestRep search.
// It holds the winning kid window, and ok is false when no instance list exists.
type repWin struct {
	off    int
	length int
	ok     bool
}

// bestRep returns the best remaining instance list of repetition ni over [i, j), after done instances.
// It keeps the section 8.5 rule: a null instance is allowed only while the final count stays at the minimum.
func bestRep(s *capSolver, re *Regexp, d *decoded, ni int32, i int, j int, done int, hasEmpty bool) repWin {
	// With no upper bound, done only changes behavior through its comparison with the minimum.
	// Folding larger values onto the minimum keeps the memoized state space quadratic in the span.
	if re.nodes[ni].max == infinite && done > re.nodes[ni].min {
		done = re.nodes[ni].min
	}
	var key memoKey
	key.a = ni
	key.b = int32(i)
	key.c = int32(j)
	key.d = int32(done << 1)
	if hasEmpty {
		key.d |= 1
	}
	var win repWin
	cached, hit := memoGet(&s.rmemo, key)
	if hit {
		win.off = int(cached.x)
		win.length = int(cached.y)
		win.ok = cached.z != 0
		return win
	}
	if !capStep(s) {
		win.off = -1
		return win
	}
	var best repBest
	if i == j && done >= re.nodes[ni].min &&
		(!hasEmpty || done == re.nodes[ni].min) {
		repTry(s, re, ni, i, j, 0, 0, &best)
	}
	canTake := re.nodes[ni].max == infinite || done < re.nodes[ni].max
	if canTake && !(hasEmpty && done >= re.nodes[ni].min) {
		child := re.nodes[ni].ch[0]
		// The remaining instances after this one bound the tail span.
		tailMin := satMul(max(re.nodes[ni].min-done-1, 0),
			re.nodes[child].minL)
		tailMax := lenInf
		if re.nodes[ni].max != infinite {
			tailMax = satMul(re.nodes[ni].max-done-1, re.nodes[child].maxL)
		} else if re.nodes[child].maxL == 0 {
			tailMax = 0
		}
		lo := i + re.nodes[child].minL
		if tailMax < lenInf {
			lo = max(lo, j-tailMax)
		}
		hi := j - tailMin
		if re.nodes[child].maxL < lenInf {
			hi = min(hi, i+re.nodes[child].maxL)
		}
		for m := lo; m <= hi; m++ {
			if m == i && done >= re.nodes[ni].min {
				continue
			}
			if !capStep(s) {
				win.off = -1
				return win
			}
			head := bestParse(s, re, d, child, i, m)
			if head < 0 {
				continue
			}
			tail := bestRep(s, re, d, ni, m, j, done+1, hasEmpty || m == i)
			if !tail.ok {
				continue
			}
			off := kidPrepend(s, head, tail.off, tail.length)
			repTry(s, re, ni, i, j, off, tail.length+1, &best)
		}
	}
	var val memoVal
	val.x = int32(best.off)
	val.y = int32(best.length)
	if best.found {
		val.z = 1
	} else {
		val.x = -1
	}
	memoPut(&s.rmemo, key, val)
	win.off = int(val.x)
	win.length = int(val.y)
	win.ok = best.found
	return win
}

// solveCaptures fills caps with the character spans of the fixed span [so, eo).
func solveCaptures(re *Regexp, d *decoded, so int, eo int, eflags uint32, caps []Match) Error {
	if re.onePass {
		for idx := 0; idx < len(caps); idx++ {
			setMatch(caps, idx, -1, -1)
		}
		setMatch(caps, 0, so, eo)
		if onePassCaps(re, d, re.root, so, eo, eflags, caps) {
			return noError()
		}
		return compileError(ErrESpace, -1)
	}
	var s capSolver
	s.eflags = eflags
	s.ctrA = make([]int, re.minSlots)
	s.ctrB = make([]int, re.minSlots)
	seedArenas(&s)
	best := bestParse(&s, re, d, re.root, so, eo)
	if s.failed {
		return compileError(ErrESpace, -1)
	}
	if best < 0 {
		// Phase A guarantees that a parse exists, so this branch is a bug.
		return compileError(ErrESpace, -1)
	}
	for idx := 0; idx < len(caps); idx++ {
		setMatch(caps, idx, -1, -1)
	}
	setMatch(caps, 0, so, eo)
	assignCaps(re, &s, best, caps)
	return noError()
}

// assignCaps records group spans from the winning parse.
// Entry into a group clears every group nested inside it.
// That is the recursive last-participation rule of section 12.7.
func assignCaps(re *Regexp, s *capSolver, t int32, caps []Match) {
	ni := s.trees[t].n
	if re.nodes[ni].op == opGroup {
		gi := re.nodes[ni].index
		for k := 0; k < len(re.nested[gi]); k++ {
			setMatch(caps, int(re.nested[gi][k]), -1, -1)
		}
		setMatch(caps, gi, int(s.trees[t].i), int(s.trees[t].j))
	}
	off := int(s.trees[t].kidsOff)
	count := int(s.trees[t].kidsLen)
	for k := 0; k < count; k++ {
		assignCaps(re, s, s.kidStore[off+k], caps)
	}
}
