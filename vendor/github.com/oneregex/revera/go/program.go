package revera

// This file lowers the AST into a flat instruction program for the phase A executor.
// Phase A only needs the match relation, the minimal repetition counters, and anchors.
// Groups compile to nothing here.

// Instruction opcodes.
const (
	iRune     uint8 = 0 // consume one character equal to arg
	iRuneFold uint8 = 1 // consume one character in foldSets[arg]
	iAny      uint8 = 2 // consume any character dot accepts
	iBracket  uint8 = 3 // consume per the bracket arena entry arg
	iBOL      uint8 = 4 // assert a line beginning
	iEOL      uint8 = 5 // assert a line end
	iSplit    uint8 = 6 // continue at next and at alt
	iJmp      uint8 = 7 // continue at next
	iMatch    uint8 = 8 // accept
)

type instr struct {
	op   uint8
	next uint32
	alt  uint32
	arg  uint32
	// mask marks the shortest-preferring repetitions this consuming instruction sits inside.
	// It holds one bit per counter slot below 64.
	mask uint64
	// extra lists counter slots at 64 and above, and is almost always nil.
	extra []uint32
}

// scanFilter speeds up positions where no thread is live.
// It holds the bytes that can begin a match from an ordinary mid-subject boundary.
// The executor may skip every byte outside the set, because no match can start there.
// The start closure at such a boundary reaches only the listed consuming instructions, and no accepting state.
type scanFilter struct {
	enabled bool
	single  bool
	b       uint8
	stop    [256]bool
}

type program struct {
	ins      []instr
	start    uint32
	foldSets [][]int32
	// multi is true when some bracket can consume several characters.
	multi bool
	scan  scanFilter
	// depth is the most consuming instructions on any path through a program whose scan filter is enabled
	// with an empty stop set, or -1 when the filter stops on some byte or a consuming cycle leaves the paths
	// unbounded.
	// Such a program seeds no thread past the first boundary, so the resource contract charges depth+3
	// boundaries instead of one per byte; lean/Vego/PhaseAAnchored.lean proves that sufficient.
	depth int
}

// maxProgram caps the expanded program size, because interval expansion can multiply nested counts.
// A pattern past the cap fails to compile with ESpace.
const maxProgram = 1 << 20

// maskWidth is the number of counter slots one mask word covers.
const maskWidth = 64

type patchSlot struct {
	idx uint32
	alt bool
}

type frag struct {
	start uint32
	out   []patchSlot
}

type progBuilder struct {
	prog    program
	tooBig  bool
	errCode int32
	icase   bool
}

// buildScanFilter derives the skip byte set for mid-subject boundaries.
// It walks epsilon transitions from the start, with both anchors off.
// It records the first bytes of the reachable consuming instructions.
// It gives up when dot, a bracket, or a reachable accept makes the filter unsound.
// newlineMode forces a stop at every newline, because anchors gain line boundaries there.
// It returns the number of stop bytes, which is zero when the filter is off.
func buildScanFilter(pr *program, newlineMode bool) int {
	ok := true
	matchReachable := false
	seen := make([]bool, len(pr.ins))
	stack := make([]uint32, 0, 16)
	stack = append(stack, pr.start)
	for len(stack) > 0 {
		pc := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[pc] {
			continue
		}
		seen[pc] = true
		switch pr.ins[pc].op {
		case iSplit:
			stack = append(stack, pr.ins[pc].next, pr.ins[pc].alt)
		case iJmp:
			stack = append(stack, pr.ins[pc].next)
		case iBOL:
			// Anchors are off at a mid-subject boundary.
		case iEOL:
			// Same as iBOL.
		case iMatch:
			matchReachable = true
		case iRune:
			pr.scan.stop[utf8LeadByte(int32(pr.ins[pc].arg))] = true
		case iRuneFold:
			set := pr.ins[pc].arg
			for i := 0; i < len(pr.foldSets[set]); i++ {
				pr.scan.stop[utf8LeadByte(pr.foldSets[set][i])] = true
			}
		default:
			// Dot and brackets accept too much to filter.
			ok = false
		}
	}
	if matchReachable || !ok || pr.multi {
		var none scanFilter
		pr.scan = none
		return 0
	}
	if newlineMode {
		pr.scan.stop['\n'] = true
	}
	pr.scan.enabled = true
	count := 0
	for b := 0; b < 256; b++ {
		if pr.scan.stop[b] {
			count++
			pr.scan.b = uint8(b)
		}
	}
	pr.scan.single = count == 1
	return count
}

// instrCount returns how many instructions emit produces for a node, or maxProgram+1 when that is more.
func instrCount(nodes []node, ni int32) int {
	total := 0
	switch nodes[ni].op {
	case opGroup:
		return instrCount(nodes, nodes[ni].ch[0])
	case opConcat, opAlt:
		if nodes[ni].op == opAlt {
			// Every branch but the last starts with a split.
			total = len(nodes[ni].ch) - 1
		}
		for i := 0; i < len(nodes[ni].ch); i++ {
			total += instrCount(nodes, nodes[ni].ch[i])
			if total > maxProgram {
				return maxProgram + 1
			}
		}
		return total
	case opRepeat:
		lo := nodes[ni].min
		hi := nodes[ni].max
		if hi == 0 {
			return 1
		}
		child := instrCount(nodes, nodes[ni].ch[0])
		if hi == infinite {
			// The last copy loops back through a split.
			total = max(lo, 1)*child + 1
		} else {
			// Every optional copy starts with a split.
			total = lo*child + (hi-lo)*(child+1)
		}
		return min(total, maxProgram+1)
	}
	return 1
}

// compileProgram lowers the AST into b.prog.
// The caller sets icase before the call, and reads tooBig and errCode after it.
// tooBig with a zero code means the expansion passed the size cap.
func compileProgram(b *progBuilder, nodes []node, root int32, multi bool, newlineMode bool) {
	// The final match instruction needs one more slot.
	if instrCount(nodes, root) >= maxProgram {
		b.tooBig = true
		return
	}
	body := emit(b, nodes, root, 0, nil)
	if b.errCode != ErrNone {
		return
	}
	var m instr
	m.op = iMatch
	match := addInstr(b, m)
	if b.errCode != ErrNone || b.tooBig {
		return
	}
	patch(b, body.out, match)
	b.prog.start = body.start
	b.prog.multi = multi
	stops := buildScanFilter(&b.prog, newlineMode)
	b.prog.depth = -1
	if !newlineMode && b.prog.scan.enabled && stops == 0 {
		b.prog.depth = progDepth(&b.prog)
	}
}

// consumingOp reports whether an opcode consumes a character.
// The consuming opcodes come first in the table.
func consumingOp(op uint8) bool {
	return op <= iBracket
}

// progEdge returns the i-th successor of one instruction.
// An accept has none, a split has two, and every other instruction has one.
func progEdge(pr *program, pc uint32, i int) (uint32, bool) {
	op := pr.ins[pc].op
	if op == iMatch {
		return 0, false
	}
	if i == 0 {
		return pr.ins[pc].next, true
	}
	if i == 1 && op == iSplit {
		return pr.ins[pc].alt, true
	}
	return 0, false
}

// progDepth returns the most consuming instructions on any path through the program, or -1 when a
// consuming cycle leaves that unbounded.
// It relaxes one label per instruction, in instruction order: every edge raises its target to its source,
// plus one when the source consumes.
// The emitter lays an acyclic program out with every edge pointing forward, so the first round settles the
// labels and the second confirms it, while a second round that still raises a label has found a consuming
// cycle.
// A cycle of epsilon instructions settles too, so a star over an empty body keeps its bound.
// The Lean link relaxes the same labels to their fixed point and checks that this value is their maximum.
func progDepth(pr *program) int {
	n := len(pr.ins)
	depth := make([]int32, n)
	for round := 0; round < 2; round++ {
		changed := false
		for pc := 0; pc < n; pc++ {
			weight := int32(0)
			if consumingOp(pr.ins[pc].op) {
				weight = 1
			}
			for e := 0; e < 2; e++ {
				target, has := progEdge(pr, uint32(pc), e)
				if has && depth[target] < depth[pc]+weight {
					depth[target] = depth[pc] + weight
					changed = true
				}
			}
		}
		if !changed {
			best := int32(0)
			for pc := 0; pc < n; pc++ {
				best = max(best, depth[pc])
			}
			return int(best)
		}
	}
	return -1
}

func addInstr(b *progBuilder, ins instr) uint32 {
	if b.tooBig {
		return 0
	}
	if len(b.prog.ins) >= maxProgram {
		b.tooBig = true
		return 0
	}
	b.prog.ins = append(b.prog.ins, ins)
	return uint32(len(b.prog.ins) - 1)
}

func patch(b *progBuilder, slots []patchSlot, target uint32) {
	if b.tooBig {
		return
	}
	for i := 0; i < len(slots); i++ {
		if slots[i].alt {
			b.prog.ins[slots[i].idx].alt = target
		} else {
			b.prog.ins[slots[i].idx].next = target
		}
	}
}

// singleOut builds the out list of a one-exit fragment.
func singleOut(idx uint32, alt bool) []patchSlot {
	var slot patchSlot
	slot.idx = idx
	slot.alt = alt
	out := make([]patchSlot, 0, 1)
	return append(out, slot)
}

// epsilonFrag returns a fragment that consumes nothing.
func epsilonFrag(b *progBuilder) frag {
	var j instr
	j.op = iJmp
	idx := addInstr(b, j)
	var f frag
	f.start = idx
	f.out = singleOut(idx, false)
	return f
}

// copyExtra duplicates an extra-slot list, so instructions never share one buffer.
func copyExtra(extra []uint32) []uint32 {
	if len(extra) == 0 {
		return nil
	}
	dup := make([]uint32, len(extra))
	copy(dup, extra)
	return dup
}

// consumeFrag appends one consuming instruction and wraps it as a fragment.
func consumeFrag(b *progBuilder, op uint8, arg uint32, mask uint64, extra []uint32) frag {
	var ins instr
	ins.op = op
	ins.arg = arg
	ins.mask = mask
	ins.extra = copyExtra(extra)
	idx := addInstr(b, ins)
	var f frag
	f.start = idx
	f.out = singleOut(idx, false)
	return f
}

func emit(b *progBuilder, nodes []node, ni int32, mask uint64, extra []uint32) frag {
	var none frag
	if b.errCode != ErrNone || b.tooBig {
		return none
	}
	switch nodes[ni].op {
	case opChar:
		if b.icase {
			arg := uint32(len(b.prog.foldSets))
			foldCopy := make([]int32, len(nodes[ni].fold))
			copy(foldCopy, nodes[ni].fold)
			b.prog.foldSets = append(b.prog.foldSets, foldCopy)
			return consumeFrag(b, iRuneFold, arg, mask, extra)
		}
		return consumeFrag(b, iRune, uint32(nodes[ni].r), mask, extra)
	case opAny:
		return consumeFrag(b, iAny, 0, mask, extra)
	case opBracket:
		return consumeFrag(b, iBracket, uint32(nodes[ni].br), mask, extra)
	case opBOL:
		return consumeFrag(b, iBOL, 0, 0, nil)
	case opEOL:
		return consumeFrag(b, iEOL, 0, 0, nil)
	case opGroup:
		return emit(b, nodes, nodes[ni].ch[0], mask, extra)
	case opConcat:
		result := emit(b, nodes, nodes[ni].ch[0], mask, extra)
		for i := 1; i < len(nodes[ni].ch); i++ {
			next := emit(b, nodes, nodes[ni].ch[i], mask, extra)
			if b.errCode != ErrNone {
				return none
			}
			patch(b, result.out, next.start)
			result.out = next.out
		}
		return result
	case opAlt:
		return emitAlt(b, nodes, ni, mask, extra)
	case opRepeat:
		return emitRepeat(b, nodes, ni, mask, extra)
	}
	b.errCode = ErrBadPat
	return none
}

func emitAlt(b *progBuilder, nodes []node, ni int32, mask uint64, extra []uint32) frag {
	var none frag
	var result frag
	splits := make([]uint32, 0, len(nodes[ni].ch))
	count := len(nodes[ni].ch)
	for i := 0; i < count; i++ {
		if i < count-1 {
			var s instr
			s.op = iSplit
			splits = append(splits, addInstr(b, s))
		}
		sub := emit(b, nodes, nodes[ni].ch[i], mask, extra)
		if b.errCode != ErrNone || b.tooBig {
			return none
		}
		if i < count-1 {
			b.prog.ins[splits[i]].next = sub.start
		} else {
			b.prog.ins[splits[i-1]].alt = sub.start
		}
		if i > 0 && i < count-1 {
			b.prog.ins[splits[i-1]].alt = splits[i]
		}
		result.out = append(result.out, sub.out...)
	}
	result.start = splits[0]
	return result
}

// fragAppend chains f after result, or starts result with f.
// It returns true, so a caller can update its have flag in one line.
func fragAppend(b *progBuilder, result *frag, have bool, f frag) bool {
	if !have {
		result.start = f.start
		result.out = f.out
		return true
	}
	patch(b, result.out, f.start)
	result.out = f.out
	return true
}

func emitRepeat(b *progBuilder, nodes []node, ni int32, mask uint64, extra []uint32) frag {
	var none frag
	if nodes[ni].minimal {
		slot := nodes[ni].index
		if slot < maskWidth {
			mask |= uint64(1) << slot
		} else {
			// The copy keeps sibling fragments from sharing the grown list.
			grown := make([]uint32, len(extra)+1)
			copy(grown, extra)
			grown[len(extra)] = uint32(slot)
			extra = grown
		}
	}
	child := nodes[ni].ch[0]
	lo := nodes[ni].min
	hi := nodes[ni].max

	if lo == 0 && hi == 0 {
		return epsilonFrag(b)
	}

	var result frag
	haveResult := false

	// These are the required copies.
	// The last one loops when the maximum is unbounded.
	for i := 0; i < lo; i++ {
		if b.errCode != ErrNone || b.tooBig {
			return none
		}
		if i == lo-1 && hi == infinite {
			fragAppend(b, &result, haveResult, emitPlus(b, nodes, child, mask, extra))
			return result
		}
		haveResult = fragAppend(b, &result, haveResult,
			emit(b, nodes, child, mask, extra))
	}

	if hi == infinite {
		// The minimum is zero here, so this is a plain star.
		fragAppend(b, &result, haveResult, emitStar(b, nodes, child, mask, extra))
		return result
	}

	// These are the optional copies, and each one may skip straight to the shared exit.
	skips := make([]patchSlot, 0, max(hi-lo, 1))
	for i := lo; i < hi; i++ {
		if b.errCode != ErrNone || b.tooBig {
			return none
		}
		var s instr
		s.op = iSplit
		split := addInstr(b, s)
		sub := emit(b, nodes, child, mask, extra)
		if b.errCode != ErrNone || b.tooBig {
			return none
		}
		b.prog.ins[split].next = sub.start
		var slot patchSlot
		slot.idx = split
		slot.alt = true
		skips = append(skips, slot)
		var piece frag
		piece.start = split
		piece.out = sub.out
		haveResult = fragAppend(b, &result, haveResult, piece)
	}
	result.out = append(result.out, skips...)
	if !haveResult {
		return epsilonFrag(b)
	}
	return result
}

func emitStar(b *progBuilder, nodes []node, child int32, mask uint64, extra []uint32) frag {
	var none frag
	var s instr
	s.op = iSplit
	split := addInstr(b, s)
	body := emit(b, nodes, child, mask, extra)
	if b.errCode != ErrNone || b.tooBig {
		return none
	}
	b.prog.ins[split].next = body.start
	patch(b, body.out, split)
	var f frag
	f.start = split
	f.out = singleOut(split, true)
	return f
}

func emitPlus(b *progBuilder, nodes []node, child int32, mask uint64, extra []uint32) frag {
	var none frag
	body := emit(b, nodes, child, mask, extra)
	if b.errCode != ErrNone || b.tooBig {
		return none
	}
	var s instr
	s.op = iSplit
	split := addInstr(b, s)
	b.prog.ins[split].next = body.start
	patch(b, body.out, split)
	var f frag
	f.start = body.start
	f.out = singleOut(split, true)
	return f
}
