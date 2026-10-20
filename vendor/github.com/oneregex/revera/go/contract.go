package revera

// This file computes resource contracts.
// A contract bounds, for each backend, what one Exec call can use on a subject of a given maximum length.
// An application can compare the figures against its budget and refuse a pattern before it ever runs.
//
// Heap figures count explicit allocation requests with fixed 64-bit field sizes and conservative allowances.
// They are therefore the same on every platform.
// Capture figures include allocator rounding for the three short-lived buffers.
// Runtime object headers, general allocator metadata, map buckets, and garbage-collector bookkeeping stay outside
// this portable model.
// Stack figures multiply the deepest possible call chain by a fixed per-frame estimate.
// Step figures count abstract unit-cost operations, not nanoseconds.
// They are worst-case bounds, and ordinary subjects stay far below them.

// BackendContract bounds the resources one backend can use during a single Exec call.
type BackendContract struct {
	// HeapBytes bounds the explicit heap allocations, in bytes.
	HeapBytes int64
	// StackBytes estimates the deepest call stack, in bytes.
	StackBytes int64
	// Steps bounds the abstract operations the backend can perform.
	Steps int64
}

// Contract bounds the resources of one Exec call on a subject of at most MaxInput bytes.
// MaxInput is the bound the figures cover.
// It is the requested value, clamped to the subject limit of Exec and to zero from below.
// Execution has three backends:
//
//   - Matcher is the phase A automaton.
//     It always runs, and it answers every call that needs no group offsets.
//   - OnePass is the phase B capture walk.
//     HasOnePass is set when compilation proved that every span has one parse.
//     It is then the only phase B backend that can run.
//   - Solver is the phase B memoized parse search.
//     HasSolver is set when parenthesized subexpression offsets require the general parse search.
//     HasOnePass and HasSolver are mutually exclusive.
//
// Every value saturates at 1<<62, which marks a bound too large to be useful.
// The figures assume a pmatch of at most NumSub()+1 elements, which is what every host API passes.
// Each extra element costs one more step, since Exec clears it.
// The per-call workspace counts once.
// Each capture backend includes the shared window allocations.
// ContractHeapBytes combines the matcher with the selected capture backend.
type Contract struct {
	MaxInput   int
	Matcher    BackendContract
	OnePass    BackendContract
	HasOnePass bool
	Solver     BackendContract
	HasSolver  bool
}

// contractCap saturates contract arithmetic.
// It leaves room to add saturated values without overflow.
const contractCap = int64(1) << 62

// Fixed 64-bit sizes of the records the contract counts, in bytes.
// The values absorb growth by append doubling, the load factor of the memo tables, and the rehash transient.
const (
	// frameBytes estimates one recursive call frame.
	frameBytes = 256
	// matcherStackBytes covers the fixed frames of the iterative phase A executor.
	matcherStackBytes = 2048
	// singleLookupFrames is the call depth below a single-character bracket test.
	singleLookupFrames = 8
	// multiLookupFrames is the call depth below a multi-character probe, which recurses once per lookahead
	// character.
	multiLookupFrames = maxElemAhead + 8
	// ptreeBytes is one solver parse-tree record of 24 bytes, with arena doubling folded in.
	ptreeBytes = 48
	// kidBytes is one child-list entry of 4 bytes, with doubling folded in.
	kidBytes = 8
	// mapEntryBytes is one memo record: a 16-byte key, a 12-byte value, and a mark.
	// It assumes a 3/4 load and folds in the rehash transient.
	mapEntryBytes = 128
	// matchBytes is the size of one Match.
	matchBytes = 16
)

func cAdd(a int64, b int64) int64 {
	if a > contractCap-b {
		return contractCap
	}
	return a + b
}

func cMul(a int64, b int64) int64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > contractCap/b {
		return contractCap
	}
	return a * b
}

// ContractHeapBytes bounds the heap of one whole call.
// It adds the matcher workspace and the selected capture backend.
func ContractHeapBytes(c *Contract) int64 {
	capture := int64(0)
	if c.HasOnePass {
		capture = c.OnePass.HeapBytes
	}
	if c.HasSolver {
		capture = max(capture, c.Solver.HeapBytes)
	}
	return cAdd(c.Matcher.HeapBytes, capture)
}

// ContractStackBytes bounds the stack of one whole call.
func ContractStackBytes(c *Contract) int64 {
	deepest := c.Matcher.StackBytes
	if c.HasOnePass {
		deepest = max(deepest, c.OnePass.StackBytes)
	}
	if c.HasSolver {
		deepest = max(deepest, c.Solver.StackBytes)
	}
	return deepest
}

// ContractSteps bounds the operations of one whole call.
// It combines the matcher with the selected capture backend.
func ContractSteps(c *Contract) int64 {
	steps := c.Matcher.Steps
	if c.HasOnePass {
		steps = cAdd(steps, c.OnePass.Steps)
	}
	if c.HasSolver {
		steps = cAdd(steps, c.Solver.Steps)
	}
	return steps
}

// ContractFor returns the resource contract of one compiled expression for subjects of at most maxInput bytes.
// A larger maxInput clamps to the subject limit of Exec.
func ContractFor(re *Regexp, maxInput int) Contract {
	length := int64(min(max(maxInput, 0), subjectLimit))
	atom := atomCost(re)
	var c Contract
	c.MaxInput = int(length)
	c.Matcher = matcherContract(re, length, atom)
	if re.nsub > 0 && re.flags&FlagNoSub == 0 {
		if re.onePass {
			c.OnePass = onePassContract(re, length)
			c.HasOnePass = true
		} else {
			c.Solver = solverContract(re, length, atom)
			c.HasSolver = true
		}
	}
	return c
}

// matcherContract bounds phase A.
// length is the subject bound in bytes, and it also bounds the character count.
func matcherContract(re *Regexp, length int64, atom int64) BackendContract {
	var b BackendContract
	n := int64(len(re.prog.ins))
	k := int64(re.minSlots)
	ring := int64(2)
	if re.prog.multi {
		ring = maxElemAhead + 1
	}

	// The per-call workspace and everything that grows in it.
	heap := workspaceHeapBound(n, k, ring)

	// The step figure is stepsFigure of lean/Vego/PhaseA.lean, which lean/Vego/PhaseAProofs.lean proves for
	// every program and subject.
	// One boundary pays for its closure, priced by a potential of (n+1)^2 units at weight 4k+22 each, which
	// covers every pop, every relaxation and every compaction; for its consuming transitions, one test and
	// up to ring-1 arrivals per live instruction; and for its fixed work.
	weight := cAdd(cMul(4, k), 22)
	perTest := cAdd(cAdd(atom, 2), cMul(ring-1, cAdd(cMul(4, k), 12)))
	perBoundary := cMul(weight, cMul(n+1, n+1))
	perBoundary = cAdd(perBoundary, cMul(n, perTest))
	perBoundary = cAdd(perBoundary, cAdd(cAdd(n, cMul(2, k)), cAdd(cMul(4, ring), 38)))

	// A run visits at most one boundary per byte, plus the end.
	// When the program depth is bounded, the figure is stepsFigureAnchored of lean/Vego/PhaseAAnchored.lean,
	// which proves that the run visits at most depth+3 boundaries instead.
	boundaries := cAdd(length, 1)
	if re.prog.depth >= 0 {
		boundaries = min(boundaries, int64(re.prog.depth)+3)
	}
	steps := cAdd(cAdd(24+ring, length), cMul(boundaries, perBoundary))

	// A bracket probe can start the deepest lookup below the fixed frames.
	stack := int64(matcherStackBytes) + multiLookupFrames*frameBytes

	b.HeapBytes = heap
	b.StackBytes = stack
	b.Steps = steps
	return b
}

// runeCountSteps bounds one runeCount call over length bytes.
// Each loop pass pays its test, a decodeRuneAt call, and a utf8Cont call per byte the decoder looks at.
// An invalid sequence that fails after k such calls advances one byte for 2+k steps, and the k bytes it looked past are then counted again at two steps each.
// That's at most three steps per byte, and valid input costs less.
// The call and the final loop test add two.
func runeCountSteps(length int64) int64 {
	return cAdd(cMul(3, length), 2)
}

// captureHeap bounds the allocations every capture call performs before its backend runs.
// It counts the decoded window and span buffer, then adds an allowance for allocator rounding.
func captureHeap(re *Regexp, length int64) int64 {
	window := cAdd(cMul(4, length), cMul(8, cAdd(length, 1)))
	spans := cMul(matchBytes, cAdd(int64(re.nsub), 1))
	payload := cAdd(window, spans)
	// Go's size-class gaps are below 8 KiB, and large allocations round to 8 KiB pages.
	// One page per buffer therefore covers the rounding whatever the subject length is.
	allowance := int64(3 * 8192)
	return cAdd(cAdd(payload, allowance), 64)
}

// onePassContract bounds the phase B capture walk, which allocates nothing itself.
func onePassContract(re *Regexp, length int64) BackendContract {
	var b BackendContract
	b.HeapBytes = captureHeap(re, length)
	// Two entry frames sit above the walk, and a bracket test can start a lookup below it.
	b.StackBytes = cMul(cAdd(astHeight(re.nodes, re.root), 2+singleLookupFrames),
		frameBytes)
	// Besides the walk, the capture phase decodes the window and fills in up to nsub+1 spans.
	lc := localeLookupCosts(&re.loc)
	once, perChar := onePassWalk(re, &lc, re.root, false)
	steps := cAdd(once, cMul(length, perChar))
	steps = cAdd(steps, runeCountSteps(length))
	b.Steps = cAdd(steps, 5*int64(re.nsub)+14)
	return b
}

// onePassVisitCost is the cost of one onePassCaps visit of node ni, not counting its children.
func onePassVisitCost(re *Regexp, lc *lookupCosts, ni int32) int64 {
	count := int64(len(re.nodes[ni].ch))
	switch re.nodes[ni].op {
	case opChar:
		if re.flags&FlagICase != 0 {
			return int64(len(re.nodes[ni].fold)) + 4
		}
	case opBracket:
		return cAdd(1, matchesOneCost(re.brackets, re.nodes[ni].br, lc))
	case opGroup:
		return 3 + 2*int64(len(re.nested[re.nodes[ni].index]))
	case opConcat:
		return 3 + 3*count
	case opAlt:
		cost := 3 + 4*count
		for i := 0; i < len(re.nodes[ni].firsts); i++ {
			cost += int64(len(re.nodes[ni].firsts[i]))
		}
		return cost
	}
	return 2
}

// onePassWalk splits the cost of walking the subtree at ni into a fixed part and a part paid per character.
// A node outside any repetition is visited once.
// A node inside one is visited once per iteration, and iterations match disjoint, nonempty spans, so that's at most once per character.
// Each iteration also pays one loop test.
func onePassWalk(re *Regexp, lc *lookupCosts, ni int32, repeated bool) (int64, int64) {
	once := int64(0)
	perChar := int64(0)
	if repeated {
		perChar = onePassVisitCost(re, lc, ni)
	} else {
		once = onePassVisitCost(re, lc, ni)
	}
	isRepeat := re.nodes[ni].op == opRepeat
	for i := 0; i < len(re.nodes[ni].ch); i++ {
		o, p := onePassWalk(re, lc, re.nodes[ni].ch[i], repeated || isRepeat)
		once = cAdd(once, o)
		perChar = cAdd(perChar, p)
		if isRepeat {
			perChar = cAdd(perChar, 1)
		}
	}
	return once, perChar
}

// solverContract bounds the phase B memoized parse search.
func solverContract(re *Regexp, length int64, atom int64) BackendContract {
	var b BackendContract
	depth := solverDepth(re.nodes, re.root, length)
	structural := min(solverSteps(re.nodes, re.root, length),
		cAdd(capWorkLimit, depth))
	tree := treeNodes(re.nodes, re.root, length)

	// One counted step can test one atom, compare two candidate trees, and touch the counter vectors.
	// A tree comparison walks both trees in full, and the work counter does not see that walk.
	// The tree size bound pays for it instead.
	// Reading the groups from the winning parse clears nested groups per visited node, and that walk runs once.
	perStep := cAdd(atom, cAdd(cMul(2, tree),
		cMul(2, int64(re.minSlots))+4))
	steps := cAdd(cMul(structural, perStep),
		cMul(tree, int64(re.nsub)+2))

	// One counted step can allocate parse records, one child list, and one memo record.
	// The slack term covers the solver struct, the counter vectors, and the initial table headers.
	perAlloc := cAdd(2*ptreeBytes+mapEntryBytes,
		cMul(kidBytes, cAdd(solverFanout(re.nodes, re.root, length), 1)))
	heap := cAdd(cMul(structural, perAlloc),
		cMul(16, int64(re.minSlots)))
	heap = cAdd(heap, 4096)
	heap = cAdd(heap, captureHeap(re, length))

	// Two entry frames sit above the parse search, and a span test can start a probe below it.
	stack := cMul(cAdd(depth, 3+multiLookupFrames), frameBytes)

	b.HeapBytes = heap
	b.StackBytes = stack
	b.Steps = steps
	return b
}

// astHeight returns the pattern tree height under ni.
func astHeight(nodes []node, ni int32) int64 {
	deepest := int64(0)
	for i := 0; i < len(nodes[ni].ch); i++ {
		deepest = max(deepest, astHeight(nodes, nodes[ni].ch[i]))
	}
	return deepest + 1
}

// atomCost bounds the operations one atom test can perform.
func atomCost(re *Regexp) int64 {
	lc := localeLookupCosts(&re.loc)
	return atomCostNode(re.nodes, re.brackets, &lc, re.root)
}

func atomCostNode(nodes []node, brs []bracketSet, lc *lookupCosts, ni int32) int64 {
	cost := int64(1)
	switch nodes[ni].op {
	case opChar:
		cost = int64(len(nodes[ni].fold)) + 1
	case opBracket:
		cost = bracketAtomCost(brs, nodes[ni].br, lc)
	}
	for i := 0; i < len(nodes[ni].ch); i++ {
		cost = max(cost, atomCostNode(nodes, brs, lc, nodes[ni].ch[i]))
	}
	return cost
}

// The bracket figures are in loop-meter units, so the contract stays above what the interpreted engine's meter counts.
// That meter ticks once per call and once per loop test, including the last one that fails.
// Each helper prices the engine function it is named after.

// searchSteps bounds the probes of a binary search over count entries.
func searchSteps(count int) int64 {
	steps := int64(0)
	for count > 0 {
		count /= 2
		steps++
	}
	return steps
}

const profileRowCost = 13

func u32ContainsCost(count int) int64 {
	return 2 + 3*searchSteps(count)
}

func findPairCost(count int) int64 {
	return 3 + 3*searchSteps(count)
}

func findCaseCost(count int) int64 {
	return 6 + 3*searchSteps(count)
}

func pairSourcesRunCost(count int, preimages int64) int64 {
	return 6 + 3*searchSteps(count) + 5*preimages
}

func compareSequenceCost(length int64) int64 {
	return 6 + 3*length
}

// lookupCosts holds the prices of the locale lookups a bracket test can call, one per function it names.
type lookupCosts struct {
	sequenceSearch int64
	contraction    int64
	primaryToken   int64
	classMask      int64
	casePreimages  int64
	caseConvert    int64
	// preimages is the most case preimages one character can have.
	preimages int64
}

// localeLookupCosts derives the lookup prices from the tables of one locale.
func localeLookupCosts(l *Locale) lookupCosts {
	var lc lookupCosts
	if l.posix {
		// POSIX searches no table.
		lc.contraction = 1
		lc.classMask = 3
		lc.casePreimages = 2
		lc.caseConvert = 2
		lc.preimages = 1
		return lc
	}
	lc.sequenceSearch = searchSteps(sectionLen(l, secSequences) / 8)
	row := collationProfileRow(l, int(l.collationProfile))
	lc.contraction = 1 + profileRowCost + u32ContainsCost(int(row.AddCount)) + 1 +
		u32ContainsCost(sectionLen(l, secRootContractions)/4) +
		u32ContainsCost(int(row.RemoveCount))
	lc.primaryToken = 1 + profileRowCost + findPairCost(int(row.OverrideCount)) + 1 +
		findPairCost(sectionLen(l, secRootEquivalences)/8)
	lc.classMask = 4
	lc.preimages = int64(localeMaxPreimages(l))
	lc.caseConvert = 2 + findCaseCost(sectionLen(l, secCaseDefault)/12)
	upper := secInvUpperDefault
	lower := secInvLowerDefault
	if l.caseProfile == 1 {
		lc.caseConvert += findCaseCost(sectionLen(l, secCaseTurkic) / 12)
		upper = secInvUpperTurkic
		lower = secInvLowerTurkic
	}
	lc.casePreimages = 3 + pairSourcesRunCost(sectionLen(l, upper)/8, lc.preimages) +
		pairSourcesRunCost(sectionLen(l, lower)/8, lc.preimages) +
		lc.preimages*(2+lc.preimages)
	return lc
}

// elementIDCost prices one elementID call over a sequence of length characters.
func elementIDCost(lc *lookupCosts, length int64) int64 {
	if length == 1 {
		return 4
	}
	return 4 + 2*length + lc.sequenceSearch*(1+compareSequenceCost(length))
}

func collatingElementIDCost(lc *lookupCosts, length int64) int64 {
	cost := 1 + elementIDCost(lc, length)
	if length > 1 {
		cost += lc.contraction
	}
	return cost
}

// primaryEqualCost prices one localePrimaryEqual call over sequences of the two lengths.
func primaryEqualCost(lc *lookupCosts, left int64, right int64) int64 {
	return 1 + collatingElementIDCost(lc, left) + collatingElementIDCost(lc, right) +
		2*lc.primaryToken
}

// equivsCost prices the comparison of a sequence of length characters with every equivalence class.
func equivsCost(brs []bracketSet, bi int32, lc *lookupCosts, length int64) int64 {
	cost := int64(1)
	for i := 0; i < len(brs[bi].equivs); i++ {
		cost = cAdd(cost, 1+primaryEqualCost(lc, length, int64(len(brs[bi].equivs[i]))))
	}
	return cost
}

func positiveSingleCost(brs []bracketSet, bi int32, lc *lookupCosts) int64 {
	cost := 3 + searchSteps(len(brs[bi].ranges))
	if brs[bi].classMask != 0 {
		cost += lc.classMask
	}
	return cAdd(cost, equivsCost(brs, bi, lc, 1))
}

func matchesOneCost(brs []bracketSet, bi int32, lc *lookupCosts) int64 {
	positive := positiveSingleCost(brs, bi, lc)
	cost := cAdd(1, positive)
	if brs[bi].icase {
		cost = cAdd(cost, cAdd(lc.casePreimages+1,
			cMul(lc.preimages, cAdd(1, positive))))
	}
	return cost
}

// candidateLeafCost prices the membership test of one candidate sequence in equivCandidate.
func candidateLeafCost(brs []bracketSet, bi int32, lc *lookupCosts, length int64) int64 {
	return cAdd(2+collatingElementIDCost(lc, length), equivsCost(brs, bi, lc, length))
}

// probeCost prices one bracketMatchesMulti call over a lookahead of length characters.
func probeCost(brs []bracketSet, bi int32, lc *lookupCosts, length int64) int64 {
	cost := cAdd(3, int64(len(brs[bi].elems)))
	counterpart := int64(2)
	if brs[bi].icase {
		counterpart = 4 + 2*lc.caseConvert
	}
	for i := 0; i < len(brs[bi].elems); i++ {
		if int64(len(brs[bi].elems[i])) == length {
			cost = cAdd(cost, cMul(length, counterpart))
		}
	}
	if len(brs[bi].equivs) == 0 {
		return cost
	}
	leaf := candidateLeafCost(brs, bi, lc, length)
	if !brs[bi].icase {
		return cAdd(cost, cAdd(length, leaf))
	}
	// With ICase, every case variant of each lookahead character is tried, so the recursion has at most (preimages+1)^length leaves, and one inner node per shorter prefix.
	candidates := int64(1)
	inner := int64(0)
	for i := int64(0); i < length; i++ {
		inner = cAdd(inner, candidates)
		candidates = cMul(candidates, lc.preimages+1)
	}
	return cAdd(cost, cAdd(cMul(inner, cAdd(2+lc.preimages, lc.casePreimages)),
		cMul(candidates, leaf)))
}

// bracketAtomCost bounds the work of one live bracket instruction at one boundary: the single-character test
// and the multi-character probes.
func bracketAtomCost(brs []bracketSet, bi int32, lc *lookupCosts) int64 {
	cost := matchesOneCost(brs, bi, lc)
	if brs[bi].multiLens == 0 {
		return cost
	}
	// The length loop in paConsume runs its test at most maxElemAhead times, counting the last one that fails.
	cost = cAdd(cost, maxElemAhead)
	for length := 2; length <= maxElemAhead; length++ {
		if brs[bi].multiLens&(1<<length) != 0 {
			cost = cAdd(cost, probeCost(brs, bi, lc, int64(length)))
		}
	}
	return cost
}

// solverSteps bounds the counted work of the parse search over any span of at most length characters.
// Every node pays for its bestParse misses.
// Concatenations, repetitions, and alternations add their split and branch loops per memo state.
func solverSteps(nodes []node, ni int32, length int64) int64 {
	spans := cMul(cAdd(length, 1), cAdd(length, 2)) / 2
	total := spans
	switch nodes[ni].op {
	case opConcat:
		total = cAdd(total, cMul(int64(len(nodes[ni].ch)-1),
			cMul(spans, cAdd(length, 2))))
	case opAlt:
		total = cAdd(total, cMul(int64(len(nodes[ni].ch)), spans))
	case opRepeat:
		states := int64(nodes[ni].min) + 1
		if nodes[ni].max != infinite {
			states = int64(nodes[ni].max) + 1
		}
		total = cAdd(total, cMul(cMul(2, states),
			cMul(spans, cAdd(length, 2))))
	}
	for i := 0; i < len(nodes[ni].ch); i++ {
		total = cAdd(total, solverSteps(nodes, nodes[ni].ch[i], length))
	}
	return total
}

// repInstances bounds the instance count of one repetition over a span of at most length characters.
// Null instances stop at the minimum, so the count passes the span by at most the minimum plus one.
func repInstances(nodes []node, ni int32, length int64) int64 {
	instances := cAdd(length, int64(nodes[ni].min)+1)
	if nodes[ni].max != infinite {
		instances = min(instances, int64(nodes[ni].max))
	}
	return instances
}

// solverDepth bounds the recursion of the parse search.
// A repetition chains one frame per instance, and a concatenation chains one frame per child.
// Sibling calls unwind before the next one starts, so the bounds add along one root path only.
func solverDepth(nodes []node, ni int32, length int64) int64 {
	switch nodes[ni].op {
	case opGroup, opAlt, opConcat:
		deepest := int64(0)
		for i := 0; i < len(nodes[ni].ch); i++ {
			deepest = max(deepest, solverDepth(nodes, nodes[ni].ch[i], length))
		}
		if nodes[ni].op == opConcat {
			return cAdd(deepest, int64(len(nodes[ni].ch))+1)
		}
		return deepest + 1
	case opRepeat:
		return cAdd(repInstances(nodes, ni, length)+1,
			solverDepth(nodes, nodes[ni].ch[0], length))
	}
	return 1
}

// treeNodes bounds the node count of one parse tree over a span of at most length characters.
// Nested nullable repetitions with a positive minimum multiply.
// The bound then saturates, and the contract reports figures too large to accept.
func treeNodes(nodes []node, ni int32, length int64) int64 {
	switch nodes[ni].op {
	case opGroup, opAlt:
		widest := int64(0)
		for i := 0; i < len(nodes[ni].ch); i++ {
			widest = max(widest, treeNodes(nodes, nodes[ni].ch[i], length))
		}
		return cAdd(widest, 1)
	case opConcat:
		total := int64(1)
		for i := 0; i < len(nodes[ni].ch); i++ {
			total = cAdd(total, treeNodes(nodes, nodes[ni].ch[i], length))
		}
		return total
	case opRepeat:
		return cAdd(1, cMul(repInstances(nodes, ni, length),
			treeNodes(nodes, nodes[ni].ch[0], length)))
	}
	return 1
}

// solverFanout bounds the widest child list one parse record can hold.
func solverFanout(nodes []node, ni int32, length int64) int64 {
	widest := int64(1)
	switch nodes[ni].op {
	case opConcat:
		widest = int64(len(nodes[ni].ch))
	case opRepeat:
		widest = cAdd(repInstances(nodes, ni, length), 1)
	}
	for i := 0; i < len(nodes[ni].ch); i++ {
		widest = max(widest, solverFanout(nodes, nodes[ni].ch[i], length))
	}
	return widest
}
