package revera

// This file holds the one-pass capture path.
// Compile-time analysis can prove that every subject span has at most one parse of the pattern.
// The selection order then has nothing to choose.
// Phase B can therefore read the group spans from one deterministic walk, instead of running the memoized best-parse search.
// This meets the POSIX proof obligation for one-pass execution.
// Parse uniqueness leaves no two derivations whose ordering or captures could differ.
//
// The walk checks every step it takes.
// On any inconsistency it reports failure, and the caller returns ErrESpace.
// This keeps the compile-time backend choice and its resource contract intact.

// onePassAnalyze reports whether every span has at most one parse of node ni.
// It also reports whether one deterministic walk can find that parse.
// It stores the branch first sets on alternation nodes that need lookahead.
func onePassAnalyze(nodes []node, brs []bracketSet, ni int32) bool {
	switch nodes[ni].op {
	case opChar, opAny, opBOL, opEOL:
		return true
	case opBracket:
		// A multi-character element makes the consumed length ambiguous.
		return !bracketHasMultiMembers(brs, nodes[ni].br)
	case opGroup:
		return onePassAnalyze(nodes, brs, nodes[ni].ch[0])
	case opConcat:
		variable := 0
		for i := 0; i < len(nodes[ni].ch); i++ {
			child := nodes[ni].ch[i]
			if !onePassAnalyze(nodes, brs, child) {
				return false
			}
			if !fixedLength(nodes, child) {
				variable++
			}
		}
		// With at most one variable-length child, arithmetic on the span length gives every split point.
		return variable <= 1
	case opRepeat:
		if nodes[ni].max == 0 {
			return true
		}
		// A fixed nonempty instance length forces the instance count.
		// It also rules out null occurrences.
		child := nodes[ni].ch[0]
		return fixedLength(nodes, child) && nodes[child].minL > 0 &&
			onePassAnalyze(nodes, brs, child)
	case opAlt:
		for i := 0; i < len(nodes[ni].ch); i++ {
			if !onePassAnalyze(nodes, brs, nodes[ni].ch[i]) {
				return false
			}
		}
		if disjointLengths(nodes, ni) {
			return true
		}
		return disjointFirsts(nodes, ni)
	}
	return false
}

// fixedLength reports whether every match of the node has the same length.
// Two saturated bounds compare equal without being exact, so they never count as fixed.
func fixedLength(nodes []node, ni int32) bool {
	return nodes[ni].minL == nodes[ni].maxL && nodes[ni].maxL < lenInf
}

// disjointLengths reports whether the branch length ranges of an alternation never overlap.
// The span length alone then selects the branch.
func disjointLengths(nodes []node, ni int32) bool {
	count := len(nodes[ni].ch)
	for i := 0; i < count; i++ {
		a := nodes[ni].ch[i]
		for k := i + 1; k < count; k++ {
			b := nodes[ni].ch[k]
			if nodes[a].minL <= nodes[b].maxL &&
				nodes[b].minL <= nodes[a].maxL {
				return false
			}
		}
	}
	return true
}

// firstSet returns the exact set of characters that can begin a nonempty match of the node.
// The flag is false when the set is not enumerable, as for dot and bracket expressions.
// The result is a fresh buffer.
func firstSet(nodes []node, ni int32) ([]int32, bool) {
	switch nodes[ni].op {
	case opChar:
		out := make([]int32, 0, len(nodes[ni].fold)+1)
		if len(nodes[ni].fold) > 0 {
			out = append(out, nodes[ni].fold...)
			return out, true
		}
		out = append(out, nodes[ni].r)
		return out, true
	case opBOL, opEOL:
		return nil, true
	case opGroup:
		return firstSet(nodes, nodes[ni].ch[0])
	case opRepeat:
		if nodes[ni].max == 0 {
			return nil, true
		}
		return firstSet(nodes, nodes[ni].ch[0])
	case opAlt:
		var out []int32
		for i := 0; i < len(nodes[ni].ch); i++ {
			sub, ok := firstSet(nodes, nodes[ni].ch[i])
			if !ok {
				return nil, false
			}
			for k := 0; k < len(sub); k++ {
				out = appendUnique(out, sub[k])
			}
		}
		return out, true
	case opConcat:
		var out []int32
		for i := 0; i < len(nodes[ni].ch); i++ {
			child := nodes[ni].ch[i]
			sub, ok := firstSet(nodes, child)
			if !ok {
				return nil, false
			}
			for k := 0; k < len(sub); k++ {
				out = appendUnique(out, sub[k])
			}
			if nodes[child].minL > 0 {
				break
			}
		}
		return out, true
	}
	return nil, false
}

// disjointFirsts checks that one lookahead character selects the branch.
// Every branch needs an exact first set, and the sets must never overlap.
// At most one branch may have a null match.
// On success it stores the sets for the walk.
func disjointFirsts(nodes []node, ni int32) bool {
	count := len(nodes[ni].ch)
	firsts := make([][]int32, count)
	nullable := 0
	for i := 0; i < count; i++ {
		branch := nodes[ni].ch[i]
		set, ok := firstSet(nodes, branch)
		if !ok {
			return false
		}
		if nodes[branch].minL == 0 {
			nullable++
		}
		firsts[i] = set
	}
	if nullable > 1 {
		return false
	}
	for i := 0; i < count; i++ {
		for k := i + 1; k < count; k++ {
			for m := 0; m < len(firsts[i]); m++ {
				if runesContain(firsts[k], firsts[i][m]) {
					return false
				}
			}
		}
	}
	nodes[ni].firsts = firsts
	return true
}

// onePassCaps fills the group spans from the unique parse of node ni over [i, j).
// It returns false when the walk hits an inconsistency.
func onePassCaps(re *Regexp, d *decoded, ni int32, i int, j int, eflags uint32, caps []Match) bool {
	// A saturated maxL means unbounded, never an actual limit.
	span := j - i
	if span < re.nodes[ni].minL ||
		(re.nodes[ni].maxL < lenInf && span > re.nodes[ni].maxL) {
		return false
	}
	switch re.nodes[ni].op {
	case opChar:
		return charMatches(re, ni, d.runes[i])
	case opAny:
		return anyMatches(re, d.runes[i])
	case opBracket:
		return bracketMatchesOne(re.brackets, re.nodes[ni].br, &re.loc,
			d.runes[i])
	case opBOL:
		return atBOL(re, d, i, eflags)
	case opEOL:
		return atEOL(re, d, i, eflags)
	case opGroup:
		// Entry into a group clears every group nested inside it.
		// This is the same section 12.7 rule that assignCaps applies.
		gi := re.nodes[ni].index
		for k := 0; k < len(re.nested[gi]); k++ {
			setMatch(caps, int(re.nested[gi][k]), -1, -1)
		}
		setMatch(caps, gi, i, j)
		return onePassCaps(re, d, re.nodes[ni].ch[0], i, j, eflags, caps)
	case opConcat:
		rest := span
		for k := 0; k < len(re.nodes[ni].ch); k++ {
			rest -= re.nodes[re.nodes[ni].ch[k]].minL
		}
		at := i
		for k := 0; k < len(re.nodes[ni].ch); k++ {
			child := re.nodes[ni].ch[k]
			length := re.nodes[child].minL
			if !fixedLength(re.nodes, child) {
				// The single variable child takes the remainder.
				length += rest
			}
			if length < 0 ||
				!onePassCaps(re, d, child, at, at+length, eflags, caps) {
				return false
			}
			at += length
		}
		return at == j
	case opRepeat:
		if span == 0 {
			return true
		}
		child := re.nodes[ni].ch[0]
		size := re.nodes[child].minL
		count := span / size
		if span%size != 0 || count < re.nodes[ni].min ||
			(re.nodes[ni].max != infinite && count > re.nodes[ni].max) {
			return false
		}
		at := i
		for k := 0; k < count; k++ {
			if !onePassCaps(re, d, child, at, at+size, eflags, caps) {
				return false
			}
			at += size
		}
		return true
	case opAlt:
		chosen := -1
		for idx := 0; idx < len(re.nodes[ni].ch); idx++ {
			branch := re.nodes[ni].ch[idx]
			if span < re.nodes[branch].minL ||
				(re.nodes[branch].maxL < lenInf && span > re.nodes[branch].maxL) {
				continue
			}
			if chosen >= 0 {
				chosen = -1
				break
			}
			chosen = idx
		}
		if chosen < 0 && re.nodes[ni].firsts != nil {
			if span == 0 {
				for idx := 0; idx < len(re.nodes[ni].ch); idx++ {
					if re.nodes[re.nodes[ni].ch[idx]].minL == 0 {
						chosen = idx
						break
					}
				}
			} else {
				for idx := 0; idx < len(re.nodes[ni].ch); idx++ {
					if runesContain(re.nodes[ni].firsts[idx], d.runes[i]) {
						chosen = idx
						break
					}
				}
			}
		}
		if chosen < 0 {
			return false
		}
		return onePassCaps(re, d, re.nodes[ni].ch[chosen], i, j, eflags, caps)
	}
	return false
}
