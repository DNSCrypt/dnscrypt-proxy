package revera

// Bracket expressions.
// A compiled bracket lives in the bracket arena of the Regexp, and nodes reference it by index.
// The flags that shape matching are fixed at compile time, so every matcher tests membership in the same context.
// The locale travels alongside as a borrowed parameter.

type runeRange struct {
	lo int32
	hi int32
}

// bracketSet is the compiled form of one bracket expression.
type bracketSet struct {
	negated bool
	icase   bool
	nlMode  bool
	// ranges holds sorted, non-overlapping single-character members.
	ranges []runeRange
	// classMask is the union of standard LC_CTYPE classes.
	classMask uint16
	// elems holds explicit multi-character collating symbols.
	elems [][]int32
	// equivs holds named equivalence-class elements.
	equivs [][]int32
	// multiLens has bit L set when a multi-character match of length L is possible.
	// The executor therefore probes only those lengths.
	multiLens uint16
}

// Bracket item kinds.
const (
	itemChar  uint8 = 0
	itemElem  uint8 = 1
	itemEquiv uint8 = 2
	itemClass uint8 = 3
)

type bracketItem struct {
	kind  uint8
	r     int32
	seq   []int32
	class uint8
}

// parseBracket parses a complete bracket expression that starts at '['.
// It appends the compiled set to the bracket arena and returns the new opBracket node.
func parseBracket(p *parser, loc *Locale) int32 {
	start := p.pos
	p.pos++
	var b bracketSet
	b.icase = p.flags&FlagICase != 0
	b.nlMode = p.flags&FlagNewline != 0
	if peekByte(p) == '^' {
		b.negated = true
		p.pos++
	}
	empty := true
	for {
		if eof(p) {
			return fail(p, ErrEBrack, start)
		}
		if peekByte(p) == ']' && !empty {
			p.pos++
			finalizeBracket(&b, loc)
			p.brackets = append(p.brackets, b)
			n := addNode(p, opBracket)
			p.nodes[n].br = int32(len(p.brackets) - 1)
			return n
		}
		item, ok := parseBracketItem(p, loc, start)
		if !ok {
			return -1
		}
		empty = false
		if item.kind == itemChar && peekByte(p) == '-' &&
			peekByteAt(p, 1) != ']' && p.pos+1 < len(p.src) {
			rangeStart := p.pos
			p.pos++
			end, ok2 := parseBracketItem(p, loc, start)
			if !ok2 {
				return -1
			}
			if end.kind != itemChar {
				return fail(p, ErrERange, rangeStart)
			}
			if !localeSupportsRanges(loc) {
				// Ranges in a non-POSIX locale use the permitted reject policy.
				return fail(p, ErrERange, rangeStart)
			}
			if item.r > end.r {
				// An empty range set uses the permitted invalid outcome.
				return fail(p, ErrERange, rangeStart)
			}
			var rr runeRange
			rr.lo = item.r
			rr.hi = end.r
			b.ranges = append(b.ranges, rr)
			if peekByte(p) == '-' && peekByteAt(p, 1) != ']' {
				// A shared range endpoint, as in [a-m-o], is undefined.
				return fail(p, ErrERange, p.pos)
			}
			continue
		}
		if item.kind != itemChar && peekByte(p) == '-' &&
			peekByteAt(p, 1) != ']' && p.pos+1 < len(p.src) {
			// A class or equivalence class cannot start a range.
			return fail(p, ErrERange, p.pos)
		}
		switch item.kind {
		case itemChar:
			var rr runeRange
			rr.lo = item.r
			rr.hi = item.r
			b.ranges = append(b.ranges, rr)
		case itemElem:
			b.elems = append(b.elems, item.seq)
		case itemEquiv:
			b.equivs = append(b.equivs, item.seq)
		case itemClass:
			b.classMask |= 1 << item.class
		}
	}
}

// parseBracketItem parses one list member.
// A member is an ordinary character, a literal leading ']', a collating symbol, an equivalence class, or a character class.
// A single-character collating symbol becomes an ordinary character item, so it stays usable as a range endpoint.
func parseBracketItem(p *parser, loc *Locale, bracketStart int) (bracketItem, bool) {
	var item bracketItem
	c := peekByte(p)
	if c == '[' {
		inner := peekByteAt(p, 1)
		if inner == '.' {
			seq, ok := scanInner(p, ".]", ErrECollate)
			if !ok {
				return item, false
			}
			if !localeIsCollatingElement(loc, seq) {
				// This case is invalid, not undefined.
				// The RE must fail when the element does not exist.
				fail(p, ErrECollate, bracketStart)
				return item, false
			}
			if len(seq) == 1 {
				item.kind = itemChar
				item.r = seq[0]
				return item, true
			}
			item.kind = itemElem
			item.seq = seq
			return item, true
		}
		if inner == '=' {
			seq, ok := scanInner(p, "=]", ErrECollate)
			if !ok {
				return item, false
			}
			if !localeIsCollatingElement(loc, seq) {
				fail(p, ErrECollate, bracketStart)
				return item, false
			}
			item.kind = itemEquiv
			item.seq = seq
			return item, true
		}
		if inner == ':' {
			seq, ok := scanInner(p, ":]", ErrECType)
			if !ok {
				return item, false
			}
			class, ok2 := classByName(runesToString(seq))
			if !ok2 {
				fail(p, ErrECType, bracketStart)
				return item, false
			}
			item.kind = itemClass
			item.class = class
			return item, true
		}
	}
	r := nextRune(p)
	if r < 0 {
		return item, false
	}
	item.kind = itemChar
	item.r = r
	return item, true
}

// runesToString encodes a scalar sequence back to UTF-8 text.
// Class names are ASCII, so the simple path is enough.
// Non-ASCII input still makes the round trip correctly.
func runesToString(seq []int32) string {
	out := make([]uint8, 0, len(seq))
	for i := 0; i < len(seq); i++ {
		r := seq[i]
		if r < 0x80 {
			out = append(out, uint8(r))
		} else if r < 0x800 {
			out = append(out, uint8(0xc0|r>>6), uint8(0x80|r&0x3f))
		} else if r < 0x10000 {
			out = append(out, uint8(0xe0|r>>12), uint8(0x80|r>>6&0x3f),
				uint8(0x80|r&0x3f))
		} else {
			out = append(out, uint8(0xf0|r>>18), uint8(0x80|r>>12&0x3f),
				uint8(0x80|r>>6&0x3f), uint8(0x80|r&0x3f))
		}
	}
	return string(out)
}

// scanInner consumes "[X content X]", where X is '.', '=', or ':', and returns the content characters.
// emptyCode reports empty content.
func scanInner(p *parser, closer string, emptyCode int32) ([]int32, bool) {
	start := p.pos
	p.pos += 2
	end := -1
	for i := p.pos; i+1 < len(p.src); i++ {
		if p.src[i] == closer[0] && p.src[i+1] == closer[1] {
			end = i
			break
		}
	}
	if end < 0 {
		fail(p, ErrEBrack, start)
		return nil, false
	}
	if end == p.pos {
		fail(p, emptyCode, start)
		return nil, false
	}
	content := make([]int32, 0, end-p.pos)
	at := p.pos
	for at < end {
		r, size := decodeRuneAt(p.src, at)
		if r < 0 {
			fail(p, ErrBadPat, start)
			return nil, false
		}
		content = append(content, r)
		at += size
	}
	p.pos = end + 2
	return content, true
}

// sortRanges orders ranges by (lo, hi) with a bottom-up merge sort.
// A large bracket therefore still compiles in n log n.
func sortRanges(rr []runeRange) {
	n := len(rr)
	if n < 2 {
		return
	}
	tmp := make([]runeRange, n)
	for width := 1; width < n; width *= 2 {
		for lo := 0; lo < n; lo += 2 * width {
			mid := min(lo+width, n)
			hi := min(lo+2*width, n)
			i := lo
			j := mid
			w := lo
			for i < mid && j < hi {
				less := rr[i].lo < rr[j].lo ||
					(rr[i].lo == rr[j].lo && rr[i].hi <= rr[j].hi)
				if less {
					tmp[w] = rr[i]
					i++
				} else {
					tmp[w] = rr[j]
					j++
				}
				w++
			}
			for i < mid {
				tmp[w] = rr[i]
				i++
				w++
			}
			for j < hi {
				tmp[w] = rr[j]
				j++
				w++
			}
		}
		copy(rr, tmp)
	}
}

// finalizeBracket sorts and merges the single-character ranges.
// It also records the lengths a multi-character match can take.
func finalizeBracket(b *bracketSet, loc *Locale) {
	if !b.negated && (len(b.elems) > 0 || len(b.equivs) > 0) {
		for i := 0; i < len(b.elems); i++ {
			b.multiLens |= 1 << len(b.elems[i])
		}
		if len(b.equivs) > 0 {
			// An equivalence class can match any collating element with an equal primary weight, whatever its length.
			for length := 2; length <= localeMaxElementLength(loc); length++ {
				b.multiLens |= 1 << length
			}
		}
	}
	if len(b.ranges) < 2 {
		return
	}
	sortRanges(b.ranges)
	w := 0
	for i := 1; i < len(b.ranges); i++ {
		if b.ranges[i].lo <= b.ranges[w].hi+1 {
			if b.ranges[i].hi > b.ranges[w].hi {
				b.ranges[w].hi = b.ranges[i].hi
			}
		} else {
			w++
			b.ranges[w] = b.ranges[i]
		}
	}
	b.ranges = b.ranges[:w+1]
}

func bracketInRanges(brs []bracketSet, bi int32, c int32) bool {
	low := 0
	high := len(brs[bi].ranges)
	for low < high {
		middle := low + (high-low)/2
		if brs[bi].ranges[middle].hi < c {
			low = middle + 1
		} else if brs[bi].ranges[middle].lo > c {
			high = middle
		} else {
			return true
		}
	}
	return false
}

// bracketPositiveSingle tests case-sensitive membership of one character in the positive list.
// It ignores multi-character elements.
func bracketPositiveSingle(brs []bracketSet, bi int32, loc *Locale, c int32) bool {
	if bracketInRanges(brs, bi, c) {
		return true
	}
	if brs[bi].classMask != 0 && localeClassMask(loc, c)&brs[bi].classMask != 0 {
		return true
	}
	var single [1]int32
	single[0] = c
	for i := 0; i < len(brs[bi].equivs); i++ {
		if localePrimaryEqual(loc, single[:], brs[bi].equivs[i]) {
			return true
		}
	}
	return false
}

// bracketMatchesOne tests whether the bracket accepts the single character c.
// Under ICase, the closure applies after inversion for a negated list, exactly as section 10.2 requires.
// The character matches when some case variant of it lands on the accepted side of the positive list.
func bracketMatchesOne(brs []bracketSet, bi int32, loc *Locale, c int32) bool {
	if c < 0 {
		// The invalid-byte sentinel matches nothing, not even a negated list.
		return false
	}
	if brs[bi].negated && brs[bi].nlMode && c == '\n' {
		return false
	}
	want := !brs[bi].negated
	if bracketPositiveSingle(brs, bi, loc, c) == want {
		return true
	}
	if !brs[bi].icase {
		return false
	}
	var buf preimageBuf
	localeCasePreimages(loc, &buf, c)
	for i := 0; i < buf.n; i++ {
		if bracketPositiveSingle(brs, bi, loc, buf.r[i]) == want {
			return true
		}
	}
	return false
}

// counterpartMatch tests one subject character against one element character, under the ICase replacement rule.
func counterpartMatch(brs []bracketSet, bi int32, loc *Locale, t int32, e int32) bool {
	if t == e {
		return true
	}
	if !brs[bi].icase {
		return false
	}
	return t == localeToUpper(loc, e) || t == localeToLower(loc, e)
}

// bracketHasMultiMembers reports whether the bracket can consume more than one character.
// Only a positive list with explicit collating symbols or equivalence classes can do that.
func bracketHasMultiMembers(brs []bracketSet, bi int32) bool {
	return !brs[bi].negated &&
		(len(brs[bi].elems) > 0 || len(brs[bi].equivs) > 0)
}

// elemBuf holds one candidate collating element while the equivalence search enumerates case preimages.
type elemBuf struct {
	r [maxElemAhead]int32
}

// bracketMatchesMulti tests a multi-character candidate against the explicit elements and equivalence classes of a positive list.
func bracketMatchesMulti(brs []bracketSet, bi int32, loc *Locale, t []int32) bool {
	if len(t) > localeMaxElementLength(loc) {
		// No collating element is longer than the data's limit.
		return false
	}
	for i := 0; i < len(brs[bi].elems); i++ {
		if len(brs[bi].elems[i]) != len(t) {
			continue
		}
		all := true
		for k := 0; k < len(t); k++ {
			if !counterpartMatch(brs, bi, loc, t[k], brs[bi].elems[i][k]) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	if len(brs[bi].equivs) == 0 {
		return false
	}
	var candidate elemBuf
	return equivCandidate(brs, bi, loc, t, &candidate, 0)
}

// equivCandidate enumerates the case preimages of each position.
// It tests every candidate sequence for membership in some equivalence class.
// Without ICase, the only candidate is the subject sequence itself.
func equivCandidate(brs []bracketSet, bi int32, loc *Locale, t []int32, candidate *elemBuf, at int) bool {
	if at == len(t) {
		if !localeIsCollatingElement(loc, candidate.r[:len(t)]) {
			return false
		}
		for i := 0; i < len(brs[bi].equivs); i++ {
			if localePrimaryEqual(loc, candidate.r[:len(t)], brs[bi].equivs[i]) {
				return true
			}
		}
		return false
	}
	candidate.r[at] = t[at]
	if equivCandidate(brs, bi, loc, t, candidate, at+1) {
		return true
	}
	if !brs[bi].icase {
		return false
	}
	var buf preimageBuf
	localeCasePreimages(loc, &buf, t[at])
	for i := 0; i < buf.n; i++ {
		candidate.r[at] = buf.r[i]
		if equivCandidate(brs, bi, loc, t, candidate, at+1) {
			return true
		}
	}
	return false
}

// bracketMatchesSpan tests whether the bracket accepts exactly the character span [i, j).
// The capture solver uses it.
func bracketMatchesSpan(brs []bracketSet, bi int32, loc *Locale, runes []int32, i int, j int) bool {
	k := j - i
	if k < 1 {
		return false
	}
	if k == 1 {
		return bracketMatchesOne(brs, bi, loc, runes[i])
	}
	if !bracketHasMultiMembers(brs, bi) {
		return false
	}
	return bracketMatchesMulti(brs, bi, loc, runes[i:j])
}

// bracketMinChars returns the smallest character count one bracket match can consume.
// Only a positive list of nothing but multi-character collating symbols and equivalence classes can need more than one character.
// An equivalence class contributes the length of the shortest element in its class.
// ICase never changes match lengths.
func bracketMinChars(brs []bracketSet, bi int32, loc *Locale) int {
	if brs[bi].negated || len(brs[bi].ranges) > 0 ||
		brs[bi].classMask != 0 ||
		(len(brs[bi].elems) == 0 && len(brs[bi].equivs) == 0) {
		return 1
	}
	best := lenInf
	for i := 0; i < len(brs[bi].elems); i++ {
		best = min(best, len(brs[bi].elems[i]))
	}
	for i := 0; i < len(brs[bi].equivs); i++ {
		best = min(best, localeMinEquivLength(loc, brs[bi].equivs[i]))
	}
	return best
}
