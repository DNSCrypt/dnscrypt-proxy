package revera

// Shared matching helpers: the decoded subject window, the atom tests, and the pmatch conversion.
// The phase B backends and the engine both use them.

// Match reports one substring as byte offsets, half-open [So, Eo).
// A nonparticipating subexpression has So == -1 and Eo == -1.
type Match struct {
	So int
	Eo int
}

// decoded is a subject window decoded into characters with byte boundaries.
// The edge flags carry the anchor context of the text around the window.
type decoded struct {
	runes []int32
	// byteAt[i] is the absolute byte offset of character boundary i.
	// Its length is len(runes)+1.
	byteAt         []int
	atSubjectStart bool
	atSubjectEnd   bool
	prevIsNewline  bool
	nextIsNewline  bool
}

// decodeWindow decodes s[so:eo].
// Both offsets sit on character boundaries.
// captureHeap in the resource contract counts these allocations.
func decodeWindow(s string, so int, eo int) decoded {
	var d decoded
	d.runes = make([]int32, 0, eo-so)
	d.byteAt = make([]int, 0, eo-so+1)
	d.atSubjectStart = so == 0
	d.atSubjectEnd = eo == len(s)
	d.prevIsNewline = so > 0 && s[so-1] == '\n'
	d.nextIsNewline = eo < len(s) && s[eo] == '\n'
	i := so
	for i < eo {
		d.byteAt = append(d.byteAt, i)
		r, size := decodeRuneAt(s, i)
		d.runes = append(d.runes, r)
		i += size
	}
	d.byteAt = append(d.byteAt, eo)
	return d
}

// indexOfByte returns the offset of the first c in s, or -1.
func indexOfByte(s string, c uint8) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func runesContain(runes []int32, r int32) bool {
	for i := 0; i < len(runes); i++ {
		if runes[i] == r {
			return true
		}
	}
	return false
}

// charMatches tests one subject character against an opChar node.
func charMatches(re *Regexp, ni int32, c int32) bool {
	if c < 0 {
		return false
	}
	if re.flags&FlagICase != 0 {
		return runesContain(re.nodes[ni].fold, c)
	}
	return c == re.nodes[ni].r
}

// anyMatches tests one subject character against dot.
func anyMatches(re *Regexp, c int32) bool {
	if c <= 0 {
		// Dot never matches NUL, and never an invalid byte.
		return false
	}
	if re.flags&FlagNewline != 0 && c == '\n' {
		return false
	}
	return true
}

// atBOL reports a line beginning at character boundary i of the window.
func atBOL(re *Regexp, d *decoded, i int, eflags uint32) bool {
	if i == 0 {
		if d.atSubjectStart {
			return eflags&ExecNotBOL == 0
		}
		return re.flags&FlagNewline != 0 && d.prevIsNewline
	}
	return re.flags&FlagNewline != 0 && d.runes[i-1] == '\n'
}

// atEOL reports a line end at character boundary i of the window.
func atEOL(re *Regexp, d *decoded, i int, eflags uint32) bool {
	if i == len(d.runes) {
		if d.atSubjectEnd {
			return eflags&ExecNotEOL == 0
		}
		return re.flags&FlagNewline != 0 && d.nextIsNewline
	}
	return re.flags&FlagNewline != 0 && d.runes[i] == '\n'
}

// fillMatches converts character spans to byte offsets, and fills pmatch under section 12.5.
func fillMatches(re *Regexp, d *decoded, caps []Match, pmatch []Match) {
	if re.flags&FlagNoSub != 0 || len(pmatch) == 0 {
		return
	}
	for idx := 0; idx < len(pmatch); idx++ {
		if idx < len(caps) && caps[idx].So >= 0 {
			pmatch[idx].So = d.byteAt[caps[idx].So]
			pmatch[idx].Eo = d.byteAt[caps[idx].Eo]
		} else {
			pmatch[idx].So = -1
			pmatch[idx].Eo = -1
		}
	}
}
