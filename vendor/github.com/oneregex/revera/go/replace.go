package revera

// Global operations.
// The subset has no function values, so the callback API of the reference engine becomes an iterator.
// MatchIterInit and MatchIterNext walk the non-overlapping matches, and ReplaceAll builds on them.
// A host wrapper rebuilds the callback and collection forms over the iterator with a few lines per language.
// ReplaceAllStringFunc is the Go one.

// MatchIter walks every non-overlapping match, left to right.
type MatchIter struct {
	pos     int
	lastEnd int
	limit   int
	done    bool
}

// MatchIterInit starts an iteration that reports at most limit matches.
// A negative limit means no bound, like the preg_replace limit or the n of FindAll.
// An expression compiled with FlagNoSub reports ENoSub, because iteration needs the match offsets.
func MatchIterInit(re *Regexp, limit int) (MatchIter, Error) {
	var it MatchIter
	it.lastEnd = -1
	it.limit = limit
	if re.flags&FlagNoSub != 0 {
		it.done = true
		return it, compileError(ErrENoSub, -1)
	}
	if limit == 0 {
		it.done = true
	}
	return it, noError()
}

// MatchIterNext reports the next match into pmatch, which must hold at least NumSub()+1 elements.
// The offsets are absolute in subject.
// It returns false when the iteration is over.
//
// Selection follows the classic global-substitution rule.
// After a match, the next search starts at its end, and it skips a null match that starts exactly there.
// A null match otherwise counts, and the scan then moves one character forward.
func MatchIterNext(re *Regexp, it *MatchIter, subject string, eflags uint32, pmatch []Match) (bool, Error) {
	if it.done {
		return false, noError()
	}
	if len(pmatch) < re.nsub+1 {
		it.done = true
		return false, compileError(ErrESpace, -1)
	}
	for it.pos <= len(subject) {
		flags := continuationFlags(re, subject, it.pos, eflags)
		matched, err := Exec(re, subject[it.pos:], pmatch, flags)
		if err.Code != ErrNone {
			it.done = true
			return false, err
		}
		if !matched {
			it.done = true
			return false, noError()
		}
		for idx := 0; idx < len(pmatch); idx++ {
			if pmatch[idx].So >= 0 {
				pmatch[idx].So += it.pos
				pmatch[idx].Eo += it.pos
			}
		}
		so := pmatch[0].So
		eo := pmatch[0].Eo
		report := so != eo || so != it.lastEnd
		if eo > so {
			it.pos = eo
		} else if so >= len(subject) {
			it.done = true
			if !report {
				return false, noError()
			}
		} else {
			_, size := decodeRuneAt(subject, so)
			it.pos = so + size
		}
		if report {
			it.lastEnd = eo
			it.limit--
			if it.limit == 0 {
				it.done = true
			}
			return true, noError()
		}
	}
	it.done = true
	return false, noError()
}

// replPart is one piece of a parsed replacement text.
// A part with a nonempty lit is a literal.
// Every other part names a group, where 0 is the whole match.
type replPart struct {
	lit   string
	group int
}

// parseReplacement splits the sed-style replacement text into parts.
// An ampersand inserts the whole match, and a backslash-digit pair inserts one group.
// A backslash escapes the next character.
// A digit above nsub reports ESubReg, and a trailing backslash reports EEscape.
func parseReplacement(replacement string, nsub int) ([]replPart, Error) {
	parts := make([]replPart, 0, 4)
	start := 0
	for idx := 0; idx < len(replacement); idx++ {
		c := replacement[idx]
		if c != '&' && c != '\\' {
			continue
		}
		if start < idx {
			var lit replPart
			lit.lit = replacement[start:idx]
			parts = append(parts, lit)
		}
		if c == '&' {
			var whole replPart
			parts = append(parts, whole)
			start = idx + 1
			continue
		}
		if idx+1 == len(replacement) {
			return nil, compileError(ErrEEscape, idx)
		}
		next := replacement[idx+1]
		if next >= '0' && next <= '9' {
			group := int(next - '0')
			if group == 0 || group > nsub {
				return nil, compileError(ErrESubReg, idx)
			}
			var ref replPart
			ref.group = group
			parts = append(parts, ref)
		} else {
			var esc replPart
			esc.lit = replacement[idx+1 : idx+2]
			parts = append(parts, esc)
		}
		idx++
		start = idx + 1
	}
	if start < len(replacement) {
		var tail replPart
		tail.lit = replacement[start:]
		parts = append(parts, tail)
	}
	return parts, noError()
}

// replaceCapacity is the output buffer reserved for a subject of n bytes.
// It is sized for the common case, where the result stays close to the subject size.
// The min keeps it from overflowing a 32-bit int.
func replaceCapacity(n int) int {
	return n + min(n/8, subjectLimit-n)
}

// ReplaceAll returns subject with every non-overlapping match replaced by replacement, like the sed s///g command.
// In replacement, & stands for the whole match and \1 through \9 for one group.
// A backslash escapes the next character, so \& and \\ are literal.
// A reference to a nonparticipating group inserts nothing, and a reference past NumSub() reports ESubReg.
// Match iteration follows the MatchIterNext rules, and limit bounds the replacement count the same way.
// The rest of the subject stays as it is.
//
// An expression compiled with FlagNoSub reports ENoSub.
func ReplaceAll(re *Regexp, subject string, replacement string, limit int, eflags uint32) (string, Error) {
	if re.flags&FlagNoSub != 0 {
		return "", compileError(ErrENoSub, -1)
	}
	parts, perr := parseReplacement(replacement, re.nsub)
	if perr.Code != ErrNone {
		return "", perr
	}
	it, ierr := MatchIterInit(re, limit)
	if ierr.Code != ErrNone {
		return "", ierr
	}
	pmatch := make([]Match, re.nsub+1)
	var out []uint8
	last := 0
	any := false
	for {
		ok, err := MatchIterNext(re, &it, subject, eflags, pmatch)
		if err.Code != ErrNone {
			return "", err
		}
		if !ok {
			break
		}
		if !any {
			out = make([]uint8, 0, replaceCapacity(len(subject)))
			any = true
		}
		out = append(out, subject[last:pmatch[0].So]...)
		for i := 0; i < len(parts); i++ {
			if len(parts[i].lit) != 0 {
				out = append(out, parts[i].lit...)
				continue
			}
			ref := pmatch[parts[i].group]
			if ref.So >= 0 {
				out = append(out, subject[ref.So:ref.Eo]...)
			}
		}
		last = pmatch[0].Eo
	}
	if !any {
		// A subject without any match comes back unchanged and without a copy.
		return subject, noError()
	}
	out = append(out, subject[last:]...)
	return string(out), noError()
}
