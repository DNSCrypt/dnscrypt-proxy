package revera

// This package is the Vego rewrite of the reference engine in dev/internal/reference.
// It is a cleanroom implementation of the POSIX.1-2024 Issue 8 Extended Regular Expression language.
// docs/POSIX-1-2024-ERE-SPECIFICATION.md in this repository is the contract it follows.
//
// The API mirrors the regcomp() family.
// Patterns and subjects are UTF-8, length-delimited strings.
// NUL is an ordinary character.
// That input lies outside the C-representable domain, so it is a permitted extension.
// Dot never matches NUL, and bytes that are not valid UTF-8 match nothing.
//
// The subset has no methods, so every operation is a function that takes the Regexp as its first argument.
// Compile returns the Regexp by value, and nothing may change it afterwards.
// Exec never writes to it, so concurrent calls on one compiled value are safe in the Go instantiation.

// Regexp is a compiled regular expression.
type Regexp struct {
	// nodes is the AST arena, and root indexes it.
	nodes []node
	// brackets is the bracket arena, and opBracket nodes index it.
	brackets []bracketSet
	root     int32
	nsub     int
	flags    uint32
	loc      Locale
	// minSlots counts shortest-preferring repetitions.
	// Each one holds a counter slot, assigned in pattern pre-order.
	minSlots int
	// nested lists, for every group, the groups strictly inside it.
	nested [][]int32
	// multi is true when some bracket can consume several characters.
	multi bool
	prog  program
	// onePass is true when every span has at most one parse.
	// The capture walk in onepass.go then replaces the phase B solver.
	onePass bool
}

// subjectLimit is the largest subject Exec accepts, in bytes.
// Thread payloads store match starts as int32, so a longer subject reports ESpace.
// The resource contract clamps its input bound to this value.
const subjectLimit = 1<<31 - 1

// maxCounterCells limits the phase A counter table, instructions times counter slots, so its indexes fit a 32-bit int.
// A pattern that needs a bigger table fails to compile with ESpace.
const maxCounterCells = 1<<31 - 1

// compileScan walks the pattern in pre-order and fills the tree-derived Regexp fields.
// Those fields are the minimal counter slots and the multi-character flag.
func compileScan(re *Regexp, ni int32) {
	switch re.nodes[ni].op {
	case opRepeat:
		if re.nodes[ni].minimal {
			re.nodes[ni].index = re.minSlots
			re.minSlots++
		}
	case opBracket:
		if bracketHasMultiMembers(re.brackets, re.nodes[ni].br) {
			re.multi = true
		}
	}
	for i := 0; i < len(re.nodes[ni].ch); i++ {
		compileScan(re, re.nodes[ni].ch[i])
	}
}

// groupStack tracks the open groups while collectNested walks the pattern.
type groupStack struct {
	g []int32
}

// collectNested records, for each group, the group numbers inside it.
func collectNested(re *Regexp, ni int32, stack *groupStack) {
	isGroup := re.nodes[ni].op == opGroup
	if isGroup {
		gi := int32(re.nodes[ni].index)
		for k := 0; k < len(stack.g); k++ {
			outer := stack.g[k]
			re.nested[outer] = append(re.nested[outer], gi)
		}
		stack.g = append(stack.g, gi)
	}
	for i := 0; i < len(re.nodes[ni].ch); i++ {
		collectNested(re, re.nodes[ni].ch[i], stack)
	}
	if isGroup {
		stack.g = stack.g[:len(stack.g)-1]
	}
}

// Compile parses and compiles pattern in the given locale.
// LocalePOSIX() gives the POSIX locale.
// A nonzero code in the returned Error means failure, and the Regexp is then meaningless.
func Compile(pattern string, loc Locale, flags uint32) (Regexp, Error) {
	var re Regexp
	if !LocaleValid(&loc) {
		return re, compileError(ErrBadPat, -1)
	}
	var p parser
	root := parse(&p, &loc, pattern, flags)
	if root < 0 {
		return re, p.err
	}
	re.nsub = p.groups
	re.nodes = p.nodes
	re.brackets = p.brackets
	re.root = root
	re.flags = flags
	re.loc = loc
	re.nested = make([][]int32, re.nsub+1)
	compileScan(&re, root)
	var stack groupStack
	collectNested(&re, root, &stack)
	computeLengths(re.nodes, &re.loc, re.brackets, root)
	re.onePass = onePassAnalyze(re.nodes, re.brackets, root)
	var b progBuilder
	b.icase = flags&FlagICase != 0
	compileProgram(&b, re.nodes, root, re.multi, flags&FlagNewline != 0)
	if b.errCode != ErrNone {
		return re, compileError(b.errCode, -1)
	}
	if b.tooBig || re.minSlots > 0 && len(b.prog.ins) > maxCounterCells/re.minSlots {
		return re, compileError(ErrESpace, -1)
	}
	re.prog = b.prog
	return re, noError()
}

// NumSub returns the number of parenthesized subexpressions, like re_nsub.
func NumSub(re *Regexp) int {
	return re.nsub
}

// Exec searches subject for the POSIX-selected match.
//
// On success it returns true and fills pmatch like regexec().
// Element 0 is the whole match, element i is capturing subexpression i, and every remaining element becomes -1, -1.
// pmatch stays untouched when the expression was compiled with FlagNoSub, or when pmatch is empty.
// Exec returns false when no match exists, and the Error code is then ErrNone for a plain mismatch.
func Exec(re *Regexp, subject string, pmatch []Match, eflags uint32) (bool, Error) {
	if len(subject) > subjectLimit {
		return false, compileError(ErrESpace, -1)
	}
	result := runPhaseA(re, subject, eflags)
	if !result.matched {
		return false, noError()
	}
	if re.flags&FlagNoSub != 0 || len(pmatch) == 0 {
		return true, noError()
	}
	setMatch(pmatch, 0, result.so, result.eo)
	for idx := 1; idx < len(pmatch); idx++ {
		setMatch(pmatch, idx, -1, -1)
	}
	if len(pmatch) == 1 || re.nsub == 0 {
		return true, noError()
	}

	// Captures need the best parse of the selected span only.
	d := decodeWindow(subject, result.so, result.eo)
	caps := make([]Match, re.nsub+1)
	serr := solveCaptures(re, &d, 0, len(d.runes), eflags, caps)
	if serr.Code != ErrNone {
		return false, serr
	}
	fillMatches(re, &d, caps, pmatch)
	return true, noError()
}
