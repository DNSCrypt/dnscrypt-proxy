package revera

// The ERE parser.
// The AST lives in a flat arena.
// Every node is one element of a []node slice, and children are indexes into it.
// A negative index means "no node", and it only appears on the error path.

// Node operators.
const (
	opChar    uint8 = 0
	opAny     uint8 = 1
	opBracket uint8 = 2
	opBOL     uint8 = 3
	opEOL     uint8 = 4
	opConcat  uint8 = 5
	opAlt     uint8 = 6
	opRepeat  uint8 = 7
	opGroup   uint8 = 8
)

// infinite marks an unbounded repetition maximum.
const infinite = -1

// lenInf saturates node length bounds far above any supported span.
const lenInf = 1 << 30

// maxNesting is the deepest parenthesis nesting that compiles.
// The parser and the later passes are recursive, so a deeper pattern fails with ESpace instead of running out of stack.
// A pattern of up to 256 bytes can't nest deeper than that, so the minimum capacity of section 3.4 still holds.
const maxNesting = 256

type node struct {
	op uint8
	ch []int32 // child node indexes, in order
	r  int32   // opChar: the literal character
	// fold holds the accepted closure set of an opChar under ICase.
	fold []int32
	// br indexes the bracket arena for opBracket.
	br      int32
	min     int  // opRepeat
	max     int  // opRepeat, where infinite means no bound
	minimal bool // opRepeat: shortest-preferring
	index   int  // opGroup capture number, or opRepeat counter slot

	// minL and maxL bound the character count one match of this node can consume.
	// maxL saturates at lenInf.
	// The capture solver uses both to clamp its split ranges.
	minL int
	maxL int
	// sufMin and sufMax bound the children from index k onward, for opConcat only.
	sufMin []int
	sufMax []int
	// firsts holds the branch first sets of a one-pass alternation that needs lookahead to select its branch.
	firsts [][]int32
}

type parser struct {
	src   string
	pos   int
	flags uint32
	// groups counts opening parentheses in pattern order.
	groups int
	// depth counts the groups open at the current position.
	depth    int
	nodes    []node
	brackets []bracketSet
	// err keeps the first failure.
	// A zero code means that nothing failed yet.
	err Error
}

// fail records the first error and returns the failure index.
func fail(p *parser, code int32, pos int) int32 {
	if p.err.Code == ErrNone {
		p.err = compileError(code, pos)
	}
	return -1
}

// addNode appends a fresh node and returns its index.
func addNode(p *parser, op uint8) int32 {
	var n node
	n.op = op
	p.nodes = append(p.nodes, n)
	return int32(len(p.nodes) - 1)
}

func eof(p *parser) bool {
	return p.pos >= len(p.src)
}

// peekByte returns the next byte without consuming it, or 0 at the end.
func peekByte(p *parser) uint8 {
	if eof(p) {
		return 0
	}
	return p.src[p.pos]
}

func peekByteAt(p *parser, ahead int) uint8 {
	if p.pos+ahead >= len(p.src) {
		return 0
	}
	return p.src[p.pos+ahead]
}

// nextRune consumes and returns one character.
// Invalid UTF-8 gives invalidRune, and it also records an error.
func nextRune(p *parser) int32 {
	r, size := decodeRuneAt(p.src, p.pos)
	if r < 0 {
		fail(p, ErrBadPat, p.pos)
		return invalidRune
	}
	p.pos += size
	return r
}

// parse builds the AST for pattern.
// On success, the parser holds the arena and the root index.
// On failure, p.err holds the first error.
func parse(p *parser, loc *Locale, pattern string, flags uint32) int32 {
	p.src = pattern
	p.flags = flags
	root := parseAlt(p, loc, false)
	if root < 0 {
		return -1
	}
	if !eof(p) {
		// Only an unmatched ')' inside parseAlt(false) can stop early.
		// parseBranch treats that character as ordinary, so this case cannot happen.
		return fail(p, ErrBadPat, p.pos)
	}
	return root
}

// parseAlt parses branch { "|" branch }.
func parseAlt(p *parser, loc *Locale, inGroup bool) int32 {
	first := parseBranch(p, loc, inGroup)
	if first < 0 {
		return -1
	}
	if peekByte(p) != '|' {
		return first
	}
	alt := addNode(p, opAlt)
	p.nodes[alt].ch = append(p.nodes[alt].ch, first)
	for peekByte(p) == '|' {
		p.pos++
		branch := parseBranch(p, loc, inGroup)
		if branch < 0 {
			return -1
		}
		p.nodes[alt].ch = append(p.nodes[alt].ch, branch)
	}
	return alt
}

// parseBranch parses a nonempty concatenation of expressions.
func parseBranch(p *parser, loc *Locale, inGroup bool) int32 {
	exprs := make([]int32, 0, 4)
	for {
		if eof(p) {
			break
		}
		c := peekByte(p)
		if c == '|' {
			break
		}
		if c == ')' && inGroup {
			break
		}
		expr := parseExpr(p, loc)
		if expr < 0 {
			return -1
		}
		exprs = append(exprs, expr)
	}
	if len(exprs) == 0 {
		// An empty pattern, group, or branch is outside the grammar.
		return fail(p, ErrBadPat, p.pos)
	}
	if len(exprs) == 1 {
		return exprs[0]
	}
	cat := addNode(p, opConcat)
	p.nodes[cat].ch = exprs
	return cat
}

func isDupByte(c uint8) bool {
	return c == '*' || c == '+' || c == '?' || c == '{'
}

// parseExpr parses one anchor, or one primary with an optional duplication.
func parseExpr(p *parser, loc *Locale) int32 {
	start := p.pos
	c := peekByte(p)
	if c == '^' || c == '$' {
		p.pos++
		if isDupByte(peekByte(p)) {
			// A duplication cannot follow an anchor.
			return fail(p, ErrBadRpt, p.pos)
		}
		if c == '^' {
			return addNode(p, opBOL)
		}
		return addNode(p, opEOL)
	}
	if isDupByte(c) {
		// The postfix operator lacks a permitted operand.
		return fail(p, ErrBadRpt, start)
	}

	var primary int32
	switch c {
	case '(':
		if p.depth == maxNesting {
			return fail(p, ErrESpace, start)
		}
		p.pos++
		p.groups++
		index := p.groups
		p.depth++
		sub := parseAlt(p, loc, true)
		p.depth--
		if sub < 0 {
			return -1
		}
		if peekByte(p) != ')' {
			return fail(p, ErrEParen, start)
		}
		p.pos++
		primary = addNode(p, opGroup)
		p.nodes[primary].ch = append(p.nodes[primary].ch, sub)
		p.nodes[primary].index = index
	case '[':
		primary = parseBracket(p, loc)
		if primary < 0 {
			return -1
		}
	case '\\':
		p.pos++
		if eof(p) {
			return fail(p, ErrEEscape, start)
		}
		r := nextRune(p)
		if r < 0 {
			return -1
		}
		if r == '^' || r == '.' || r == '[' || r == ']' || r == '$' ||
			r == '(' || r == ')' || r == '|' || r == '*' || r == '+' ||
			r == '?' || r == '{' || r == '}' || r == '\\' {
			primary = charNode(p, loc, r)
		} else {
			// A backslash before an ordinary character is undefined.
			return fail(p, ErrBadPat, start)
		}
	case '.':
		p.pos++
		primary = addNode(p, opAny)
	default:
		// ')' arrives here only at depth zero, where it is ordinary.
		r := nextRune(p)
		if r < 0 {
			return -1
		}
		primary = charNode(p, loc, r)
	}
	return parseDup(p, primary)
}

// charNode builds a literal atom and its ICase closure set.
func charNode(p *parser, loc *Locale, r int32) int32 {
	n := addNode(p, opChar)
	p.nodes[n].r = r
	if p.flags&FlagICase != 0 {
		fold := make([]int32, 0, 3)
		fold = appendUnique(fold, r)
		fold = appendUnique(fold, localeToUpper(loc, r))
		fold = appendUnique(fold, localeToLower(loc, r))
		p.nodes[n].fold = fold
	}
	return n
}

func appendUnique(runes []int32, r int32) []int32 {
	for i := 0; i < len(runes); i++ {
		if runes[i] == r {
			return runes
		}
	}
	return append(runes, r)
}

// parseDup parses an optional duplication and its repetition modifier.
func parseDup(p *parser, operand int32) int32 {
	c := peekByte(p)
	var lo int
	var hi int
	switch c {
	case '*':
		p.pos++
		lo = 0
		hi = infinite
	case '+':
		p.pos++
		lo = 1
		hi = infinite
	case '?':
		p.pos++
		lo = 0
		hi = 1
	case '{':
		iv, ok := parseInterval(p)
		if !ok {
			return -1
		}
		lo = iv.lo
		hi = iv.hi
	default:
		return operand
	}
	minimal := p.flags&FlagMinimal != 0
	if peekByte(p) == '?' {
		p.pos++
		minimal = !minimal
	}
	if isDupByte(peekByte(p)) {
		// Adjacent duplication symbols past one modifier are undefined.
		return fail(p, ErrBadRpt, p.pos)
	}
	rep := addNode(p, opRepeat)
	p.nodes[rep].ch = append(p.nodes[rep].ch, operand)
	p.nodes[rep].min = lo
	p.nodes[rep].max = hi
	p.nodes[rep].minimal = minimal
	return rep
}

// interval is one parsed "{m,n}" bound pair.
type interval struct {
	lo int
	hi int
}

// parseInterval parses "{m}", "{m,}", or "{m,n}" starting at '{'.
func parseInterval(p *parser) (interval, bool) {
	var iv interval
	start := p.pos
	p.pos++
	lo, ok := parseCount(p)
	if !ok {
		intervalError(p, start)
		return iv, false
	}
	c := peekByte(p)
	if c == '}' {
		p.pos++
		iv.lo = lo
		iv.hi = lo
		return iv, true
	}
	if c != ',' {
		intervalError(p, start)
		return iv, false
	}
	p.pos++
	if peekByte(p) == '}' {
		p.pos++
		iv.lo = lo
		iv.hi = infinite
		return iv, true
	}
	hi, ok2 := parseCount(p)
	if !ok2 || peekByte(p) != '}' {
		intervalError(p, start)
		return iv, false
	}
	p.pos++
	if hi < lo {
		fail(p, ErrBadBR, start)
		return iv, false
	}
	iv.lo = lo
	iv.hi = hi
	return iv, true
}

// intervalError picks EBrace when the brace never closes, else BadBR.
func intervalError(p *parser, start int) {
	if indexOfByte(p.src[p.pos:], '}') >= 0 {
		fail(p, ErrBadBR, start)
		return
	}
	fail(p, ErrEBrace, start)
}

// parseCount parses a decimal count from zero through dupMax.
func parseCount(p *parser) (int, bool) {
	if eof(p) || p.src[p.pos] < '0' || p.src[p.pos] > '9' {
		return 0, false
	}
	value := 0
	for !eof(p) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
		value = value*10 + int(p.src[p.pos]-'0')
		if value > dupMax {
			return 0, false
		}
		p.pos++
	}
	return value, true
}

// satAdd and satMul clamp their result to lenInf, for operands in [0, lenInf].
// They check before computing, so the raw result never overflows a 32-bit int.
func satAdd(a int, b int) int {
	if a > lenInf-b {
		return lenInf
	}
	return a + b
}

func satMul(a int, b int) int {
	if a != 0 && b > lenInf/a {
		return lenInf
	}
	return a * b
}

// computeLengths fills minL, maxL, and the concatenation suffix bounds, from the bottom up.
func computeLengths(nodes []node, loc *Locale, brackets []bracketSet, ni int32) {
	for i := 0; i < len(nodes[ni].ch); i++ {
		computeLengths(nodes, loc, brackets, nodes[ni].ch[i])
	}
	switch nodes[ni].op {
	case opChar, opAny:
		nodes[ni].minL = 1
		nodes[ni].maxL = 1
	case opBracket:
		nodes[ni].minL = int(bracketMinChars(brackets, nodes[ni].br, loc))
		nodes[ni].maxL = 1
		if bracketHasMultiMembers(brackets, nodes[ni].br) {
			nodes[ni].maxL = localeMaxElementLength(loc)
		}
	case opBOL, opEOL:
		nodes[ni].minL = 0
		nodes[ni].maxL = 0
	case opGroup:
		child := nodes[ni].ch[0]
		nodes[ni].minL = nodes[child].minL
		nodes[ni].maxL = nodes[child].maxL
	case opConcat:
		count := len(nodes[ni].ch)
		nodes[ni].sufMin = make([]int, count+1)
		nodes[ni].sufMax = make([]int, count+1)
		for k := count - 1; k >= 0; k-- {
			child := nodes[ni].ch[k]
			nodes[ni].sufMin[k] = satAdd(nodes[ni].sufMin[k+1], nodes[child].minL)
			nodes[ni].sufMax[k] = satAdd(nodes[ni].sufMax[k+1], nodes[child].maxL)
		}
		nodes[ni].minL = nodes[ni].sufMin[0]
		nodes[ni].maxL = nodes[ni].sufMax[0]
	case opAlt:
		nodes[ni].minL = lenInf
		nodes[ni].maxL = 0
		for i := 0; i < len(nodes[ni].ch); i++ {
			child := nodes[ni].ch[i]
			nodes[ni].minL = min(nodes[ni].minL, nodes[child].minL)
			nodes[ni].maxL = max(nodes[ni].maxL, nodes[child].maxL)
		}
	case opRepeat:
		child := nodes[ni].ch[0]
		nodes[ni].minL = satMul(nodes[ni].min, nodes[child].minL)
		if nodes[ni].max == 0 || nodes[child].maxL == 0 {
			nodes[ni].maxL = 0
		} else if nodes[ni].max == infinite {
			nodes[ni].maxL = lenInf
		} else {
			nodes[ni].maxL = satMul(nodes[ni].max, nodes[child].maxL)
		}
	}
}
