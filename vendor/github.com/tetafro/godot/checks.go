package godot

import (
	"go/token"
	"regexp"
	"strings"
	"unicode"
)

// Error messages.
const (
	noPeriodMessage  = "Comment should end in a period"
	noCapitalMessage = "Sentence should start with a capital letter"
)

var (
	// List of valid sentence ending.
	// A sentence can be inside parenthesis, and therefore ends with parenthesis.
	lastChars = []string{".", "?", "!", ".)", "?)", "!)", specialReplacer}

	// Special tags in comments like "// nolint:", or "// +k8s:".
	tags = regexp.MustCompile(`^\+?[a-z0-9]+:`)

	// Special hashtags in comments like "// #nosec".
	hashtags = regexp.MustCompile(`^#[a-z]+($|\s)`)

	// URL at the end of the line.
	endURL = regexp.MustCompile(`[a-z]+://[^\s]+$`)
)

// checkComments checks every comment accordings to the rules from
// `settings` argument.
func checkComments(comments []comment, settings Settings) []Issue {
	var issues []Issue // nolint: prealloc
	for _, c := range comments {
		if settings.Period {
			if iss := checkCommentForPeriod(c); iss != nil {
				issues = append(issues, *iss)
			}
		}
		if settings.Capital {
			if iss := checkCommentForCapital(c); len(iss) > 0 {
				issues = append(issues, iss...)
			}
		}
	}
	return issues
}

// checkCommentForPeriod checks that the last sentense of the comment ends
// in a period.
func checkCommentForPeriod(c comment) *Issue {
	pos, ok := checkPeriod(c.text)
	if ok {
		return nil
	}

	// Shift position by the length of comment's special symbols: /* or //
	isBlock := strings.HasPrefix(c.lines[0], "/*")
	if (isBlock && pos.line == 1) || !isBlock {
		pos.column += 2
	}

	iss := Issue{
		Pos: token.Position{
			Filename: c.start.Filename,
			Offset:   c.start.Offset,
			Line:     pos.line + c.start.Line - 1,
			Column:   pos.column + c.start.Column - 1,
		},
		Message: noPeriodMessage,
	}

	// Make a replacement. Use `pos.line` to get an original line from
	// attached lines. Use `iss.Pos.Column` because it's a position in
	// the original line.
	original := []rune(c.lines[pos.line-1])
	iss.Replacement = string(original[:iss.Pos.Column-1]) + "." +
		string(original[iss.Pos.Column-1:])

	// Save replacement to raw lines to be able to combine it with
	// further replacements
	c.lines[pos.line-1] = iss.Replacement

	return &iss
}

// checkCommentForCapital checks that the each sentense of the comment starts with
// a capital letter.
// nolint: unparam
func checkCommentForCapital(c comment) []Issue {
	pp := checkCapital(c.text, c.decl)
	if len(pp) == 0 {
		return nil
	}

	issues := make([]Issue, len(pp))
	for i, pos := range pp {
		// Shift position by the length of comment's special symbols: /* or //
		isBlock := strings.HasPrefix(c.lines[0], "/*")
		if (isBlock && pos.line == 1) || !isBlock {
			pos.column += 2
		}

		iss := Issue{
			Pos: token.Position{
				Filename: c.start.Filename,
				Offset:   c.start.Offset,
				Line:     pos.line + c.start.Line - 1,
				Column:   pos.column + c.start.Column - 1,
			},
			Message: noCapitalMessage,
		}

		// Make a replacement. Use `pos.line` to get an original line from
		// attached lines. Use `iss.Pos.Column` because it's a position in
		// the original line.
		rep := []rune(c.lines[pos.line-1])
		rep[iss.Pos.Column-1] = unicode.ToTitle(rep[iss.Pos.Column-1])
		iss.Replacement = string(rep)

		// Save replacement to raw lines to be able to combine it with
		// further replacements
		c.lines[pos.line-1] = iss.Replacement

		issues[i] = iss
	}

	return issues
}

// checkPeriod checks that the last sentense of the text ends in a period.
// NOTE: Returned position is a position inside given text, not in the
// original file.
func checkPeriod(comment string) (pos position, ok bool) {
	// Check last non-empty line
	var found bool
	var line string
	lines := strings.Split(comment, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line = strings.TrimRightFunc(lines[i], unicode.IsSpace)
		if line == "" {
			continue
		}
		found = true
		pos.line = i + 1
		break
	}
	// All lines are empty
	if !found {
		return position{}, true
	}
	// Correct line
	if hasSuffix(line, lastChars) {
		return position{}, true
	}

	pos.column = len([]rune(line)) + 1
	return pos, false
}

// checkCapital checks that the each sentense of the text starts with
// a capital letter.
// NOTE: First letter is not checked in declaration comments, because they
// can describe unexported functions, which start from small letter.
func checkCapital(comment string, skipFirst bool) (pp []position) {
	// List of states during the scan: `empty` - nothing special,
	// `endChar` - found one of sentence ending chars (.!?),
	// `endOfSentence` - found `endChar`, and then space or newline.
	const empty, endChar, endOfSentence = 1, 2, 3

	pos := position{line: 1}
	state := endOfSentence
	if skipFirst {
		state = empty
	}
	for _, r := range comment {
		s := string(r)

		pos.column++
		if s == "\n" {
			pos.line++
			pos.column = 0
			if state == endChar {
				state = endOfSentence
			}
			continue
		}
		if s == "." || s == "!" || s == "?" {
			state = endChar
			continue
		}
		if s == ")" && state == endChar {
			continue
		}
		if s == " " {
			if state == endChar {
				state = endOfSentence
			}
			continue
		}
		if state == endOfSentence && unicode.IsLower(r) {
			pp = append(pp, position{line: pos.line, column: pos.column})
		}
		state = empty
	}
	return pp
}

// isSpecialBlock checks that given block of comment lines is special and
// shouldn't be checked as a regular sentence.
func isSpecialBlock(comment string) bool {
	// Skip cgo code blocks
	// TODO: Find a better way to detect cgo code
	if strings.HasPrefix(comment, "/*") && (strings.Contains(comment, "#include") ||
		strings.Contains(comment, "#define")) {
		return true
	}
	return false
}

// isSpecialBlock checks that given comment line is special and
// shouldn't be checked as a regular sentence.
func isSpecialLine(comment string) bool {
	// Skip cgo export tags: https://golang.org/cmd/cgo/#hdr-C_references_to_Go
	if strings.HasPrefix(comment, "//export ") {
		return true
	}

	comment = strings.TrimPrefix(comment, "//")
	comment = strings.TrimPrefix(comment, "/*")

	// Don't check comments starting with space indentation - they may
	// contain code examples, which shouldn't end with period
	if strings.HasPrefix(comment, "  ") ||
		strings.HasPrefix(comment, " \t") ||
		strings.HasPrefix(comment, "\t") {
		return true
	}

	// Skip tags and URLs
	comment = strings.TrimSpace(comment)
	if tags.MatchString(comment) ||
		hashtags.MatchString(comment) ||
		endURL.MatchString(comment) ||
		strings.HasPrefix(comment, "+build") {
		return true
	}

	return false
}

func hasSuffix(s string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}
