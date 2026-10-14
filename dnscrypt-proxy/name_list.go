package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jedisct1/dlog"
	revera "github.com/oneregex/revera/go"
)

const (
	regexKeyword = "regex:"

	// Longest name regex rules are checked against: a full-size DNS name with
	// every byte written as \DDD.
	regexMaxSubjectLen = 1003

	// Maximum cost of all the regex rules of a list, in Revera steps.
	// A query checks the allowlist once and the blocklist up to 1+aliasesLimit
	// times, so this also limits the cost of a query.
	regexMaxSteps int64 = 250_000_000

	regexMaxExpressionLen = 1024
	regexMaxRules         = 1000

	// Revera reports this cost when it is too large to compute.
	reveraSaturatedSteps = int64(1) << 62
)

// nameRegexp is a compiled expression. Tests replace it to simulate errors.
type nameRegexp interface {
	MatchString(subject string) (bool, error)
}

type regexRule struct {
	re           nameRegexp
	directive    string
	weeklyRanges *WeeklyRanges
	line         int
}

// NameList holds the rules of a blocked or allowed names file.
// It never changes once loaded, so concurrent queries can share it.
type NameList struct {
	patternMatcher *PatternMatcher
	regexRules     []regexRule
	fileName       string
}

// LoadNameList parses a name list file.
// Invalid ordinary rules are logged and skipped, but any problem with a regex
// rule rejects the whole file.
func LoadNameList(fileName string, lines string, allWeeklyRanges *map[string]WeeklyRanges) (*NameList, error) {
	nameList := &NameList{
		patternMatcher: NewPatternMatcher(),
		fileName:       fileName,
	}
	var totalSteps int64
	for lineNo, line := range strings.Split(lines, "\n") {
		if candidate, ok := regexDirectiveCandidate(line); ok {
			if len(nameList.regexRules) >= regexMaxRules {
				return nil, fmt.Errorf("%s:%d: too many regex rules, the limit is %d per list", fileName, lineNo+1, regexMaxRules)
			}
			rule, steps, err := compileRegexRule(candidate, line, allWeeklyRanges)
			if err == nil {
				err = checkRegexCost(totalSteps, steps, regexMaxSteps)
			}
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", fileName, lineNo+1, err)
			}
			totalSteps += steps
			rule.line = lineNo + 1
			nameList.regexRules = append(nameList.regexRules, rule)
			continue
		}
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		rulePart, weeklyRanges, err := ParseTimeBasedRule(line, lineNo, allWeeklyRanges)
		if err != nil {
			dlog.Error(err)
			continue
		}
		if err := nameList.patternMatcher.Add(rulePart, weeklyRanges, lineNo+1); err != nil {
			dlog.Error(err)
			continue
		}
	}
	return nameList, nil
}

// regexDirectiveCandidate reports whether a line looks like a regex rule, even
// a broken one, so that it never ends up parsed as an ordinary rule.
func regexDirectiveCandidate(line string) (string, bool) {
	trimmed := strings.TrimLeftFunc(line, unicode.IsSpace)
	if len(trimmed) < len(regexKeyword) || !strings.EqualFold(trimmed[:len(regexKeyword)], regexKeyword) {
		return "", false
	}
	return trimmed, true
}

func compileRegexRule(candidate string, line string, allWeeklyRanges *map[string]WeeklyRanges) (regexRule, int64, error) {
	var rule regexRule
	if leading := line[:len(line)-len(candidate)]; strings.Trim(leading, " \t") != "" {
		return rule, 0, fmt.Errorf("only spaces and tabs can precede %q", regexKeyword)
	}
	directive, expression, weeklyRanges, err := parseRegexDirective(strings.TrimSuffix(candidate, "\r"), allWeeklyRanges)
	if err != nil {
		return rule, 0, err
	}
	re, steps, err := compileRegex(expression)
	if err != nil {
		return rule, 0, fmt.Errorf("cannot compile `%s`: %w", expression, err)
	}
	rule.re = re
	// Copy the text, so that the list doesn't keep the whole file in memory
	rule.directive = strings.Clone(directive)
	rule.weeklyRanges = weeklyRanges
	return rule, steps, nil
}

// compileRegex compiles an expression and returns its cost for the longest names.
func compileRegex(expression string) (*revera.Regexp, int64, error) {
	re, err := revera.New(expression, revera.CaseInsensitive(), revera.NoCaptures())
	if err != nil {
		return nil, 0, err
	}
	return re, re.Contract(regexMaxSubjectLen).Steps(), nil
}

func checkRegexCost(totalSteps int64, steps int64, maxSteps int64) error {
	if steps < 0 || steps >= reveraSaturatedSteps {
		return errors.New("the cost of this rule is too large to compute")
	}
	if steps > maxSteps-totalSteps {
		return fmt.Errorf("this rule costs %d steps and brings the regex rules of the list to %d steps, over the limit of %d",
			steps, uint64(totalSteps)+uint64(steps), maxSteps)
	}
	return nil
}

// parseRegexDirective parses a line such as:
//
//	regex: `expression` @schedule # comment
//
// The schedule and the comment are optional.
// directive is the rule as written, without them, and is what logs show.
func parseRegexDirective(line string, allWeeklyRanges *map[string]WeeklyRanges) (directive string, expression string, weeklyRanges *WeeklyRanges, err error) {
	if !strings.HasPrefix(line, regexKeyword) {
		return "", "", nil, fmt.Errorf("the regex keyword must be written in lowercase as %q", regexKeyword)
	}
	rest := strings.TrimLeft(line[len(regexKeyword):], " \t")
	if !strings.HasPrefix(rest, "`") {
		return "", "", nil, fmt.Errorf("expected an expression between backticks after %q, such as regex: `^example\\.com$`", regexKeyword)
	}
	end := strings.IndexByte(rest[1:], '`')
	if end < 0 {
		return "", "", nil, errors.New("missing closing backtick")
	}
	expression = rest[1 : 1+end]
	directive = line[:len(line)-len(rest)+end+2]
	tail := rest[end+2:]

	if len(expression) == 0 {
		return "", "", nil, errors.New("empty expression")
	}
	if len(expression) > regexMaxExpressionLen {
		return "", "", nil, fmt.Errorf("the expression is %d bytes long, the limit is %d", len(expression), regexMaxExpressionLen)
	}
	for i := 0; i < len(expression); i++ {
		c := expression[i]
		if c >= utf8.RuneSelf {
			return "", "", nil, fmt.Errorf("non-ASCII byte at offset %d of the expression; internationalized names must be written in their ASCII (xn--) form", i)
		}
		if c < 0x20 || c == 0x7f {
			return "", "", nil, fmt.Errorf("control character at offset %d of the expression", i)
		}
	}

	if len(tail) > 0 && tail[0] != ' ' && tail[0] != '\t' {
		if strings.IndexByte(tail, '`') >= 0 {
			return "", "", nil, errors.New("backticks are not supported in expressions")
		}
		return "", "", nil, errors.New("expected a space or a tab after the closing backtick")
	}
	tail = strings.TrimLeft(tail, " \t")
	if strings.HasPrefix(tail, "@") {
		name := tail[1:]
		tail = ""
		if i := strings.IndexAny(name, " \t"); i >= 0 {
			name, tail = name[:i], strings.TrimLeft(name[i:], " \t")
		}
		switch {
		case len(name) == 0:
			return "", "", nil, errors.New("empty schedule name after @")
		case strings.ContainsFunc(name, unicode.IsSpace):
			return "", "", nil, errors.New("schedule names cannot contain whitespace")
		case strings.Contains(name, "@"):
			return "", "", nil, errors.New("only one schedule can be given")
		case strings.Contains(name, "#"):
			return "", "", nil, errors.New("expected a space or a tab between the schedule name and the comment")
		}
		ranges, ok := (*allWeeklyRanges)[name]
		if !ok {
			return "", "", nil, fmt.Errorf("time range [%s] not found", name)
		}
		weeklyRanges = &ranges
	}
	switch {
	case len(tail) == 0, tail[0] == '#':
	case tail[0] == '@':
		return "", "", nil, errors.New("only one schedule can be given")
	case strings.IndexByte(tail, '`') >= 0:
		return "", "", nil, errors.New("backticks are not supported in expressions")
	default:
		return "", "", nil, fmt.Errorf("unexpected text after the expression: %q", tail)
	}
	return directive, expression, weeklyRanges, nil
}

// Eval returns the rule that applies to a normalized name right now.
// Ordinary rules come first: if one matches but its schedule is inactive,
// nothing applies.
// Otherwise, the first active regex rule that matches wins.
func (nameList *NameList) Eval(qName string) (matched bool, reason string, err error) {
	var now time.Time
	matched, reason, val := nameList.patternMatcher.Eval(qName)
	if matched {
		weeklyRanges, _ := val.(*WeeklyRanges)
		if !scheduleActive(weeklyRanges, &now) {
			return false, "", nil
		}
		return true, reason, nil
	}
	for i := range nameList.regexRules {
		rule := &nameList.regexRules[i]
		if !scheduleActive(rule.weeklyRanges, &now) {
			continue
		}
		if len(qName) > regexMaxSubjectLen {
			return false, "", fmt.Errorf("name is %d bytes long, longer than the %d bytes regex rules support", len(qName), regexMaxSubjectLen)
		}
		found, err := rule.re.MatchString(qName)
		if err != nil {
			return false, "", fmt.Errorf("%s:%d: %w", nameList.fileName, rule.line, err)
		}
		if found {
			return true, rule.directive, nil
		}
	}
	return false, "", nil
}

// scheduleActive reads the clock at most once per name.
func scheduleActive(weeklyRanges *WeeklyRanges, now *time.Time) bool {
	if weeklyRanges == nil {
		return true
	}
	if now.IsZero() {
		*now = time.Now().Local()
	}
	return weeklyRanges.Match(*now)
}
