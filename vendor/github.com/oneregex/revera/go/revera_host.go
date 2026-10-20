package revera

// Host file, outside the Vego subset.
// It supplies what the subset cannot express on purpose.
// Those parts are the embedded locale data and the idiomatic Go surface over the subset functions.
// Every language a translator targets writes the same two things for itself.
//
// The subset functions stay available and unchanged.
// They are the low level: an explicit locale, numeric flags, caller-owned match slices, and an Error value instead of an error.
// Everything below is a thin layer over them.

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed data.bin
var embeddedLocaleData string

// EmbeddedLocaleData returns the CLDR locale blob compiled into the Go build.
// Pass it to LocaleOpen or LocaleLoad.
func EmbeddedLocaleData() string {
	return embeddedLocaleData
}

// DupMax is the largest supported interval count.
const DupMax = dupMax

// Error implements the error interface.
// The methods below return a nil error for success, never a zero Error.
// A caller that stores a subset result in an error variable must check the code first.
// An interface that holds a zero Error is not nil.
func (e Error) Error() string {
	if e.Pos >= 0 {
		return fmt.Sprintf("revera: %s at byte %d", ErrorText(e.Code), e.Pos)
	}
	return "revera: " + ErrorText(e.Code)
}

// asError maps the subset Error onto the Go convention.
// Success gives nil, and every other code gives the value itself.
func asError(e Error) error {
	if e.Code == ErrNone {
		return nil
	}
	return e
}

// An Option changes how New compiles a pattern.
type Option func(*settings)

type settings struct {
	loc   Locale
	flags uint32
}

// CaseInsensitive matches upper and lower case alike, like REG_ICASE.
func CaseInsensitive() Option {
	return func(s *settings) { s.flags |= FlagICase }
}

// NewlineSensitive gives ^ and $ their line meaning, like REG_NEWLINE.
// It also stops dot and negated brackets on a newline.
func NewlineSensitive() Option {
	return func(s *settings) { s.flags |= FlagNewline }
}

// NoCaptures compiles for a yes-or-no answer only, like REG_NOSUB.
// MatchString still works.
// Every method that reports offsets or rewrites the subject fails with ErrENoSub.
func NoCaptures() Option {
	return func(s *settings) { s.flags |= FlagNoSub }
}

// ShortestMatch makes every duplication prefer the shortest repetition.
// A repetition modifier reverses one duplication back.
func ShortestMatch() Option {
	return func(s *settings) { s.flags |= FlagMinimal }
}

// In compiles the pattern in loc instead of the POSIX locale.
// The locale decides character classes, case folding, and the meaning of collating elements and equivalence classes.
func In(loc Locale) Option {
	return func(s *settings) { s.loc = loc }
}

// New compiles pattern as a POSIX.1-2024 extended regular expression.
// Without options it uses the POSIX locale and no flags.
func New(pattern string, opts ...Option) (*Regexp, error) {
	s := settings{loc: LocalePOSIX()}
	for _, opt := range opts {
		opt(&s)
	}
	re, err := Compile(pattern, s.loc, s.flags)
	if err.Code != ErrNone {
		return nil, err
	}
	return &re, nil
}

// MustNew is New for patterns fixed at build time.
// It panics when the pattern does not compile.
func MustNew(pattern string, opts ...Option) *Regexp {
	re, err := New(pattern, opts...)
	if err != nil {
		panic(err.Error())
	}
	return re
}

// OpenLocale resolves a CLDR locale name against the embedded data.
// An empty collation type selects the standard collation of the locale.
// LocaleNames lists the names this accepts.
func OpenLocale(name, collationType string) (Locale, error) {
	loc, ok := LocaleOpen(embeddedLocaleData, name, collationType)
	if !ok {
		return loc, fmt.Errorf("revera: no locale %q with collation %q", name, collationType)
	}
	return loc, nil
}

// LocaleNames returns every locale name in the embedded data, in the order the data stores them.
func LocaleNames() []string {
	base, ok := LocaleLoad(embeddedLocaleData)
	if !ok {
		return nil
	}
	names := make([]string, LocaleCount(&base))
	for i := range names {
		names[i] = LocaleName(&base, i)
	}
	return names
}

// NumSubexp returns the number of parenthesized subexpressions, like re_nsub.
func (re *Regexp) NumSubexp() int {
	return NumSub(re)
}

// MatchString reports whether the expression matches anywhere in subject.
func (re *Regexp) MatchString(subject string) (bool, error) {
	ok, err := Exec(re, subject, nil, 0)
	return ok, asError(err)
}

// FindStringIndex returns the byte offsets of the leftmost-longest match as a two-element slice.
// It returns nil when there is no match.
func (re *Regexp) FindStringIndex(subject string) ([]int, error) {
	pmatch, err := re.search(subject, 1)
	if pmatch == nil {
		return nil, err
	}
	return flatten(pmatch), nil
}

// FindStringSubmatchIndex returns the byte offsets of the match and of every capturing group, as consecutive start and end pairs.
// A group that took no part in the match has the pair -1, -1.
// The result is nil when there is no match.
func (re *Regexp) FindStringSubmatchIndex(subject string) ([]int, error) {
	pmatch, err := re.search(subject, NumSub(re)+1)
	if pmatch == nil {
		return nil, err
	}
	return flatten(pmatch), nil
}

// FindString returns the text of the leftmost-longest match.
// The second result reports whether there was a match.
// A match of the null string returns an empty string too.
func (re *Regexp) FindString(subject string) (string, bool, error) {
	pmatch, err := re.search(subject, 1)
	if pmatch == nil {
		return "", false, err
	}
	return subject[pmatch[0].So:pmatch[0].Eo], true, nil
}

// FindStringSubmatch returns the text of the match and of every capturing group.
// A group that took no part in the match holds the empty string, and FindStringSubmatchIndex tells the two cases apart.
// The result is nil when there is no match.
func (re *Regexp) FindStringSubmatch(subject string) ([]string, error) {
	pmatch, err := re.search(subject, NumSub(re)+1)
	if pmatch == nil {
		return nil, err
	}
	return texts(subject, pmatch), nil
}

// FindAllStringIndex returns the offsets of the first n non-overlapping matches, left to right.
// A negative n returns them all.
// The result is nil when there is no match.
func (re *Regexp) FindAllStringIndex(subject string, n int) ([][]int, error) {
	return collect(re, subject, n, func(pmatch []Match) []int {
		return []int{pmatch[0].So, pmatch[0].Eo}
	})
}

// FindAllStringSubmatchIndex returns the offsets of the first n non-overlapping matches and their groups.
// Each row uses the layout of FindStringSubmatchIndex.
// A negative n returns them all.
func (re *Regexp) FindAllStringSubmatchIndex(subject string, n int) ([][]int, error) {
	return collect(re, subject, n, flatten)
}

// FindAllString returns the text of the first n non-overlapping matches.
// A negative n returns them all.
func (re *Regexp) FindAllString(subject string, n int) ([]string, error) {
	return collect(re, subject, n, func(pmatch []Match) string {
		return subject[pmatch[0].So:pmatch[0].Eo]
	})
}

// FindAllStringSubmatch returns the text of the first n non-overlapping matches and their groups.
// A negative n returns them all.
func (re *Regexp) FindAllStringSubmatch(subject string, n int) ([][]string, error) {
	return collect(re, subject, n, func(pmatch []Match) []string {
		return texts(subject, pmatch)
	})
}

// ReplaceAllString returns subject with every non-overlapping match replaced by replacement, like the sed s///g command.
// In replacement, & stands for the whole match and \1 through \9 for one group.
// A backslash escapes the next character.
//
// The subset function ReplaceAll takes a replacement limit.
func (re *Regexp) ReplaceAllString(subject, replacement string) (string, error) {
	out, err := ReplaceAll(re, subject, replacement, -1, 0)
	return out, asError(err)
}

// ReplaceAllStringFunc returns subject with every non-overlapping match replaced by the return value of repl.
// repl receives the text of the match.
func (re *Regexp) ReplaceAllStringFunc(subject string, repl func(match string) string) (string, error) {
	var out strings.Builder
	last := 0
	any := false
	err := re.eachMatch(subject, -1, func(pmatch []Match) {
		if !any {
			out.Grow(replaceCapacity(len(subject)))
			any = true
		}
		out.WriteString(subject[last:pmatch[0].So])
		out.WriteString(repl(subject[pmatch[0].So:pmatch[0].Eo]))
		last = pmatch[0].Eo
	})
	if err != nil {
		return "", err
	}
	if !any {
		return subject, nil
	}
	out.WriteString(subject[last:])
	return out.String(), nil
}

// Contract bounds what one match can cost on a subject of at most maxInput bytes.
// An application compares the figures against its budget.
// It can then refuse the expression before the expression ever runs.
func (re *Regexp) Contract(maxInput int) Contract {
	return ContractFor(re, maxInput)
}

// HeapBytes bounds the explicit heap allocation of one match, in bytes.
func (c Contract) HeapBytes() int64 {
	return ContractHeapBytes(&c)
}

// StackBytes estimates the deepest call stack of one match, in bytes.
func (c Contract) StackBytes() int64 {
	return ContractStackBytes(&c)
}

// Steps bounds the abstract operations of one match.
// The figure counts unit-cost operations, not nanoseconds.
func (c Contract) Steps() int64 {
	return ContractSteps(&c)
}

// search runs one search for group offsets.
// It returns nil when there is no match, and the FlagNoSub error case reports the same.
func (re *Regexp) search(subject string, groups int) ([]Match, error) {
	if re.flags&FlagNoSub != 0 {
		return nil, compileError(ErrENoSub, -1)
	}
	pmatch := make([]Match, groups)
	ok, err := Exec(re, subject, pmatch, 0)
	if err.Code != ErrNone || !ok {
		return nil, asError(err)
	}
	return pmatch, nil
}

// collect gathers one value per match, for the first n non-overlapping matches.
func collect[T any](re *Regexp, subject string, n int, one func(pmatch []Match) T) ([]T, error) {
	var out []T
	err := re.eachMatch(subject, n, func(pmatch []Match) {
		out = append(out, one(pmatch))
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// eachMatch calls visit for the first n non-overlapping matches.
// It reuses one pmatch slice, so visit must copy what it keeps.
func (re *Regexp) eachMatch(subject string, n int, visit func(pmatch []Match)) error {
	it, err := MatchIterInit(re, n)
	if err.Code != ErrNone {
		return err
	}
	pmatch := make([]Match, NumSub(re)+1)
	for {
		ok, nerr := MatchIterNext(re, &it, subject, 0, pmatch)
		if nerr.Code != ErrNone {
			return nerr
		}
		if !ok {
			return nil
		}
		visit(pmatch)
	}
}

func flatten(pmatch []Match) []int {
	out := make([]int, 0, 2*len(pmatch))
	for _, m := range pmatch {
		out = append(out, m.So, m.Eo)
	}
	return out
}

func texts(subject string, pmatch []Match) []string {
	out := make([]string, len(pmatch))
	for i, m := range pmatch {
		if m.So >= 0 {
			out[i] = subject[m.So:m.Eo]
		}
	}
	return out
}

// LocaleToUpper maps one code point to upper case under the locale, and LocaleToLower to lower case.
// The driver protocol of the conformance kit uses them for its case digests.
func LocaleToUpper(l *Locale, r int32) int32 {
	return localeToUpper(l, r)
}

func LocaleToLower(l *Locale, r int32) int32 {
	return localeToLower(l, r)
}
