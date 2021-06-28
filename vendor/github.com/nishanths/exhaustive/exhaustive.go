// Package exhaustive provides an analyzer that checks exhaustiveness of enum
// switch statements. The analyzer also provides fixes to make the offending
// switch statements exhaustive (see "Fixes" section).
//
// See "cmd/exhaustive" subpackage for the related command line program.
//
// Definition of enum
//
// The Go language spec does not provide an explicit definition for enums.
// For the purpose of this program, an enum type is a package-level named type
// whose underlying type is an integer (includes byte and rune), a float, or
// a string type. An enum type must have associated with it one or more
// package-level variables of the named type in the package. These variables
// constitute the enum's members.
//
// In the code snippet below, Biome is an enum type with 3 members. (You may
// also use iota instead of explicitly specifying values.)
//
//   type Biome int
//
//   const (
//       Tundra  Biome = 1
//       Savanna Biome = 2
//       Desert  Biome = 3
//   )
//
// Switch statement exhaustiveness
//
// An enum switch statement is exhaustive if it has cases for each of the enum's members.
//
// For an enum type defined in the same package as the switch statement, both
// exported and unexported enum members must be present in order to consider
// the switch exhaustive. On the other hand, for an enum type defined
// in an external package it is sufficient for just exported enum members
// to be present in order to consider the switch exhaustive.
//
// Flags
//
// The analyzer accepts a boolean flag: -default-signifies-exhaustive.
// The flag, if enabled, indicates to the analyzer that switch statements
// are to be considered exhaustive as long as a 'default' case is present, even
// if all enum members aren't listed in the switch statements cases.
//
// The -check-generated boolean flag, disabled by default, indicates whether
// to check switch statements in generated Go source files.
//
// The other relevant flag is the -fix flag; its behavior is described
// in the next section.
//
// Fixes
//
// The analyzer suggests fixes for a switch statement if it is not exhaustive
// and does not have a 'default' case. The suggested fix always adds a single
// case clause for the missing enum members.
//
//   case MissingA, MissingB, MissingC:
//       panic(fmt.Sprintf("unhandled value: %v", v))
//
// where v is the expression in the switch statement's tag (in other words, the
// value being switched upon). If the switch statement's tag is a function or a
// method call the analyzer does not suggest a fix, as reusing the call expression
// in the panic/fmt.Sprintf call could be mutative.
//
// The rationale for the fix using panic is that it might be better to fail loudly on
// existing unhandled or impossible cases than to let them slip by quietly unnoticed.
// An even better fix may, of course, be to manually inspect the sites reported
// by the package and handle the missing cases if necessary.
//
// Imports will be adjusted automatically to account for the "fmt" dependency.
//
// Skipping analysis
//
// If the following directive comment:
//
//   //exhaustive:ignore
//
// is associated with a switch statement, the analyzer skips
// checking of the switch statement and no diagnostics are reported.
//
// Additionally, no diagnostics are reported for switch statements in
// generated files (see https://golang.org/s/generatedcode for definition of
// generated file), unless the -check-generated flag is enabled.
package exhaustive

import (
	"go/ast"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// Flag names used by the analyzer. They are exported for use by analyzer
// driver programs.
const (
	DefaultSignifiesExhaustiveFlag = "default-signifies-exhaustive"
	CheckGeneratedFlag             = "check-generated"
)

var (
	fDefaultSignifiesExhaustive bool
	fCheckGeneratedFiles        bool
)

func init() {
	Analyzer.Flags.BoolVar(&fDefaultSignifiesExhaustive, DefaultSignifiesExhaustiveFlag, false, "indicates that switch statements are to be considered exhaustive if a 'default' case is present, even if all enum members aren't listed in the switch")
	Analyzer.Flags.BoolVar(&fCheckGeneratedFiles, CheckGeneratedFlag, false, "check switch statements in generated files also")
}

var Analyzer = &analysis.Analyzer{
	Name:      "exhaustive",
	Doc:       "check exhaustiveness of enum switch statements",
	Run:       run,
	Requires:  []*analysis.Analyzer{inspect.Analyzer},
	FactTypes: []analysis.Fact{&enumsFact{}},
}

// IgnoreDirectivePrefix is used to exclude checking of specific switch statements.
// See package comment for details.
const IgnoreDirectivePrefix = "//exhaustive:ignore"

func containsIgnoreDirective(comments []*ast.Comment) bool {
	for _, c := range comments {
		if strings.HasPrefix(c.Text, IgnoreDirectivePrefix) {
			return true
		}
	}
	return false
}

type enumsFact struct {
	Enums enums
}

var _ analysis.Fact = (*enumsFact)(nil)

func (e *enumsFact) AFact() {}

func (e *enumsFact) String() string {
	// sort for stability (required for testing)
	var sortedKeys []string
	for k := range e.Enums {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	var buf strings.Builder
	for i, k := range sortedKeys {
		v := e.Enums[k]
		buf.WriteString(k)
		buf.WriteString(":")

		for j, vv := range v.OrderedNames {
			buf.WriteString(vv)
			// add comma separator between each enum member in an enum type
			if j != len(v.OrderedNames)-1 {
				buf.WriteString(",")
			}
		}
		// add semicolon separator between each enum type
		if i != len(sortedKeys)-1 {
			buf.WriteString("; ")
		}
	}
	return buf.String()
}

func run(pass *analysis.Pass) (interface{}, error) {
	e := findEnums(pass)
	if len(e) != 0 {
		pass.ExportPackageFact(&enumsFact{Enums: e})
	}

	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	comments := make(map[*ast.File]ast.CommentMap) // CommentMap per package file, lazily populated by reference
	generated := make(map[*ast.File]bool)

	checkSwitchStatements(pass, inspect, comments, generated)
	return nil, nil
}

func enumTypeName(e *types.Named, samePkg bool) string {
	if samePkg {
		return e.Obj().Name()
	}
	return e.Obj().Pkg().Name() + "." + e.Obj().Name()
}
