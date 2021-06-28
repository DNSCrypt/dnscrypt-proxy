package ruleguard

import (
	"go/ast"
	"go/token"
	"go/types"
	"io"
)

// Engine is the main ruleguard package API object.
//
// First, load some ruleguard files with Load() to build a rule set.
// Then use Run() to execute the rules.
//
// It's advised to have only 1 engine per application as it does a lot of caching.
// The Run() method is synchronized, so it can be used concurrently.
//
// An Engine must be created with NewEngine() function.
type Engine struct {
	impl *engine
}

// NewEngine creates an engine with empty rule set.
func NewEngine() *Engine {
	return &Engine{impl: newEngine()}
}

// Load reads a ruleguard file from r and adds it to the engine rule set.
//
// Load() is not thread-safe, especially if used concurrently with Run() method.
// It's advised to Load() all ruleguard files under a critical section (like sync.Once)
// and then use Run() to execute all of them.
func (e *Engine) Load(ctx *ParseContext, filename string, r io.Reader) error {
	return e.impl.Load(ctx, filename, r)
}

// Run executes all loaded rules on a given file.
// Matched rules invoke `RunContext.Report()` method.
//
// Run() is thread-safe, unless used in parallel with Load(),
// which modifies the engine state.
func (e *Engine) Run(ctx *RunContext, f *ast.File) error {
	return e.impl.Run(ctx, f)
}

type ParseContext struct {
	DebugFilter  string
	DebugImports bool
	DebugPrint   func(string)

	// GroupFilter is called for every rule group being parsed.
	// If function returns false, that group will not be included
	// in the resulting rules set.
	// Nil filter accepts all rule groups.
	GroupFilter func(string) bool

	Fset *token.FileSet
}

type RunContext struct {
	Debug        string
	DebugImports bool
	DebugPrint   func(string)

	Types  *types.Info
	Sizes  types.Sizes
	Fset   *token.FileSet
	Report func(rule GoRuleInfo, n ast.Node, msg string, s *Suggestion)
	Pkg    *types.Package
}

type Suggestion struct {
	From        token.Pos
	To          token.Pos
	Replacement []byte
}

type GoRuleInfo struct {
	// Filename is a file that defined this rule.
	Filename string

	// Line is a line inside a file that defined this rule.
	Line int

	// Group is a function name that contained this rule.
	Group string
}
