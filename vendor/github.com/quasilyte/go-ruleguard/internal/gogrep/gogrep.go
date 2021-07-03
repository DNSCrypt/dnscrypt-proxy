package gogrep

import (
	"go/ast"
	"go/token"

	"github.com/quasilyte/go-ruleguard/nodetag"
)

func IsEmptyNodeSlice(n ast.Node) bool {
	if list, ok := n.(nodeSlice); ok {
		return list.len() == 0
	}
	return false
}

// MatchData describes a successful pattern match.
type MatchData struct {
	Node    ast.Node
	Capture []CapturedNode
}

type CapturedNode struct {
	Name string
	Node ast.Node
}

func (data MatchData) CapturedByName(name string) (ast.Node, bool) {
	return findNamed(data.Capture, name)
}

type Pattern struct {
	m *matcher
}

func (p *Pattern) NodeTag() nodetag.Value {
	return operationInfoTable[p.m.prog.insts[0].op].Tag
}

// MatchNode calls cb if n matches a pattern.
func (p *Pattern) MatchNode(n ast.Node, cb func(MatchData)) {
	p.m.MatchNode(n, cb)
}

// Clone creates a pattern copy.
func (p *Pattern) Clone() *Pattern {
	clone := *p
	clone.m = &matcher{}
	*clone.m = *p.m
	clone.m.capture = make([]CapturedNode, 0, 8)
	return &clone
}

func Compile(fset *token.FileSet, src string, strict bool) (*Pattern, error) {
	n, err := parseExpr(fset, src)
	if err != nil {
		return nil, err
	}
	var c compiler
	prog, err := c.Compile(fset, n, strict)
	if err != nil {
		return nil, err
	}
	m := newMatcher(prog)
	return &Pattern{m: m}, nil
}
