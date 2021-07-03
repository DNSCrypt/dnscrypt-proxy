package gogrep

import (
	"go/ast"
	"go/token"
)

type nodeSlice interface {
	at(i int) ast.Node
	len() int
	slice(from, to int) nodeSlice
	ast.Node
}

type (
	exprSlice  []ast.Expr
	stmtSlice  []ast.Stmt
	fieldSlice []*ast.Field
	identSlice []*ast.Ident
	specSlice  []ast.Spec
)

func (l exprSlice) len() int                 { return len(l) }
func (l exprSlice) at(i int) ast.Node        { return l[i] }
func (l exprSlice) slice(i, j int) nodeSlice { return l[i:j] }
func (l exprSlice) Pos() token.Pos           { return l[0].Pos() }
func (l exprSlice) End() token.Pos           { return l[len(l)-1].End() }

func (l stmtSlice) len() int                 { return len(l) }
func (l stmtSlice) at(i int) ast.Node        { return l[i] }
func (l stmtSlice) slice(i, j int) nodeSlice { return l[i:j] }
func (l stmtSlice) Pos() token.Pos           { return l[0].Pos() }
func (l stmtSlice) End() token.Pos           { return l[len(l)-1].End() }

func (l fieldSlice) len() int                 { return len(l) }
func (l fieldSlice) at(i int) ast.Node        { return l[i] }
func (l fieldSlice) slice(i, j int) nodeSlice { return l[i:j] }
func (l fieldSlice) Pos() token.Pos           { return l[0].Pos() }
func (l fieldSlice) End() token.Pos           { return l[len(l)-1].End() }

func (l identSlice) len() int                 { return len(l) }
func (l identSlice) at(i int) ast.Node        { return l[i] }
func (l identSlice) slice(i, j int) nodeSlice { return l[i:j] }
func (l identSlice) Pos() token.Pos           { return l[0].Pos() }
func (l identSlice) End() token.Pos           { return l[len(l)-1].End() }

func (l specSlice) len() int                 { return len(l) }
func (l specSlice) at(i int) ast.Node        { return l[i] }
func (l specSlice) slice(i, j int) nodeSlice { return l[i:j] }
func (l specSlice) Pos() token.Pos           { return l[0].Pos() }
func (l specSlice) End() token.Pos           { return l[len(l)-1].End() }
