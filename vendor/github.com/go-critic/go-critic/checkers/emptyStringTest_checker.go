package checkers

import (
	"go/ast"
	"go/token"

	"github.com/go-critic/go-critic/checkers/internal/astwalk"
	"github.com/go-critic/go-critic/framework/linter"
	"github.com/go-toolsmith/astcast"
	"github.com/go-toolsmith/astcopy"
	"github.com/go-toolsmith/typep"
)

func init() {
	var info linter.CheckerInfo
	info.Name = "emptyStringTest"
	info.Tags = []string{"style", "experimental"}
	info.Summary = "Detects empty string checks that can be written more idiomatically"
	info.Before = `len(s) == 0`
	info.After = `s == ""`
	info.Note = "See https://dmitri.shuralyov.com/idiomatic-go#empty-string-check."

	collection.AddChecker(&info, func(ctx *linter.CheckerContext) (linter.FileWalker, error) {
		return astwalk.WalkerForExpr(&emptyStringTestChecker{ctx: ctx}), nil
	})
}

type emptyStringTestChecker struct {
	astwalk.WalkHandler
	ctx *linter.CheckerContext
}

func (c *emptyStringTestChecker) VisitExpr(e ast.Expr) {
	cmp := astcast.ToBinaryExpr(e)
	if cmp.Op != token.EQL && cmp.Op != token.NEQ {
		return
	}
	lenCall := astcast.ToCallExpr(cmp.X)
	if astcast.ToIdent(lenCall.Fun).Name != "len" {
		return
	}
	s := lenCall.Args[0]
	if !typep.HasStringProp(c.ctx.TypeOf(s)) {
		return
	}
	zero := astcast.ToBasicLit(cmp.Y)
	if zero.Value != "0" {
		return
	}
	c.warn(cmp, s)
}

func (c *emptyStringTestChecker) warn(cmp *ast.BinaryExpr, s ast.Expr) {
	suggest := astcopy.BinaryExpr(cmp)
	suggest.X = s
	suggest.Y = &ast.BasicLit{Value: `""`}
	c.ctx.Warn(cmp, "replace `%s` with `%s`", cmp, suggest)
}
