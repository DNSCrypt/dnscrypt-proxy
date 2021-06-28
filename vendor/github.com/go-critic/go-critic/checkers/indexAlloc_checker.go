package checkers

import (
	"go/ast"

	"github.com/go-critic/go-critic/checkers/internal/astwalk"
	"github.com/go-critic/go-critic/framework/linter"
	"github.com/go-toolsmith/astcast"
	"github.com/go-toolsmith/typep"
)

func init() {
	var info linter.CheckerInfo
	info.Name = "indexAlloc"
	info.Tags = []string{"performance"}
	info.Summary = "Detects strings.Index calls that may cause unwanted allocs"
	info.Before = `strings.Index(string(x), y)`
	info.After = `bytes.Index(x, []byte(y))`
	info.Note = `See Go issue for details: https://github.com/golang/go/issues/25864`

	collection.AddChecker(&info, func(ctx *linter.CheckerContext) (linter.FileWalker, error) {
		return astwalk.WalkerForExpr(&indexAllocChecker{ctx: ctx}), nil
	})
}

type indexAllocChecker struct {
	astwalk.WalkHandler
	ctx *linter.CheckerContext
}

func (c *indexAllocChecker) VisitExpr(e ast.Expr) {
	call := astcast.ToCallExpr(e)
	if qualifiedName(call.Fun) != "strings.Index" {
		return
	}
	stringConv := astcast.ToCallExpr(call.Args[0])
	if qualifiedName(stringConv.Fun) != "string" {
		return
	}
	x := stringConv.Args[0]
	y := call.Args[1]
	if typep.SideEffectFree(c.ctx.TypesInfo, x) && typep.SideEffectFree(c.ctx.TypesInfo, y) {
		c.warn(e, x, y)
	}
}

func (c *indexAllocChecker) warn(cause ast.Node, x, y ast.Expr) {
	c.ctx.Warn(cause, "consider replacing %s with bytes.Index(%s, []byte(%s))",
		cause, x, y)
}
