package checkers

import (
	"go/ast"

	"github.com/go-critic/go-critic/checkers/internal/astwalk"
	"github.com/go-critic/go-critic/framework/linter"
	"github.com/go-toolsmith/typep"
)

func init() {
	var info linter.CheckerInfo
	info.Name = "stringXbytes"
	info.Tags = []string{"style"}
	info.Summary = "Detects redundant conversions between string and []byte"
	info.Before = `copy(b, []byte(s))`
	info.After = `copy(b, s)`

	collection.AddChecker(&info, func(ctx *linter.CheckerContext) (linter.FileWalker, error) {
		return astwalk.WalkerForExpr(&stringXbytes{ctx: ctx}), nil
	})
}

type stringXbytes struct {
	astwalk.WalkHandler
	ctx *linter.CheckerContext
}

func (c *stringXbytes) VisitExpr(expr ast.Expr) {
	x, ok := expr.(*ast.CallExpr)
	if !ok || qualifiedName(x.Fun) != "copy" || len(x.Args) != 2 {
		return
	}

	src := x.Args[1]

	byteCast, ok := src.(*ast.CallExpr)
	if ok && typep.IsTypeExpr(c.ctx.TypesInfo, byteCast.Fun) &&
		typep.HasStringProp(c.ctx.TypeOf(byteCast.Args[0])) {

		c.warn(byteCast, byteCast.Args[0])
	}
}

func (c *stringXbytes) warn(cause *ast.CallExpr, suggestion ast.Expr) {
	c.ctx.Warn(cause, "can simplify `%s` to `%s`", cause, suggestion)
}
