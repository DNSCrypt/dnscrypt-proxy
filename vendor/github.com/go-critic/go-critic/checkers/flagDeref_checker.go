package checkers

import (
	"go/ast"

	"github.com/go-critic/go-critic/checkers/internal/astwalk"
	"github.com/go-critic/go-critic/framework/linter"
)

func init() {
	var info linter.CheckerInfo
	info.Name = "flagDeref"
	info.Tags = []string{"diagnostic"}
	info.Summary = "Detects immediate dereferencing of `flag` package pointers"
	info.Details = "Suggests to use pointer to array to avoid the copy using `&` on range expression."
	info.Before = `b := *flag.Bool("b", false, "b docs")`
	info.After = `
var b bool
flag.BoolVar(&b, "b", false, "b docs")`
	info.Note = `
Dereferencing returned pointers will lead to hard to find errors
where flag values are not updated after flag.Parse().`

	collection.AddChecker(&info, func(ctx *linter.CheckerContext) (linter.FileWalker, error) {
		c := &flagDerefChecker{
			ctx: ctx,
			flagPtrFuncs: map[string]bool{
				"flag.Bool":     true,
				"flag.Duration": true,
				"flag.Float64":  true,
				"flag.Int":      true,
				"flag.Int64":    true,
				"flag.String":   true,
				"flag.Uint":     true,
				"flag.Uint64":   true,
			},
		}
		return astwalk.WalkerForExpr(c), nil
	})
}

type flagDerefChecker struct {
	astwalk.WalkHandler
	ctx *linter.CheckerContext

	flagPtrFuncs map[string]bool
}

func (c *flagDerefChecker) VisitExpr(expr ast.Expr) {
	if expr, ok := expr.(*ast.StarExpr); ok {
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			return
		}
		called := qualifiedName(call.Fun)
		if c.flagPtrFuncs[called] {
			c.warn(expr, called+"Var")
		}
	}
}

func (c *flagDerefChecker) warn(x ast.Node, suggestion string) {
	c.ctx.Warn(x, "immediate deref in %s is most likely an error; consider using %s",
		x, suggestion)
}
