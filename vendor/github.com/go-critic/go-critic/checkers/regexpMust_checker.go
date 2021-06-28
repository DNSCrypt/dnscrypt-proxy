package checkers

import (
	"go/ast"
	"strings"

	"github.com/go-critic/go-critic/checkers/internal/astwalk"
	"github.com/go-critic/go-critic/framework/linter"
	"github.com/go-toolsmith/astp"
	"golang.org/x/tools/go/ast/astutil"
)

func init() {
	var info linter.CheckerInfo
	info.Name = "regexpMust"
	info.Tags = []string{"style"}
	info.Summary = "Detects `regexp.Compile*` that can be replaced with `regexp.MustCompile*`"
	info.Before = `re, _ := regexp.Compile("const pattern")`
	info.After = `re := regexp.MustCompile("const pattern")`

	collection.AddChecker(&info, func(ctx *linter.CheckerContext) (linter.FileWalker, error) {
		return astwalk.WalkerForExpr(&regexpMustChecker{ctx: ctx}), nil
	})
}

type regexpMustChecker struct {
	astwalk.WalkHandler
	ctx *linter.CheckerContext
}

func (c *regexpMustChecker) VisitExpr(x ast.Expr) {
	if x, ok := x.(*ast.CallExpr); ok {
		switch name := qualifiedName(x.Fun); name {
		case "regexp.Compile", "regexp.CompilePOSIX":
			// Only check for trivial string args, permit parenthesis.
			if !astp.IsBasicLit(astutil.Unparen(x.Args[0])) {
				return
			}
			c.warn(x, strings.Replace(name, "Compile", "MustCompile", 1))
		}
	}
}

func (c *regexpMustChecker) warn(cause *ast.CallExpr, suggestion string) {
	c.ctx.Warn(cause, "for const patterns like %s, use %s",
		cause.Args[0], suggestion)
}
