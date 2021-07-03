package checkers

import (
	"go/ast"
	"go/token"

	"github.com/go-critic/go-critic/checkers/internal/astwalk"
	"github.com/go-critic/go-critic/framework/linter"
	"github.com/go-toolsmith/astcopy"
	"github.com/go-toolsmith/astp"
)

func init() {
	var info linter.CheckerInfo
	info.Name = "yodaStyleExpr"
	info.Tags = []string{"style", "experimental"}
	info.Summary = "Detects Yoda style expressions and suggests to replace them"
	info.Before = `return nil != ptr`
	info.After = `return ptr != nil`

	collection.AddChecker(&info, func(ctx *linter.CheckerContext) (linter.FileWalker, error) {
		return astwalk.WalkerForLocalExpr(&yodaStyleExprChecker{ctx: ctx}), nil
	})
}

type yodaStyleExprChecker struct {
	astwalk.WalkHandler
	ctx *linter.CheckerContext
}

func (c *yodaStyleExprChecker) VisitLocalExpr(expr ast.Expr) {
	binexpr, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return
	}
	switch binexpr.Op {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GEQ, token.GTR:
		if c.isConstExpr(binexpr.X) && !c.isConstExpr(binexpr.Y) {
			c.warn(binexpr)
		}
	}
}

func (c *yodaStyleExprChecker) isConstExpr(expr ast.Expr) bool {
	return qualifiedName(expr) == "nil" || astp.IsBasicLit(expr)
}

func (c *yodaStyleExprChecker) invert(expr *ast.BinaryExpr) {
	expr.X, expr.Y = expr.Y, expr.X
	switch expr.Op {
	case token.LSS:
		expr.Op = token.GEQ
	case token.LEQ:
		expr.Op = token.GTR
	case token.GEQ:
		expr.Op = token.LSS
	case token.GTR:
		expr.Op = token.LEQ
	}
}

func (c *yodaStyleExprChecker) warn(expr *ast.BinaryExpr) {
	e := astcopy.BinaryExpr(expr)
	c.invert(e)
	c.ctx.Warn(expr, "consider to change order in expression to %s", e)
}
