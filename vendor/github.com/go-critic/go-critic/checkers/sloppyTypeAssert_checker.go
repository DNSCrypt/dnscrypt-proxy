package checkers

import (
	"go/ast"
	"go/types"

	"github.com/go-critic/go-critic/checkers/internal/astwalk"
	"github.com/go-critic/go-critic/framework/linter"
	"github.com/go-toolsmith/astcast"
)

func init() {
	var info linter.CheckerInfo
	info.Name = "sloppyTypeAssert"
	info.Tags = []string{"diagnostic", "experimental"}
	info.Summary = "Detects redundant type assertions"
	info.Before = `
func f(r io.Reader) interface{} {
	return r.(interface{})
}
`
	info.After = `
func f(r io.Reader) interface{} {
	return r
}
`

	collection.AddChecker(&info, func(ctx *linter.CheckerContext) (linter.FileWalker, error) {
		return astwalk.WalkerForExpr(&sloppyTypeAssertChecker{ctx: ctx}), nil
	})
}

type sloppyTypeAssertChecker struct {
	astwalk.WalkHandler
	ctx *linter.CheckerContext
}

func (c *sloppyTypeAssertChecker) VisitExpr(expr ast.Expr) {
	assert := astcast.ToTypeAssertExpr(expr)
	if assert.Type == nil {
		return
	}

	toType := c.ctx.TypeOf(expr)
	fromType := c.ctx.TypeOf(assert.X)

	if types.Identical(toType, fromType) {
		c.warnIdentical(expr)
		return
	}

	toIface, ok := toType.Underlying().(*types.Interface)
	if !ok {
		return
	}

	switch {
	case toIface.Empty():
		c.warnEmpty(expr)
	case types.Implements(fromType, toIface):
		c.warnImplements(expr, assert.X)
	}
}

func (c *sloppyTypeAssertChecker) warnIdentical(cause ast.Expr) {
	c.ctx.Warn(cause, "type assertion from/to types are identical")
}

func (c *sloppyTypeAssertChecker) warnEmpty(cause ast.Expr) {
	c.ctx.Warn(cause, "type assertion to interface{} may be redundant")
}

func (c *sloppyTypeAssertChecker) warnImplements(cause, val ast.Expr) {
	c.ctx.Warn(cause, "type assertion may be redundant as %s always implements selected interface", val)
}
