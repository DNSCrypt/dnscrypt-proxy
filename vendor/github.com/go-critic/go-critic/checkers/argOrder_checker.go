package checkers

import (
	"go/ast"
	"go/types"

	"github.com/go-critic/go-critic/checkers/internal/astwalk"
	"github.com/go-critic/go-critic/framework/linter"
	"github.com/go-toolsmith/astcast"
	"github.com/go-toolsmith/astcopy"
	"github.com/go-toolsmith/astp"
	"github.com/go-toolsmith/typep"
)

func init() {
	var info linter.CheckerInfo
	info.Name = "argOrder"
	info.Tags = []string{"diagnostic"}
	info.Summary = "Detects suspicious arguments order"
	info.Before = `strings.HasPrefix("#", userpass)`
	info.After = `strings.HasPrefix(userpass, "#")`

	collection.AddChecker(&info, func(ctx *linter.CheckerContext) (linter.FileWalker, error) {
		return astwalk.WalkerForExpr(&argOrderChecker{ctx: ctx}), nil
	})
}

type argOrderChecker struct {
	astwalk.WalkHandler
	ctx *linter.CheckerContext
}

func (c *argOrderChecker) VisitExpr(expr ast.Expr) {
	call := astcast.ToCallExpr(expr)

	// For now only handle functions of 2 args.
	// TODO(quasilyte): generalize the algorithm and add more patterns.
	if len(call.Args) != 2 {
		return
	}

	calledExpr := astcast.ToSelectorExpr(call.Fun)
	obj, ok := c.ctx.TypesInfo.ObjectOf(astcast.ToIdent(calledExpr.X)).(*types.PkgName)
	if !ok || !isStdlibPkg(obj.Imported()) {
		return
	}

	x := call.Args[0]
	y := call.Args[1]
	switch calledExpr.Sel.Name {
	case "HasPrefix", "HasSuffix", "Contains", "TrimPrefix", "TrimSuffix", "Split":
		if obj.Name() != "bytes" && obj.Name() != "strings" {
			return
		}
		if c.isConstLiteral(x) && !c.isConstLiteral(y) {
			c.warn(call)
		}
	}
}

func (c *argOrderChecker) isConstLiteral(x ast.Expr) bool {
	// Also permit byte slices.
	switch x := x.(type) {
	case *ast.BasicLit:
		return true

	case *ast.CallExpr:
		// Handle `[]byte("abc")` as well.
		if len(x.Args) != 1 || !astp.IsBasicLit(x.Args[0]) {
			return false
		}
		typ, ok := c.ctx.TypeOf(x.Fun).(*types.Slice)
		return ok && typep.HasUint8Kind(typ.Elem())

	case *ast.CompositeLit:
		// Check if it's a const byte slice.
		typ, ok := c.ctx.TypeOf(x).(*types.Slice)
		if !ok || !typep.HasUint8Kind(typ.Elem()) {
			return false
		}
		for _, elt := range x.Elts {
			if !astp.IsBasicLit(elt) {
				return false
			}
		}
		return true

	default:
		return false
	}
}

func (c *argOrderChecker) warn(call *ast.CallExpr) {
	fixed := astcopy.CallExpr(call)
	fixed.Args[0], fixed.Args[1] = fixed.Args[1], fixed.Args[0]
	c.ctx.Warn(call, "probably meant `%s`", fixed)
}
