package checkers

import (
	"go/ast"

	"github.com/go-critic/go-critic/checkers/internal/astwalk"
	"github.com/go-critic/go-critic/framework/linter"
	"github.com/go-toolsmith/astequal"
)

func init() {
	var info linter.CheckerInfo
	info.Name = "badLock"
	info.Tags = []string{"diagnostic", "experimental"}
	info.Summary = "Detects suspicious mutex lock/unlock operations"
	info.Before = `
mu.Lock()
mu.Unlock()`
	info.After = `
mu.Lock()
defer mu.Unlock()`

	collection.AddChecker(&info, func(ctx *linter.CheckerContext) (linter.FileWalker, error) {
		return astwalk.WalkerForStmtList(&badLockChecker{ctx: ctx}), nil
	})
}

type badLockChecker struct {
	astwalk.WalkHandler
	ctx *linter.CheckerContext
}

func (c *badLockChecker) VisitStmtList(list []ast.Stmt) {
	if len(list) < 2 {
		return
	}

	for i := 0; i < len(list)-1; i++ {
		current, ok := list[i].(*ast.ExprStmt)
		if !ok {
			continue
		}
		deferred := false
		var next ast.Expr
		switch x := list[i+1].(type) {
		case *ast.ExprStmt:
			next = x.X
		case *ast.DeferStmt:
			next = x.Call
			deferred = true
		default:
			continue
		}

		mutex1, lockFunc, ok := c.asLockedMutex(current.X)
		if !ok {
			continue
		}
		mutex2, unlockFunc, ok := c.asUnlockedMutex(next)
		if !ok {
			continue
		}
		if !astequal.Expr(mutex1, mutex2) {
			continue
		}

		switch {
		case !deferred:
			c.warnImmediateUnlock(mutex2)
		case lockFunc == "Lock" && unlockFunc == "RUnlock":
			c.warnMismatchingUnlock(mutex2, "Unlock")
		case lockFunc == "RLock" && unlockFunc == "Unlock":
			c.warnMismatchingUnlock(mutex2, "RUnlock")
		}
	}
}

func (c *badLockChecker) asLockedMutex(e ast.Expr) (ast.Expr, string, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return nil, "", false
	}
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		if fn.Sel.Name == "Lock" || fn.Sel.Name == "RLock" {
			return fn.X, fn.Sel.Name, true
		}
		return nil, "", false
	default:
		return nil, "", false
	}
}

func (c *badLockChecker) asUnlockedMutex(e ast.Expr) (ast.Expr, string, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return nil, "", false
	}
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		if fn.Sel.Name == "Unlock" || fn.Sel.Name == "RUnlock" {
			return fn.X, fn.Sel.Name, true
		}
		return nil, "", false
	default:
		return nil, "", false
	}
}

func (c *badLockChecker) warnImmediateUnlock(cause ast.Node) {
	c.ctx.Warn(cause, "defer is missing, mutex is unlocked immediately")
}

func (c *badLockChecker) warnMismatchingUnlock(cause ast.Node, suggestion string) {
	c.ctx.Warn(cause, "suspicious unlock, maybe %s was intended?", suggestion)
}
