package errorlint

import (
	"fmt"
	"go/ast"
	"go/types"
)

var allowedErrors = []struct {
	err string
	fun string
}{
	// pkg/archive/tar
	{err: "io.EOF", fun: "(*tar.Reader).Next"},
	{err: "io.EOF", fun: "(*tar.Reader).Read"},
	// pkg/bufio
	{err: "io.EOF", fun: "(*bufio.Reader).Read"},
	{err: "io.EOF", fun: "(*bufio.Reader).ReadByte"},
	{err: "io.EOF", fun: "(*bufio.Reader).ReadBytes"},
	{err: "io.EOF", fun: "(*bufio.Reader).ReadSlice"},
	{err: "io.EOF", fun: "(*bufio.Reader).ReadString"},
	{err: "io.EOF", fun: "(*bufio.Scanner).Scan"},
	// pkg/bytes
	{err: "io.EOF", fun: "(*bytes.Buffer).Read"},
	{err: "io.EOF", fun: "(*bytes.Buffer).ReadByte"},
	{err: "io.EOF", fun: "(*bytes.Buffer).ReadBytes"},
	{err: "io.EOF", fun: "(*bytes.Buffer).ReadRune"},
	{err: "io.EOF", fun: "(*bytes.Buffer).ReadString"},
	// pkg/database/sql
	{err: "sql.ErrNoRows", fun: "(*database/sql.Row).Scan"},
	// pkg/io
	{err: "io.EOF", fun: "(io.Reader).Read"},
	{err: "io.ErrClosedPipe", fun: "(*io.PipeWriter).Write"},
	{err: "io.ErrShortBuffer", fun: "io.ReadAtLeast"},
	{err: "io.ErrUnexpectedEOF", fun: "io.ReadAtLeast"},
	{err: "io.ErrUnexpectedEOF", fun: "io.ReadFull"},
	// pkg/os
	{err: "io.EOF", fun: "(*os.File).Read"},
	{err: "io.EOF", fun: "(*os.File).ReadAt"},
	{err: "io.EOF", fun: "(*os.File).ReadDir"},
	{err: "io.EOF", fun: "(*os.File).Readdir"},
	{err: "io.EOF", fun: "(*os.File).Readdirnames"},
	// pkg/strings
	{err: "io.EOF", fun: "(*strings.Reader).Read"},
	{err: "io.EOF", fun: "(*strings.Reader).ReadAt"},
	{err: "io.EOF", fun: "(*strings.Reader).ReadByte"},
	{err: "io.EOF", fun: "(*strings.Reader).ReadRune"},
}

func isAllowedErrorComparison(info types.Info, binExpr *ast.BinaryExpr) bool {
	var errName string // `<package>.<name>`, e.g. `io.EOF`
	var callExpr *ast.CallExpr

	// Figure out which half of the expression is the returned error and which
	// half is the presumed error declaration.
	for _, expr := range []ast.Expr{binExpr.X, binExpr.Y} {
		switch t := expr.(type) {
		case *ast.SelectorExpr:
			// A selector which we assume refers to a staticaly declared error
			// in a package.
			errName = selectorToString(t)
		case *ast.Ident:
			// Identifier, most likely to be the `err` variable or whatever
			// produces it.
			callExpr = assigningCallExpr(info, t)
		case *ast.CallExpr:
			callExpr = t
		}
	}

	// Unimplemented or not sure, disallow the expression.
	if errName == "" || callExpr == nil {
		return false
	}

	// Find the expression that last assigned the subject identifier.
	functionSelector, ok := callExpr.Fun.(*ast.SelectorExpr)
	if !ok {
		// If the function is not a selector it is not an Std function that is
		// allowed.
		return false
	}
	var functionName string
	if sel, ok := info.Selections[functionSelector]; ok {
		functionName = fmt.Sprintf("(%s).%s", sel.Recv(), sel.Obj().Name())
	} else {
		// If there is no selection, assume it is a package.
		functionName = selectorToString(callExpr.Fun.(*ast.SelectorExpr))
	}

	for _, w := range allowedErrors {
		if w.fun == functionName && w.err == errName {
			return true
		}
	}
	return false
}

func assigningCallExpr(info types.Info, subject *ast.Ident) *ast.CallExpr {
	if subject.Obj == nil {
		return nil
	}
	switch declT := subject.Obj.Decl.(type) {
	case *ast.AssignStmt:
		// The identifier is LHS of an assignment.
		assignment := declT

		assigningExpr := assignment.Rhs[0]
		// If the assignment is comprised of multiple expressions, find out
		// which LHS expression we should use by finding its index in the LHS.
		if len(assignment.Rhs) > 1 {
			for i, lhs := range assignment.Lhs {
				if subject.Name == lhs.(*ast.Ident).Name {
					assigningExpr = assignment.Rhs[i]
					break
				}
			}
		}

		switch assignT := assigningExpr.(type) {
		case *ast.CallExpr:
			// Found the function call.
			return assignT
		case *ast.Ident:
			// The subject was the result of assigning from another identifier.
			return assigningCallExpr(info, assignT)
		}
	}
	return nil
}

func selectorToString(selExpr *ast.SelectorExpr) string {
	if ident, ok := selExpr.X.(*ast.Ident); ok {
		return ident.Name + "." + selExpr.Sel.Name
	}
	return ""
}
