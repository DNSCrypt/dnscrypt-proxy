package goutil

import (
	"go/ast"
	"go/printer"
	"go/token"
	"strings"
)

// SprintNode returns the textual representation of n.
// If fset is nil, freshly created file set will be used.
func SprintNode(fset *token.FileSet, n ast.Node) string {
	if fset == nil {
		fset = token.NewFileSet()
	}
	var buf strings.Builder
	if err := printer.Fprint(&buf, fset, n); err != nil {
		return ""
	}
	return buf.String()
}
