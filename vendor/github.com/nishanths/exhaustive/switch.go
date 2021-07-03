package exhaustive

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"go/types"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/ast/inspector"
)

func isDefaultCase(c *ast.CaseClause) bool {
	return c.List == nil // see doc comment on field
}

func checkSwitchStatements(
	pass *analysis.Pass,
	inspect *inspector.Inspector,
	comments map[*ast.File]ast.CommentMap,
	generated map[*ast.File]bool,
) {
	inspect.WithStack([]ast.Node{&ast.SwitchStmt{}}, func(n ast.Node, push bool, stack []ast.Node) bool {
		if !push {
			return true
		}

		file := stack[0].(*ast.File)

		// Determine if file is a generated file, based on https://golang.org/s/generatedcode.
		// If generated, don't check this file.
		var isGenerated bool
		if gen, ok := generated[file]; ok {
			isGenerated = gen
		} else {
			isGenerated = isGeneratedFile(file)
			generated[file] = isGenerated
		}
		if isGenerated && !fCheckGeneratedFiles {
			// don't check
			return true
		}

		sw := n.(*ast.SwitchStmt)
		if sw.Tag == nil {
			return true
		}
		t := pass.TypesInfo.Types[sw.Tag]
		if !t.IsValue() {
			return true
		}
		tagType, ok := t.Type.(*types.Named)
		if !ok {
			return true
		}

		tagPkg := tagType.Obj().Pkg()
		if tagPkg == nil {
			// Doc comment: nil for labels and objects in the Universe scope.
			// This happens for the `error` type, for example.
			// Continuing would mean that ImportPackageFact panics.
			return true
		}

		var enums enumsFact
		if !pass.ImportPackageFact(tagPkg, &enums) {
			// Can't do anything further.
			return true
		}

		em, isEnum := enums.Enums[tagType.Obj().Name()]
		if !isEnum {
			// Tag's type is not a known enum.
			return true
		}

		// Get comment map.
		var allComments ast.CommentMap
		if cm, ok := comments[file]; ok {
			allComments = cm
		} else {
			allComments = ast.NewCommentMap(pass.Fset, file, file.Comments)
			comments[file] = allComments
		}

		specificComments := allComments.Filter(sw)
		for _, group := range specificComments.Comments() {
			if containsIgnoreDirective(group.List) {
				return true // skip checking due to ignore directive
			}
		}

		samePkg := tagPkg == pass.Pkg
		checkUnexported := samePkg

		hitlist := hitlistFromEnumMembers(em, checkUnexported)
		if len(hitlist) == 0 {
			// can happen if external package and enum consists only of
			// unexported members
			return true
		}

		defaultCaseExists := false
		for _, stmt := range sw.Body.List {
			caseCl := stmt.(*ast.CaseClause)
			if isDefaultCase(caseCl) {
				defaultCaseExists = true
				continue // nothing more to do if it's the default case
			}
			for _, e := range caseCl.List {
				e = astutil.Unparen(e)
				if samePkg {
					ident, ok := e.(*ast.Ident)
					if !ok {
						continue
					}
					updateHitlist(hitlist, em, ident.Name)
				} else {
					selExpr, ok := e.(*ast.SelectorExpr)
					if !ok {
						continue
					}

					// ensure X is package identifier
					ident, ok := selExpr.X.(*ast.Ident)
					if !ok {
						continue
					}
					if !isPackageNameIdentifier(pass, ident) {
						continue
					}

					updateHitlist(hitlist, em, selExpr.Sel.Name)
				}
			}
		}

		defaultSuffices := fDefaultSignifiesExhaustive && defaultCaseExists
		shouldReport := len(hitlist) > 0 && !defaultSuffices

		if shouldReport {
			reportSwitch(pass, sw, samePkg, tagType, em, hitlist, defaultCaseExists, file)
		}
		return true
	})
}

func updateHitlist(hitlist map[string]struct{}, em *enumMembers, foundName string) {
	constVal, ok := em.NameToValue[foundName]
	if !ok {
		// only delete the name alone from hitlist
		delete(hitlist, foundName)
		return
	}

	// delete all of the same-valued names from hitlist
	namesToDelete := em.ValueToNames[constVal]
	for _, n := range namesToDelete {
		delete(hitlist, n)
	}
}

func isPackageNameIdentifier(pass *analysis.Pass, ident *ast.Ident) bool {
	obj := pass.TypesInfo.ObjectOf(ident)
	if obj == nil {
		return false
	}
	_, ok := obj.(*types.PkgName)
	return ok
}

func hitlistFromEnumMembers(em *enumMembers, checkUnexported bool) map[string]struct{} {
	hitlist := make(map[string]struct{})
	for _, m := range em.OrderedNames {
		if m == "_" {
			// blank identifier is often used to skip entries in iota lists
			continue
		}
		if !ast.IsExported(m) && !checkUnexported {
			continue
		}
		hitlist[m] = struct{}{}
	}
	return hitlist
}

func determineMissingOutput(missingMembers map[string]struct{}, em *enumMembers) []string {
	constValMembers := make(map[string][]string) // value -> names
	var otherMembers []string                    // non-constant value names

	for m := range missingMembers {
		if constVal, ok := em.NameToValue[m]; ok {
			constValMembers[constVal] = append(constValMembers[constVal], m)
		} else {
			otherMembers = append(otherMembers, m)
		}
	}

	missingOutput := make([]string, 0, len(constValMembers)+len(otherMembers))
	for _, names := range constValMembers {
		sort.Strings(names)
		missingOutput = append(missingOutput, strings.Join(names, "|"))
	}
	missingOutput = append(missingOutput, otherMembers...)
	sort.Strings(missingOutput)
	return missingOutput
}

func reportSwitch(
	pass *analysis.Pass,
	sw *ast.SwitchStmt,
	samePkg bool,
	enumType *types.Named,
	em *enumMembers,
	missingMembers map[string]struct{},
	defaultCaseExists bool,
	f *ast.File,
) {
	missingOutput := determineMissingOutput(missingMembers, em)

	var fixes []analysis.SuggestedFix
	if !defaultCaseExists {
		if fix, ok := computeFix(pass, pass.Fset, f, sw, enumType, samePkg, missingMembers); ok {
			fixes = append(fixes, fix)
		}
	}

	pass.Report(analysis.Diagnostic{
		Pos:            sw.Pos(),
		End:            sw.End(),
		Message:        fmt.Sprintf("missing cases in switch of type %s: %s", enumTypeName(enumType, samePkg), strings.Join(missingOutput, ", ")),
		SuggestedFixes: fixes,
	})
}

func computeFix(pass *analysis.Pass, fset *token.FileSet, f *ast.File, sw *ast.SwitchStmt, enumType *types.Named, samePkg bool, missingMembers map[string]struct{}) (analysis.SuggestedFix, bool) {
	// Function and method calls may be mutative, so we don't want to reuse the
	// call expression in the about-to-be-inserted case clause body. So we just
	// don't suggest a fix in such situations.
	//
	// However, we need to make an exception for type conversions, which are
	// also call expressions in the AST.
	//
	// We'll need to lookup type information for this, and can't rely solely
	// on the AST.
	if containsFuncCall(pass, sw.Tag) {
		return analysis.SuggestedFix{}, false
	}

	textEdits := []analysis.TextEdit{
		missingCasesTextEdit(fset, f, samePkg, sw, enumType, missingMembers),
	}

	// need to add "fmt" import if "fmt" import doesn't already exist
	if !hasImportWithPath(fset, f, `"fmt"`) {
		textEdits = append(textEdits, fmtImportTextEdit(fset, f))
	}

	missing := make([]string, 0, len(missingMembers))
	for m := range missingMembers {
		missing = append(missing, m)
	}
	sort.Strings(missing)

	return analysis.SuggestedFix{
		Message:   fmt.Sprintf("add case clause for: %s?", strings.Join(missing, ", ")),
		TextEdits: textEdits,
	}, true
}

func containsFuncCall(pass *analysis.Pass, e ast.Expr) bool {
	e = astutil.Unparen(e)
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	if _, isFunc := pass.TypesInfo.TypeOf(c.Fun).Underlying().(*types.Signature); isFunc {
		return true
	}
	for _, a := range c.Args {
		if containsFuncCall(pass, a) {
			return true
		}
	}
	return false
}

func firstImportDecl(fset *token.FileSet, f *ast.File) *ast.GenDecl {
	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if ok && genDecl.Tok == token.IMPORT {
			// first IMPORT GenDecl
			return genDecl
		}
	}
	return nil
}

// copies an GenDecl in a manner such that appending to the returned GenDecl's Specs field
// doesn't mutate the original GenDecl
func copyGenDecl(im *ast.GenDecl) *ast.GenDecl {
	imCopy := *im
	imCopy.Specs = make([]ast.Spec, len(im.Specs))
	for i := range im.Specs {
		imCopy.Specs[i] = im.Specs[i]
	}
	return &imCopy
}

func hasImportWithPath(fset *token.FileSet, f *ast.File, pathLiteral string) bool {
	igroups := astutil.Imports(fset, f)
	for _, igroup := range igroups {
		for _, importSpec := range igroup {
			if importSpec.Path.Value == pathLiteral {
				return true
			}
		}
	}
	return false
}

func fmtImportTextEdit(fset *token.FileSet, f *ast.File) analysis.TextEdit {
	firstDecl := firstImportDecl(fset, f)

	if firstDecl == nil {
		// file has no import declarations
		// insert "fmt" import spec after package statement
		return analysis.TextEdit{
			Pos: f.Name.End() + 1, // end of package name + 1
			End: f.Name.End() + 1,
			NewText: []byte(`import (
				"fmt"
			)`),
		}
	}

	// copy because we'll be mutating its Specs field
	firstDeclCopy := copyGenDecl(firstDecl)

	// find insertion index for "fmt" import spec
	var i int
	for ; i < len(firstDeclCopy.Specs); i++ {
		im := firstDeclCopy.Specs[i].(*ast.ImportSpec)
		if v, _ := strconv.Unquote(im.Path.Value); v > "fmt" {
			break
		}
	}

	// insert "fmt" import spec at the index
	fmtSpec := &ast.ImportSpec{
		Path: &ast.BasicLit{
			// NOTE: Pos field doesn't seem to be required for our
			// purposes here.
			Kind:  token.STRING,
			Value: `"fmt"`,
		},
	}
	s := firstDeclCopy.Specs // local var for easier comprehension of next line
	s = append(s[:i], append([]ast.Spec{fmtSpec}, s[i:]...)...)
	firstDeclCopy.Specs = s

	// create the text edit
	var buf bytes.Buffer
	printer.Fprint(&buf, fset, firstDeclCopy)

	return analysis.TextEdit{
		Pos:     firstDecl.Pos(),
		End:     firstDecl.End(),
		NewText: buf.Bytes(),
	}
}

func missingCasesTextEdit(fset *token.FileSet, f *ast.File, samePkg bool, sw *ast.SwitchStmt, enumType *types.Named, missingMembers map[string]struct{}) analysis.TextEdit {
	// ... Construct insertion text for case clause and its body ...

	var tag bytes.Buffer
	printer.Fprint(&tag, fset, sw.Tag)

	// If possible and if necessary, determine the package identifier based on the AST of other `case` clauses.
	var pkgIdent *ast.Ident
	if !samePkg {
		for _, stmt := range sw.Body.List {
			caseCl := stmt.(*ast.CaseClause)
			// At least one expression must exist in List at this point.
			// List cannot be nil because we only arrive here if the "default" clause
			// does not exist. Additionally, a syntactically valid case clause must
			// have at least one expression.
			if sel, ok := caseCl.List[0].(*ast.SelectorExpr); ok {
				pkgIdent = sel.X.(*ast.Ident)
				break
			}
		}
	}

	missing := make([]string, 0, len(missingMembers))
	for m := range missingMembers {
		if !samePkg {
			if pkgIdent != nil {
				// we were able to determine package identifier
				missing = append(missing, pkgIdent.Name+"."+m)
			} else {
				// use the package name (may not be correct always)
				//
				// TODO: May need to also add import if the package isn't imported
				// elsewhere. This (ie, a switch with zero case clauses) should
				// happen rarely, so don't implement this for now.
				missing = append(missing, enumType.Obj().Pkg().Name()+"."+m)
			}
		} else {
			missing = append(missing, m)
		}
	}
	sort.Strings(missing)

	insert := `case ` + strings.Join(missing, ", ") + `:
	panic(fmt.Sprintf("unhandled value: %v",` + tag.String() + `))`

	// ... Create the text edit ...

	return analysis.TextEdit{
		Pos:     sw.Body.Rbrace - 1,
		End:     sw.Body.Rbrace - 1,
		NewText: []byte(insert),
	}
}
