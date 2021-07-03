package ruleguard

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/ioutil"
	"path"
	"regexp"
	"strconv"

	"github.com/quasilyte/go-ruleguard/internal/gogrep"
	"github.com/quasilyte/go-ruleguard/nodetag"
	"github.com/quasilyte/go-ruleguard/ruleguard/goutil"
	"github.com/quasilyte/go-ruleguard/ruleguard/quasigo"
	"github.com/quasilyte/go-ruleguard/ruleguard/typematch"
)

// TODO(quasilyte): use source code byte slicing instead of SprintNode?

type parseError struct{ error }

// ImportError is returned when a ruleguard file references a package that cannot be imported.
type ImportError struct {
	msg string
	err error
}

func (e *ImportError) Error() string { return e.msg }
func (e *ImportError) Unwrap() error { return e.err }

type rulesParser struct {
	state *engineState
	ctx   *ParseContext

	prefix      string // For imported packages, a prefix that is added to a rule group name
	importedPkg string // Package path; only for imported packages

	filename string
	group    string
	res      *goRuleSet
	pkg      *types.Package
	types    *types.Info

	importer *goImporter

	itab *typematch.ImportsTab

	imported []*goRuleSet

	dslPkgname string // The local name of the "ruleguard/dsl" package (usually its just "dsl")
}

type rulesParserConfig struct {
	state *engineState

	ctx *ParseContext

	importer *goImporter

	prefix      string
	importedPkg string

	itab *typematch.ImportsTab
}

func newRulesParser(config rulesParserConfig) *rulesParser {
	return &rulesParser{
		state:       config.state,
		ctx:         config.ctx,
		importer:    config.importer,
		prefix:      config.prefix,
		importedPkg: config.importedPkg,
		itab:        config.itab,
	}
}

func (p *rulesParser) ParseFile(filename string, r io.Reader) (*goRuleSet, error) {
	p.dslPkgname = "dsl"
	p.filename = filename
	p.res = &goRuleSet{
		universal: &scopedGoRuleSet{},
		groups:    make(map[string]token.Position),
	}

	parserFlags := parser.Mode(0)
	f, err := parser.ParseFile(p.ctx.Fset, filename, r, parserFlags)
	if err != nil {
		return nil, fmt.Errorf("parse file error: %w", err)
	}

	for _, imp := range f.Imports {
		importPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return nil, p.errorf(imp, fmt.Errorf("unquote %s import path: %w", imp.Path.Value, err))
		}
		if importPath == "github.com/quasilyte/go-ruleguard/dsl" {
			if imp.Name != nil {
				p.dslPkgname = imp.Name.Name
			}
		}
	}

	if f.Name.Name != "gorules" {
		return nil, fmt.Errorf("expected a gorules package name, found %s", f.Name.Name)
	}

	typechecker := types.Config{Importer: p.importer}
	p.types = &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Uses:  map[*ast.Ident]types.Object{},
		Defs:  map[*ast.Ident]types.Object{},
	}
	pkg, err := typechecker.Check("gorules", p.ctx.Fset, []*ast.File{f}, p.types)
	if err != nil {
		return nil, fmt.Errorf("typechecker error: %w", err)
	}
	p.pkg = pkg

	var matcherFuncs []*ast.FuncDecl
	var userFuncs []*ast.FuncDecl
	for _, decl := range f.Decls {
		decl, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if decl.Name.String() == "init" {
			if err := p.parseInitFunc(decl); err != nil {
				return nil, err
			}
			continue
		}

		if p.isMatcherFunc(decl) {
			matcherFuncs = append(matcherFuncs, decl)
		} else {
			userFuncs = append(userFuncs, decl)
		}
	}

	for _, decl := range userFuncs {
		if err := p.parseUserFunc(decl); err != nil {
			return nil, err
		}
	}
	for _, decl := range matcherFuncs {
		if err := p.parseRuleGroup(decl); err != nil {
			return nil, err
		}
	}

	if len(p.imported) != 0 {
		toMerge := []*goRuleSet{p.res}
		toMerge = append(toMerge, p.imported...)
		merged, err := mergeRuleSets(toMerge)
		if err != nil {
			return nil, err
		}
		p.res = merged
	}

	return p.res, nil
}

func (p *rulesParser) parseUserFunc(f *ast.FuncDecl) error {
	ctx := &quasigo.CompileContext{
		Env:   p.state.env,
		Types: p.types,
		Fset:  p.ctx.Fset,
	}
	compiled, err := quasigo.Compile(ctx, f)
	if err != nil {
		return err
	}
	if p.ctx.DebugFilter == f.Name.String() {
		p.ctx.DebugPrint(quasigo.Disasm(p.state.env, compiled))
	}
	ctx.Env.AddFunc(p.pkg.Path(), f.Name.String(), compiled)
	return nil
}

func (p *rulesParser) parseInitFunc(f *ast.FuncDecl) error {
	type bundleImport struct {
		node    ast.Node
		prefix  string
		pkgPath string
	}

	var imported []bundleImport

	for _, stmt := range f.Body.List {
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return p.errorf(stmt, errors.New("unsupported statement"))
		}
		call, ok := exprStmt.X.(*ast.CallExpr)
		if !ok {
			return p.errorf(stmt, errors.New("unsupported expr"))
		}
		fn, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return p.errorf(stmt, errors.New("unsupported call"))
		}
		pkg, ok := fn.X.(*ast.Ident)
		if !ok || pkg.Name != p.dslPkgname {
			return p.errorf(stmt, errors.New("unsupported call"))
		}

		switch fn.Sel.Name {
		case "ImportRules":
			if p.importedPkg != "" {
				return p.errorf(call, errors.New("imports from imported packages are not supported yet"))
			}
			prefix := p.parseStringArg(call.Args[0])
			bundleSelector, ok := call.Args[1].(*ast.SelectorExpr)
			if !ok {
				return p.errorf(call.Args[1], errors.New("expected a `pkgname.Bundle` argument"))
			}
			bundleObj := p.types.ObjectOf(bundleSelector.Sel)
			imported = append(imported, bundleImport{
				node:    stmt,
				prefix:  prefix,
				pkgPath: bundleObj.Pkg().Path(),
			})

		default:
			return p.errorf(stmt, fmt.Errorf("unsupported %s call", fn.Sel.Name))
		}
	}

	for _, imp := range imported {
		files, err := findBundleFiles(imp.pkgPath)
		if err != nil {
			return p.errorf(imp.node, fmt.Errorf("import lookup error: %w", err))
		}
		for _, filename := range files {
			rset, err := p.importRules(imp.prefix, imp.pkgPath, filename)
			if err != nil {
				return p.errorf(imp.node, fmt.Errorf("import parsing error: %w", err))
			}
			p.imported = append(p.imported, rset)
		}
	}

	return nil
}

func (p *rulesParser) importRules(prefix, pkgPath, filename string) (*goRuleSet, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	config := rulesParserConfig{
		state:       p.state,
		ctx:         p.ctx,
		importer:    p.importer,
		prefix:      prefix,
		importedPkg: pkgPath,
		itab:        p.itab,
	}
	rset, err := newRulesParser(config).ParseFile(filename, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.importedPkg, err)
	}
	return rset, nil
}

func (p *rulesParser) isMatcherFunc(f *ast.FuncDecl) bool {
	typ := p.types.ObjectOf(f.Name).Type().(*types.Signature)
	return typ.Results().Len() == 0 &&
		typ.Params().Len() == 1 &&
		typ.Params().At(0).Type().String() == "github.com/quasilyte/go-ruleguard/dsl.Matcher"
}

func (p *rulesParser) parseRuleGroup(f *ast.FuncDecl) (err error) {
	defer func() {
		if err != nil {
			return
		}
		rv := recover()
		if rv == nil {
			return
		}
		if parseErr, ok := rv.(parseError); ok {
			err = parseErr.error
			return
		}
		panic(rv) // not our panic
	}()

	if f.Name.String() == "_" {
		return p.errorf(f.Name, errors.New("`_` is not a valid rule group function name"))
	}
	if f.Body == nil {
		return p.errorf(f, errors.New("unexpected empty function body"))
	}
	params := f.Type.Params.List
	matcher := params[0].Names[0].Name

	p.group = f.Name.Name
	if p.prefix != "" {
		p.group = p.prefix + "/" + f.Name.Name
	}

	if p.ctx.GroupFilter != nil && !p.ctx.GroupFilter(p.group) {
		return nil // Skip this group
	}
	if _, ok := p.res.groups[p.group]; ok {
		panic(fmt.Sprintf("duplicated function %s after the typecheck", p.group)) // Should never happen
	}
	p.res.groups[p.group] = token.Position{
		Filename: p.filename,
		Line:     p.ctx.Fset.Position(f.Name.Pos()).Line,
	}

	p.itab.EnterScope()
	defer p.itab.LeaveScope()

	for _, stmt := range f.Body.List {
		if _, ok := stmt.(*ast.DeclStmt); ok {
			continue
		}
		stmtExpr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return p.errorf(stmt, fmt.Errorf("expected a %s method call, found %s", matcher, goutil.SprintNode(p.ctx.Fset, stmt)))
		}
		call, ok := stmtExpr.X.(*ast.CallExpr)
		if !ok {
			return p.errorf(stmt, fmt.Errorf("expected a %s method call, found %s", matcher, goutil.SprintNode(p.ctx.Fset, stmt)))
		}
		if err := p.parseCall(matcher, call); err != nil {
			return err
		}

	}

	return nil
}

func (p *rulesParser) parseCall(matcher string, call *ast.CallExpr) error {
	f := call.Fun.(*ast.SelectorExpr)
	x, ok := f.X.(*ast.Ident)
	if ok && x.Name == matcher {
		return p.parseStmt(f.Sel, call.Args)
	}

	return p.parseRule(matcher, call)
}

func (p *rulesParser) parseStmt(fn *ast.Ident, args []ast.Expr) error {
	switch fn.Name {
	case "Import":
		pkgPath, ok := p.toStringValue(args[0])
		if !ok {
			return p.errorf(args[0], errors.New("expected a string literal argument"))
		}
		pkgName := path.Base(pkgPath)
		p.itab.Load(pkgName, pkgPath)
		return nil
	default:
		return p.errorf(fn, fmt.Errorf("unexpected %s method", fn.Name))
	}
}

func (p *rulesParser) parseRule(matcher string, call *ast.CallExpr) error {
	origCall := call
	var (
		matchArgs        *[]ast.Expr
		matchCommentArgs *[]ast.Expr
		whereArgs        *[]ast.Expr
		suggestArgs      *[]ast.Expr
		reportArgs       *[]ast.Expr
		atArgs           *[]ast.Expr
	)
	for {
		chain, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			break
		}
		switch chain.Sel.Name {
		case "Match":
			if matchArgs != nil {
				return p.errorf(chain.Sel, errors.New("Match() can't be repeated"))
			}
			if matchCommentArgs != nil {
				return p.errorf(chain.Sel, errors.New("Match() and MatchComment() can't be combined"))
			}
			matchArgs = &call.Args
		case "MatchComment":
			if matchCommentArgs != nil {
				return p.errorf(chain.Sel, errors.New("MatchComment() can't be repeated"))
			}
			if matchArgs != nil {
				return p.errorf(chain.Sel, errors.New("Match() and MatchComment() can't be combined"))
			}
			matchCommentArgs = &call.Args
		case "Where":
			if whereArgs != nil {
				return p.errorf(chain.Sel, errors.New("Where() can't be repeated"))
			}
			whereArgs = &call.Args
		case "Suggest":
			if suggestArgs != nil {
				return p.errorf(chain.Sel, errors.New("Suggest() can't be repeated"))
			}
			suggestArgs = &call.Args
		case "Report":
			if reportArgs != nil {
				return p.errorf(chain.Sel, errors.New("Report() can't be repeated"))
			}
			reportArgs = &call.Args
		case "At":
			if atArgs != nil {
				return p.errorf(chain.Sel, errors.New("At() can't be repeated"))
			}
			atArgs = &call.Args
		default:
			return p.errorf(chain.Sel, fmt.Errorf("unexpected %s method", chain.Sel.Name))
		}
		call, ok = chain.X.(*ast.CallExpr)
		if !ok {
			break
		}
	}

	proto := goRule{
		filename: p.filename,
		line:     p.ctx.Fset.Position(origCall.Pos()).Line,
		group:    p.group,
	}

	// AST patterns for Match() or regexp patterns for MatchComment().
	var alternatives []string

	if matchArgs == nil && matchCommentArgs == nil {
		return p.errorf(origCall, errors.New("missing Match() or MatchComment() call"))
	}

	if matchArgs != nil {
		for _, arg := range *matchArgs {
			alternatives = append(alternatives, p.parseStringArg(arg))
		}
	} else {
		for _, arg := range *matchCommentArgs {
			alternatives = append(alternatives, p.parseStringArg(arg))
		}
	}

	if whereArgs != nil {
		proto.filter = p.parseFilter((*whereArgs)[0])
	}

	if suggestArgs != nil {
		proto.suggestion = p.parseStringArg((*suggestArgs)[0])
	}

	if reportArgs == nil {
		if suggestArgs == nil {
			return p.errorf(origCall, errors.New("missing Report() or Suggest() call"))
		}
		proto.msg = "suggestion: " + proto.suggestion
	} else {
		proto.msg = p.parseStringArg((*reportArgs)[0])
	}

	if atArgs != nil {
		index, ok := (*atArgs)[0].(*ast.IndexExpr)
		if !ok {
			return p.errorf((*atArgs)[0], fmt.Errorf("expected %s[`varname`] expression", matcher))
		}
		arg, ok := p.toStringValue(index.Index)
		if !ok {
			return p.errorf(index.Index, errors.New("expected a string literal index"))
		}
		proto.location = arg
	}

	if matchArgs != nil {
		return p.loadGogrepRules(proto, *matchArgs, alternatives)
	}
	return p.loadCommentRules(proto, *matchCommentArgs, alternatives)
}

func (p *rulesParser) loadCommentRules(proto goRule, matchArgs []ast.Expr, alternatives []string) error {
	dst := p.res.universal
	for i, alt := range alternatives {
		pat, err := regexp.Compile(alt)
		if err != nil {
			return p.errorf(matchArgs[i], fmt.Errorf("parse match comment pattern: %w", err))
		}
		rule := goCommentRule{
			base:          proto,
			pat:           pat,
			captureGroups: regexpHasCaptureGroups(alt),
		}
		dst.commentRules = append(dst.commentRules, rule)
	}

	return nil
}

func (p *rulesParser) loadGogrepRules(proto goRule, matchArgs []ast.Expr, alternatives []string) error {
	dst := p.res.universal
	for i, alt := range alternatives {
		rule := proto
		pat, err := gogrep.Compile(p.ctx.Fset, alt, false)
		if err != nil {
			return p.errorf(matchArgs[i], fmt.Errorf("parse match pattern: %w", err))
		}
		rule.pat = pat
		var dstTags []nodetag.Value
		switch tag := pat.NodeTag(); tag {
		case nodetag.Unknown:
			return p.errorf(matchArgs[i], fmt.Errorf("can't infer a tag of %s", alt))
		case nodetag.Node:
			// TODO: add to every bucket?
			return p.errorf(matchArgs[i], fmt.Errorf("%s is too general", alt))
		case nodetag.StmtList:
			dstTags = []nodetag.Value{
				nodetag.BlockStmt,
				nodetag.CaseClause,
				nodetag.CommClause,
			}
		case nodetag.ExprList:
			dstTags = []nodetag.Value{
				nodetag.CallExpr,
				nodetag.CompositeLit,
				nodetag.ReturnStmt,
			}
		default:
			dstTags = []nodetag.Value{tag}
		}
		for _, tag := range dstTags {
			dst.rulesByTag[tag] = append(dst.rulesByTag[tag], rule)
		}
		dst.categorizedNum++
	}

	return nil
}

func (p *rulesParser) parseFilter(root ast.Expr) matchFilter {
	return p.parseFilterExpr(root)
}

func (p *rulesParser) errorf(n ast.Node, err error) parseError {
	loc := p.ctx.Fset.Position(n.Pos())
	return parseError{fmt.Errorf("%s:%d: %w", loc.Filename, loc.Line, err)}
}

func (p *rulesParser) parseStringArg(e ast.Expr) string {
	s, ok := p.toStringValue(e)
	if !ok {
		panic(p.errorf(e, errors.New("expected a string literal argument")))
	}
	return s
}

func (p *rulesParser) parseRegexpArg(e ast.Expr) *regexp.Regexp {
	patternString, ok := p.toStringValue(e)
	if !ok {
		panic(p.errorf(e, errors.New("expected a regexp pattern argument")))
	}
	re, err := regexp.Compile(patternString)
	if err != nil {
		panic(p.errorf(e, err))
	}
	return re
}

func (p *rulesParser) parseTypeStringArg(e ast.Expr) types.Type {
	typeString, ok := p.toStringValue(e)
	if !ok {
		panic(p.errorf(e, errors.New("expected a type string argument")))
	}
	typ, err := typeFromString(typeString)
	if err != nil {
		panic(p.errorf(e, fmt.Errorf("parse type expr: %w", err)))
	}
	if typ == nil {
		panic(p.errorf(e, fmt.Errorf("can't convert %s into a type constraint yet", typeString)))
	}
	return typ
}

func (p *rulesParser) parseFilterExpr(e ast.Expr) matchFilter {
	result := matchFilter{src: goutil.SprintNode(p.ctx.Fset, e)}

	switch e := e.(type) {
	case *ast.ParenExpr:
		return p.parseFilterExpr(e.X)

	case *ast.UnaryExpr:
		x := p.parseFilterExpr(e.X)
		if e.Op == token.NOT {
			result.fn = makeNotFilter(result.src, x)
			return result
		}
		panic(p.errorf(e, fmt.Errorf("unsupported unary op: %s", result.src)))

	case *ast.BinaryExpr:
		switch e.Op {
		case token.LAND:
			result.fn = makeAndFilter(p.parseFilterExpr(e.X), p.parseFilterExpr(e.Y))
			return result
		case token.LOR:
			result.fn = makeOrFilter(p.parseFilterExpr(e.X), p.parseFilterExpr(e.Y))
			return result
		case token.GEQ, token.LEQ, token.LSS, token.GTR, token.EQL, token.NEQ:
			operand := p.toFilterOperand(e.X)
			rhs := p.toFilterOperand(e.Y)
			rhsValue := p.types.Types[e.Y].Value
			if operand.path == "Type.Size" && rhsValue != nil {
				result.fn = makeTypeSizeConstFilter(result.src, operand.varName, e.Op, rhsValue)
				return result
			}
			if operand.path == "Value.Int" && rhsValue != nil {
				result.fn = makeValueIntConstFilter(result.src, operand.varName, e.Op, rhsValue)
				return result
			}
			if operand.path == "Value.Int" && rhs.path == "Value.Int" && rhs.varName != "" {
				result.fn = makeValueIntFilter(result.src, operand.varName, e.Op, rhs.varName)
				return result
			}
			if operand.path == "Text" && rhsValue != nil {
				result.fn = makeTextConstFilter(result.src, operand.varName, e.Op, rhsValue)
				return result
			}
			if operand.path == "Text" && rhs.path == "Text" && rhs.varName != "" {
				result.fn = makeTextFilter(result.src, operand.varName, e.Op, rhs.varName)
				return result
			}
		}
		panic(p.errorf(e, fmt.Errorf("unsupported binary op: %s", result.src)))
	}

	operand := p.toFilterOperand(e)
	args := operand.args
	switch operand.path {
	default:
		panic(p.errorf(e, fmt.Errorf("unsupported expr: %s", result.src)))

	case "File.Imports":
		pkgPath := p.parseStringArg(args[0])
		result.fn = makeFileImportsFilter(result.src, pkgPath)

	case "File.PkgPath.Matches":
		re := p.parseRegexpArg(args[0])
		result.fn = makeFilePkgPathMatchesFilter(result.src, re)

	case "File.Name.Matches":
		re := p.parseRegexpArg(args[0])
		result.fn = makeFileNameMatchesFilter(result.src, re)

	case "Pure":
		result.fn = makePureFilter(result.src, operand.varName)

	case "Const":
		result.fn = makeConstFilter(result.src, operand.varName)

	case "Addressable":
		result.fn = makeAddressableFilter(result.src, operand.varName)

	case "Filter":
		expr, fn := goutil.ResolveFunc(p.types, args[0])
		if expr != nil {
			panic(p.errorf(expr, errors.New("expected a simple function name, found expression")))
		}
		sig := fn.Type().(*types.Signature)
		userFn := p.state.env.GetFunc(fn.Pkg().Path(), fn.Name())
		if userFn == nil {
			panic(p.errorf(args[0], fmt.Errorf("can't find a compiled version of %s", sig.String())))
		}
		result.fn = makeCustomVarFilter(result.src, operand.varName, userFn)

	case "Type.Is", "Type.Underlying.Is":
		// TODO(quasilyte): add FQN support?
		typeString, ok := p.toStringValue(args[0])
		if !ok {
			panic(p.errorf(args[0], errors.New("expected a string literal argument")))
		}
		ctx := typematch.Context{Itab: p.itab}
		pat, err := typematch.Parse(&ctx, typeString)
		if err != nil {
			panic(p.errorf(args[0], fmt.Errorf("parse type expr: %w", err)))
		}
		underlying := operand.path == "Type.Underlying.Is"
		result.fn = makeTypeIsFilter(result.src, operand.varName, underlying, pat)

	case "Type.ConvertibleTo":
		dstType := p.parseTypeStringArg(args[0])
		result.fn = makeTypeConvertibleToFilter(result.src, operand.varName, dstType)

	case "Type.AssignableTo":
		dstType := p.parseTypeStringArg(args[0])
		result.fn = makeTypeAssignableToFilter(result.src, operand.varName, dstType)

	case "Type.Implements":
		iface := p.toInterfaceValue(args[0])
		result.fn = makeTypeImplementsFilter(result.src, operand.varName, iface)

	case "Text.Matches":
		re := p.parseRegexpArg(args[0])
		result.fn = makeTextMatchesFilter(result.src, operand.varName, re)

	case "Node.Is":
		typeString, ok := p.toStringValue(args[0])
		if !ok {
			panic(p.errorf(args[0], errors.New("expected a string literal argument")))
		}
		tag := nodetag.FromString(typeString)
		if tag == nodetag.Unknown {
			panic(p.errorf(args[0], fmt.Errorf("%s is not a valid go/ast type name", typeString)))
		}
		result.fn = makeNodeIsFilter(result.src, operand.varName, tag)
	}

	if result.fn == nil {
		panic("bug: nil func for the filter") // Should never happen
	}
	return result
}

func (p *rulesParser) toInterfaceValue(x ast.Node) *types.Interface {
	typeString, ok := p.toStringValue(x)
	if !ok {
		panic(p.errorf(x, errors.New("expected a string literal argument")))
	}

	typ, err := p.state.FindType(p.importer, p.pkg, typeString)
	if err == nil {
		iface, ok := typ.Underlying().(*types.Interface)
		if !ok {
			panic(p.errorf(x, fmt.Errorf("%s is not an interface type", typeString)))
		}
		return iface
	}

	n, err := parser.ParseExpr(typeString)
	if err != nil {
		panic(p.errorf(x, fmt.Errorf("parse type expr: %w", err)))
	}
	qn, ok := n.(*ast.SelectorExpr)
	if !ok {
		panic(p.errorf(x, fmt.Errorf("can't resolve %s type; try a fully-qualified name", typeString)))
	}
	pkgName, ok := qn.X.(*ast.Ident)
	if !ok {
		panic(p.errorf(qn.X, errors.New("invalid package name")))
	}
	pkgPath, ok := p.itab.Lookup(pkgName.Name)
	if !ok {
		panic(p.errorf(qn.X, fmt.Errorf("package %s is not imported", pkgName.Name)))
	}
	pkg, err := p.importer.Import(pkgPath)
	if err != nil {
		panic(p.errorf(n, &ImportError{msg: fmt.Sprintf("can't load %s", pkgPath), err: err}))
	}
	obj := pkg.Scope().Lookup(qn.Sel.Name)
	if obj == nil {
		panic(p.errorf(n, fmt.Errorf("%s is not found in %s", qn.Sel.Name, pkgPath)))
	}
	iface, ok := obj.Type().Underlying().(*types.Interface)
	if !ok {
		panic(p.errorf(n, fmt.Errorf("%s is not an interface type", qn.Sel.Name)))
	}
	return iface
}

func (p *rulesParser) toStringValue(x ast.Node) (string, bool) {
	switch x := x.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case ast.Expr:
		typ, ok := p.types.Types[x]
		if !ok || typ.Type.String() != "string" {
			return "", false
		}
		str := typ.Value.ExactString()
		str = str[1 : len(str)-1] // remove quotes
		return str, true
	}
	return "", false
}

func (p *rulesParser) toFilterOperand(e ast.Expr) filterOperand {
	var o filterOperand

	if call, ok := e.(*ast.CallExpr); ok {
		o.args = call.Args
		e = call.Fun
	}
	var path string
	for {
		if call, ok := e.(*ast.CallExpr); ok {
			e = call.Fun
			continue
		}
		selector, ok := e.(*ast.SelectorExpr)
		if !ok {
			break
		}
		if path == "" {
			path = selector.Sel.Name
		} else {
			path = selector.Sel.Name + "." + path
		}
		e = selector.X
	}

	o.path = path

	indexing, ok := e.(*ast.IndexExpr)
	if !ok {
		return o
	}
	mapIdent, ok := indexing.X.(*ast.Ident)
	if !ok {
		return o
	}
	o.mapName = mapIdent.Name
	indexString, _ := p.toStringValue(indexing.Index)
	o.varName = indexString

	return o
}

type filterOperand struct {
	mapName string
	varName string
	path    string
	args    []ast.Expr
}

var stdlibPackages = map[string]string{
	"adler32":         "hash/adler32",
	"aes":             "crypto/aes",
	"ascii85":         "encoding/ascii85",
	"asn1":            "encoding/asn1",
	"ast":             "go/ast",
	"atomic":          "sync/atomic",
	"base32":          "encoding/base32",
	"base64":          "encoding/base64",
	"big":             "math/big",
	"binary":          "encoding/binary",
	"bits":            "math/bits",
	"bufio":           "bufio",
	"build":           "go/build",
	"bytes":           "bytes",
	"bzip2":           "compress/bzip2",
	"cgi":             "net/http/cgi",
	"cgo":             "runtime/cgo",
	"cipher":          "crypto/cipher",
	"cmplx":           "math/cmplx",
	"color":           "image/color",
	"constant":        "go/constant",
	"context":         "context",
	"cookiejar":       "net/http/cookiejar",
	"crc32":           "hash/crc32",
	"crc64":           "hash/crc64",
	"crypto":          "crypto",
	"csv":             "encoding/csv",
	"debug":           "runtime/debug",
	"des":             "crypto/des",
	"doc":             "go/doc",
	"draw":            "image/draw",
	"driver":          "database/sql/driver",
	"dsa":             "crypto/dsa",
	"dwarf":           "debug/dwarf",
	"ecdsa":           "crypto/ecdsa",
	"ed25519":         "crypto/ed25519",
	"elf":             "debug/elf",
	"elliptic":        "crypto/elliptic",
	"encoding":        "encoding",
	"errors":          "errors",
	"exec":            "os/exec",
	"expvar":          "expvar",
	"fcgi":            "net/http/fcgi",
	"filepath":        "path/filepath",
	"flag":            "flag",
	"flate":           "compress/flate",
	"fmt":             "fmt",
	"fnv":             "hash/fnv",
	"format":          "go/format",
	"gif":             "image/gif",
	"gob":             "encoding/gob",
	"gosym":           "debug/gosym",
	"gzip":            "compress/gzip",
	"hash":            "hash",
	"heap":            "container/heap",
	"hex":             "encoding/hex",
	"hmac":            "crypto/hmac",
	"html":            "html",
	"http":            "net/http",
	"httptest":        "net/http/httptest",
	"httptrace":       "net/http/httptrace",
	"httputil":        "net/http/httputil",
	"image":           "image",
	"importer":        "go/importer",
	"io":              "io",
	"iotest":          "testing/iotest",
	"ioutil":          "io/ioutil",
	"jpeg":            "image/jpeg",
	"json":            "encoding/json",
	"jsonrpc":         "net/rpc/jsonrpc",
	"list":            "container/list",
	"log":             "log",
	"lzw":             "compress/lzw",
	"macho":           "debug/macho",
	"mail":            "net/mail",
	"math":            "math",
	"md5":             "crypto/md5",
	"mime":            "mime",
	"multipart":       "mime/multipart",
	"net":             "net",
	"os":              "os",
	"palette":         "image/color/palette",
	"parse":           "text/template/parse",
	"parser":          "go/parser",
	"path":            "path",
	"pe":              "debug/pe",
	"pem":             "encoding/pem",
	"pkix":            "crypto/x509/pkix",
	"plan9obj":        "debug/plan9obj",
	"plugin":          "plugin",
	"png":             "image/png",
	"pprof":           "runtime/pprof",
	"printer":         "go/printer",
	"quick":           "testing/quick",
	"quotedprintable": "mime/quotedprintable",
	"race":            "runtime/race",
	"rand":            "math/rand",
	"rc4":             "crypto/rc4",
	"reflect":         "reflect",
	"regexp":          "regexp",
	"ring":            "container/ring",
	"rpc":             "net/rpc",
	"rsa":             "crypto/rsa",
	"runtime":         "runtime",
	"scanner":         "text/scanner",
	"sha1":            "crypto/sha1",
	"sha256":          "crypto/sha256",
	"sha512":          "crypto/sha512",
	"signal":          "os/signal",
	"smtp":            "net/smtp",
	"sort":            "sort",
	"sql":             "database/sql",
	"strconv":         "strconv",
	"strings":         "strings",
	"subtle":          "crypto/subtle",
	"suffixarray":     "index/suffixarray",
	"sync":            "sync",
	"syntax":          "regexp/syntax",
	"syscall":         "syscall",
	"syslog":          "log/syslog",
	"tabwriter":       "text/tabwriter",
	"tar":             "archive/tar",
	"template":        "text/template",
	"testing":         "testing",
	"textproto":       "net/textproto",
	"time":            "time",
	"tls":             "crypto/tls",
	"token":           "go/token",
	"trace":           "runtime/trace",
	"types":           "go/types",
	"unicode":         "unicode",
	"unsafe":          "unsafe",
	"url":             "net/url",
	"user":            "os/user",
	"utf16":           "unicode/utf16",
	"utf8":            "unicode/utf8",
	"x509":            "crypto/x509",
	"xml":             "encoding/xml",
	"zip":             "archive/zip",
	"zlib":            "compress/zlib",
}
