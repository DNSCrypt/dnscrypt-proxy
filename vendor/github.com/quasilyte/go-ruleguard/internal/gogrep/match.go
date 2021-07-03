package gogrep

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"

	"github.com/go-toolsmith/astequal"
)

type matcher struct {
	prog *program

	insts []instruction
	pc    int

	// node values recorded by name, excluding "_" (used only by the
	// actual matching phase)
	capture []CapturedNode
}

func newMatcher(prog *program) *matcher {
	return &matcher{
		prog:    prog,
		insts:   prog.insts,
		capture: make([]CapturedNode, 0, 8),
	}
}

func (m *matcher) nextInst() instruction {
	inst := m.insts[m.pc]
	m.pc++
	return inst
}

func (m *matcher) stringValue(inst instruction) string {
	return m.prog.strings[inst.valueIndex]
}

func (m *matcher) ifaceValue(inst instruction) interface{} {
	return m.prog.ifaces[inst.valueIndex]
}

func (m *matcher) MatchNode(n ast.Node, accept func(MatchData)) {
	m.pc = 0
	inst := m.nextInst()
	switch inst.op {
	case opMultiStmt:
		switch n := n.(type) {
		case *ast.BlockStmt:
			m.walkStmtSlice(n.List, accept)
		case *ast.CaseClause:
			m.walkStmtSlice(n.Body, accept)
		case *ast.CommClause:
			m.walkStmtSlice(n.Body, accept)
		}
	case opMultiExpr:
		switch n := n.(type) {
		case *ast.CallExpr:
			m.walkExprSlice(n.Args, accept)
		case *ast.CompositeLit:
			m.walkExprSlice(n.Elts, accept)
		case *ast.ReturnStmt:
			m.walkExprSlice(n.Results, accept)
		}
	default:
		m.capture = m.capture[:0]
		if m.matchNodeWithInst(inst, n) {
			accept(MatchData{
				Capture: m.capture,
				Node:    n,
			})
		}
	}
}

func (m *matcher) walkExprSlice(exprs []ast.Expr, accept func(MatchData)) {
	m.walkNodeSlice(exprSlice(exprs), accept)
}

func (m *matcher) walkStmtSlice(stmts []ast.Stmt, accept func(MatchData)) {
	m.walkNodeSlice(stmtSlice(stmts), accept)
}

func (m *matcher) walkNodeSlice(nodes nodeSlice, accept func(MatchData)) {
	sliceLen := nodes.len()
	from := 0
	for {
		m.pc = 1 // FIXME: this is a kludge
		m.capture = m.capture[:0]
		matched, offset := m.matchNodeList(nodes.slice(from, sliceLen), true)
		if matched == nil {
			break
		}
		accept(MatchData{
			Capture: m.capture,
			Node:    matched,
		})
		from += offset - 1
		if from >= sliceLen {
			break
		}
	}
}

func (m *matcher) matchNamed(name string, n ast.Node) bool {
	prev, ok := findNamed(m.capture, name)
	if !ok {
		// First occurrence, record value.
		m.capture = append(m.capture, CapturedNode{Name: name, Node: n})
		return true
	}
	return equalNodes(prev, n)
}

func (m *matcher) matchNodeWithInst(inst instruction, n ast.Node) bool {
	switch inst.op {
	case opNode:
		return n != nil
	case opOptNode:
		return true

	case opNamedNode:
		return n != nil && m.matchNamed(m.stringValue(inst), n)
	case opNamedOptNode:
		return m.matchNamed(m.stringValue(inst), n)

	case opBasicLit:
		n, ok := n.(*ast.BasicLit)
		return ok && m.ifaceValue(inst) == literalValue(n)

	case opStrictIntLit:
		n, ok := n.(*ast.BasicLit)
		return ok && n.Kind == token.INT && m.stringValue(inst) == n.Value
	case opStrictFloatLit:
		n, ok := n.(*ast.BasicLit)
		return ok && n.Kind == token.FLOAT && m.stringValue(inst) == n.Value
	case opStrictCharLit:
		n, ok := n.(*ast.BasicLit)
		return ok && n.Kind == token.CHAR && m.stringValue(inst) == n.Value
	case opStrictStringLit:
		n, ok := n.(*ast.BasicLit)
		return ok && n.Kind == token.STRING && m.stringValue(inst) == n.Value
	case opStrictComplexLit:
		n, ok := n.(*ast.BasicLit)
		return ok && n.Kind == token.IMAG && m.stringValue(inst) == n.Value

	case opIdent:
		n, ok := n.(*ast.Ident)
		return ok && m.stringValue(inst) == n.Name

	case opBinaryExpr:
		n, ok := n.(*ast.BinaryExpr)
		return ok && n.Op == token.Token(inst.value) &&
			m.matchNode(n.X) && m.matchNode(n.Y)

	case opUnaryExpr:
		n, ok := n.(*ast.UnaryExpr)
		return ok && n.Op == token.Token(inst.value) && m.matchNode(n.X)

	case opStarExpr:
		n, ok := n.(*ast.StarExpr)
		return ok && m.matchNode(n.X)

	case opVariadicCallExpr:
		n, ok := n.(*ast.CallExpr)
		return ok && n.Ellipsis.IsValid() && m.matchNode(n.Fun) && m.matchExprSlice(n.Args)
	case opCallExpr:
		n, ok := n.(*ast.CallExpr)
		return ok && !n.Ellipsis.IsValid() && m.matchNode(n.Fun) && m.matchExprSlice(n.Args)

	case opSimpleSelectorExpr:
		n, ok := n.(*ast.SelectorExpr)
		return ok && m.stringValue(inst) == n.Sel.Name && m.matchNode(n.X)
	case opSelectorExpr:
		n, ok := n.(*ast.SelectorExpr)
		return ok && m.matchNode(n.Sel) && m.matchNode(n.X)

	case opTypeAssertExpr:
		n, ok := n.(*ast.TypeAssertExpr)
		return ok && m.matchNode(n.X) && m.matchNode(n.Type)
	case opTypeSwitchAssertExpr:
		n, ok := n.(*ast.TypeAssertExpr)
		return ok && n.Type == nil && m.matchNode(n.X)

	case opSliceExpr:
		n, ok := n.(*ast.SliceExpr)
		return ok && n.Low == nil && n.High == nil && m.matchNode(n.X)
	case opSliceFromExpr:
		n, ok := n.(*ast.SliceExpr)
		return ok && n.Low != nil && n.High == nil && !n.Slice3 &&
			m.matchNode(n.X) && m.matchNode(n.Low)
	case opSliceToExpr:
		n, ok := n.(*ast.SliceExpr)
		return ok && n.Low == nil && n.High != nil && !n.Slice3 &&
			m.matchNode(n.X) && m.matchNode(n.High)
	case opSliceFromToExpr:
		n, ok := n.(*ast.SliceExpr)
		return ok && n.Low != nil && n.High != nil && !n.Slice3 &&
			m.matchNode(n.X) && m.matchNode(n.Low) && m.matchNode(n.High)
	case opSliceToCapExpr:
		n, ok := n.(*ast.SliceExpr)
		return ok && n.Low == nil && n.High != nil && n.Max != nil &&
			m.matchNode(n.X) && m.matchNode(n.High) && m.matchNode(n.Max)
	case opSliceFromToCapExpr:
		n, ok := n.(*ast.SliceExpr)
		return ok && n.Low != nil && n.High != nil && n.Max != nil &&
			m.matchNode(n.X) && m.matchNode(n.Low) && m.matchNode(n.High) && m.matchNode(n.Max)

	case opIndexExpr:
		n, ok := n.(*ast.IndexExpr)
		return ok && m.matchNode(n.X) && m.matchNode(n.Index)

	case opKeyValueExpr:
		n, ok := n.(*ast.KeyValueExpr)
		return ok && m.matchNode(n.Key) && m.matchNode(n.Value)

	case opParenExpr:
		n, ok := n.(*ast.ParenExpr)
		return ok && m.matchNode(n.X)

	case opEllipsis:
		n, ok := n.(*ast.Ellipsis)
		return ok && n.Elt == nil
	case opTypedEllipsis:
		n, ok := n.(*ast.Ellipsis)
		return ok && n.Elt != nil && m.matchNode(n.Elt)

	case opSliceType:
		n, ok := n.(*ast.ArrayType)
		return ok && n.Len == nil && m.matchNode(n.Elt)
	case opArrayType:
		n, ok := n.(*ast.ArrayType)
		return ok && n.Len != nil && m.matchNode(n.Len) && m.matchNode(n.Elt)
	case opMapType:
		n, ok := n.(*ast.MapType)
		return ok && m.matchNode(n.Key) && m.matchNode(n.Value)
	case opChanType:
		n, ok := n.(*ast.ChanType)
		return ok && ast.ChanDir(inst.value) == n.Dir && m.matchNode(n.Value)
	case opVoidFuncType:
		n, ok := n.(*ast.FuncType)
		return ok && n.Results == nil && m.matchNode(n.Params)
	case opFuncType:
		n, ok := n.(*ast.FuncType)
		return ok && n.Results != nil && m.matchNode(n.Params) && m.matchNode(n.Results)

	case opCompositeLit:
		n, ok := n.(*ast.CompositeLit)
		return ok && n.Type == nil && m.matchExprSlice(n.Elts)
	case opTypedCompositeLit:
		n, ok := n.(*ast.CompositeLit)
		return ok && n.Type != nil && m.matchNode(n.Type) && m.matchExprSlice(n.Elts)

	case opUnnamedField:
		n, ok := n.(*ast.Field)
		return ok && len(n.Names) == 0 && m.matchNode(n.Type)
	case opSimpleField:
		n, ok := n.(*ast.Field)
		return ok && len(n.Names) == 1 && m.stringValue(inst) == n.Names[0].Name && m.matchNode(n.Type)
	case opField:
		n, ok := n.(*ast.Field)
		return ok && len(n.Names) == 1 && m.matchNode(n.Names[0]) && m.matchNode(n.Type)
	case opMultiField:
		n, ok := n.(*ast.Field)
		return ok && len(n.Names) >= 2 && m.matchIdentSlice(n.Names) && m.matchNode(n.Type)
	case opFieldList:
		n, ok := n.(*ast.FieldList)
		return ok && m.matchFieldSlice(n.List)

	case opFuncLit:
		n, ok := n.(*ast.FuncLit)
		return ok && m.matchNode(n.Type) && m.matchNode(n.Body)

	case opAssignStmt:
		n, ok := n.(*ast.AssignStmt)
		return ok && token.Token(inst.value) == n.Tok &&
			len(n.Lhs) == 1 && m.matchNode(n.Lhs[0]) &&
			len(n.Rhs) == 1 && m.matchNode(n.Rhs[0])
	case opMultiAssignStmt:
		n, ok := n.(*ast.AssignStmt)
		return ok && token.Token(inst.value) == n.Tok &&
			m.matchExprSlice(n.Lhs) && m.matchExprSlice(n.Rhs)

	case opExprStmt:
		n, ok := n.(*ast.ExprStmt)
		return ok && m.matchNode(n.X)

	case opGoStmt:
		n, ok := n.(*ast.GoStmt)
		return ok && m.matchNode(n.Call)
	case opDeferStmt:
		n, ok := n.(*ast.DeferStmt)
		return ok && m.matchNode(n.Call)
	case opSendStmt:
		n, ok := n.(*ast.SendStmt)
		return ok && m.matchNode(n.Chan) && m.matchNode(n.Value)

	case opBlockStmt:
		n, ok := n.(*ast.BlockStmt)
		return ok && m.matchStmtSlice(n.List)

	case opIfStmt:
		n, ok := n.(*ast.IfStmt)
		return ok && n.Init == nil && n.Else == nil &&
			m.matchNode(n.Cond) && m.matchNode(n.Body)
	case opIfElseStmt:
		n, ok := n.(*ast.IfStmt)
		return ok && n.Init == nil && n.Else != nil &&
			m.matchNode(n.Cond) && m.matchNode(n.Body) && m.matchNode(n.Else)
	case opIfInitStmt:
		n, ok := n.(*ast.IfStmt)
		return ok && n.Else == nil &&
			m.matchNode(n.Init) && m.matchNode(n.Cond) && m.matchNode(n.Body)
	case opIfInitElseStmt:
		n, ok := n.(*ast.IfStmt)
		return ok && n.Else != nil &&
			m.matchNode(n.Init) && m.matchNode(n.Cond) && m.matchNode(n.Body) && m.matchNode(n.Else)

	case opIfNamedOptStmt:
		n, ok := n.(*ast.IfStmt)
		return ok && n.Else == nil && m.matchNode(n.Body) &&
			m.matchNamed(m.stringValue(inst), toStmtSlice(n.Cond, n.Init))
	case opIfNamedOptElseStmt:
		n, ok := n.(*ast.IfStmt)
		return ok && n.Else != nil && m.matchNode(n.Body) && m.matchNode(n.Else) &&
			m.matchNamed(m.stringValue(inst), toStmtSlice(n.Cond, n.Init))

	case opCaseClause:
		n, ok := n.(*ast.CaseClause)
		return ok && n.List != nil && m.matchExprSlice(n.List) && m.matchStmtSlice(n.Body)
	case opDefaultCaseClause:
		n, ok := n.(*ast.CaseClause)
		return ok && n.List == nil && m.matchStmtSlice(n.Body)

	case opSwitchStmt:
		n, ok := n.(*ast.SwitchStmt)
		return ok && n.Init == nil && n.Tag == nil && m.matchStmtSlice(n.Body.List)
	case opSwitchTagStmt:
		n, ok := n.(*ast.SwitchStmt)
		return ok && n.Init == nil && m.matchNode(n.Tag) && m.matchStmtSlice(n.Body.List)
	case opSwitchInitStmt:
		n, ok := n.(*ast.SwitchStmt)
		return ok && n.Tag == nil && m.matchNode(n.Init) && m.matchStmtSlice(n.Body.List)
	case opSwitchInitTagStmt:
		n, ok := n.(*ast.SwitchStmt)
		return ok && m.matchNode(n.Init) && m.matchNode(n.Tag) && m.matchStmtSlice(n.Body.List)

	case opTypeSwitchStmt:
		n, ok := n.(*ast.TypeSwitchStmt)
		return ok && n.Init == nil && m.matchNode(n.Assign) && m.matchStmtSlice(n.Body.List)
	case opTypeSwitchInitStmt:
		n, ok := n.(*ast.TypeSwitchStmt)
		return ok && m.matchNode(n.Init) &&
			m.matchNode(n.Assign) && m.matchStmtSlice(n.Body.List)

	case opCommClause:
		n, ok := n.(*ast.CommClause)
		return ok && n.Comm != nil && m.matchNode(n.Comm) && m.matchStmtSlice(n.Body)
	case opDefaultCommClause:
		n, ok := n.(*ast.CommClause)
		return ok && n.Comm == nil && m.matchStmtSlice(n.Body)

	case opSelectStmt:
		n, ok := n.(*ast.SelectStmt)
		return ok && m.matchStmtSlice(n.Body.List)

	case opRangeStmt:
		n, ok := n.(*ast.RangeStmt)
		return ok && n.Key == nil && n.Value == nil && m.matchNode(n.X) && m.matchNode(n.Body)
	case opRangeKeyStmt:
		n, ok := n.(*ast.RangeStmt)
		return ok && n.Key != nil && n.Value == nil && token.Token(inst.value) == n.Tok &&
			m.matchNode(n.Key) && m.matchNode(n.X) && m.matchNode(n.Body)
	case opRangeKeyValueStmt:
		n, ok := n.(*ast.RangeStmt)
		return ok && n.Key != nil && n.Value != nil && token.Token(inst.value) == n.Tok &&
			m.matchNode(n.Key) && m.matchNode(n.Value) && m.matchNode(n.X) && m.matchNode(n.Body)

	case opForStmt:
		n, ok := n.(*ast.ForStmt)
		return ok && n.Init == nil && n.Cond == nil && n.Post == nil &&
			m.matchNode(n.Body)
	case opForPostStmt:
		n, ok := n.(*ast.ForStmt)
		return ok && n.Init == nil && n.Cond == nil && n.Post != nil &&
			m.matchNode(n.Post) && m.matchNode(n.Body)
	case opForCondStmt:
		n, ok := n.(*ast.ForStmt)
		return ok && n.Init == nil && n.Cond != nil && n.Post == nil &&
			m.matchNode(n.Cond) && m.matchNode(n.Body)
	case opForCondPostStmt:
		n, ok := n.(*ast.ForStmt)
		return ok && n.Init == nil && n.Cond != nil && n.Post != nil &&
			m.matchNode(n.Cond) && m.matchNode(n.Post) && m.matchNode(n.Body)
	case opForInitStmt:
		n, ok := n.(*ast.ForStmt)
		return ok && n.Init != nil && n.Cond == nil && n.Post == nil &&
			m.matchNode(n.Init) && m.matchNode(n.Body)
	case opForInitPostStmt:
		n, ok := n.(*ast.ForStmt)
		return ok && n.Init != nil && n.Cond == nil && n.Post != nil &&
			m.matchNode(n.Init) && m.matchNode(n.Post) && m.matchNode(n.Body)
	case opForInitCondStmt:
		n, ok := n.(*ast.ForStmt)
		return ok && n.Init != nil && n.Cond != nil && n.Post == nil &&
			m.matchNode(n.Init) && m.matchNode(n.Cond) && m.matchNode(n.Body)
	case opForInitCondPostStmt:
		n, ok := n.(*ast.ForStmt)
		return ok && m.matchNode(n.Init) && m.matchNode(n.Cond) && m.matchNode(n.Post) && m.matchNode(n.Body)

	case opIncDecStmt:
		n, ok := n.(*ast.IncDecStmt)
		return ok && token.Token(inst.value) == n.Tok && m.matchNode(n.X)

	case opReturnStmt:
		n, ok := n.(*ast.ReturnStmt)
		return ok && m.matchExprSlice(n.Results)

	case opLabeledStmt:
		n, ok := n.(*ast.LabeledStmt)
		return ok && m.matchNode(n.Label) && m.matchNode(n.Stmt)
	case opSimpleLabeledStmt:
		n, ok := n.(*ast.LabeledStmt)
		return ok && m.stringValue(inst) == n.Label.Name && m.matchNode(n.Stmt)

	case opLabeledBranchStmt:
		n, ok := n.(*ast.BranchStmt)
		return ok && n.Label != nil && token.Token(inst.value) == n.Tok && m.matchNode(n.Label)
	case opSimpleLabeledBranchStmt:
		n, ok := n.(*ast.BranchStmt)
		return ok && n.Label != nil && m.stringValue(inst) == n.Label.Name && token.Token(inst.value) == n.Tok
	case opBranchStmt:
		n, ok := n.(*ast.BranchStmt)
		return ok && n.Label == nil && token.Token(inst.value) == n.Tok

	case opEmptyStmt:
		_, ok := n.(*ast.EmptyStmt)
		return ok

	case opFuncDecl:
		n, ok := n.(*ast.FuncDecl)
		return ok && n.Recv == nil && n.Body != nil &&
			m.matchNode(n.Name) && m.matchNode(n.Type) && m.matchNode(n.Body)
	case opFuncProtoDecl:
		n, ok := n.(*ast.FuncDecl)
		return ok && n.Recv == nil && n.Body == nil &&
			m.matchNode(n.Name) && m.matchNode(n.Type)
	case opMethodDecl:
		n, ok := n.(*ast.FuncDecl)
		return ok && n.Recv != nil && n.Body != nil &&
			m.matchNode(n.Recv) && m.matchNode(n.Name) && m.matchNode(n.Type) && m.matchNode(n.Body)
	case opMethodProtoDecl:
		n, ok := n.(*ast.FuncDecl)
		return ok && n.Recv != nil && n.Body == nil &&
			m.matchNode(n.Recv) && m.matchNode(n.Name) && m.matchNode(n.Type)

	case opValueInitSpec:
		n, ok := n.(*ast.ValueSpec)
		return ok && len(n.Values) != 0 && n.Type == nil &&
			m.matchIdentSlice(n.Names) && m.matchExprSlice(n.Values)
	case opTypedValueSpec:
		n, ok := n.(*ast.ValueSpec)
		return ok && len(n.Values) == 0 && n.Type != nil &&
			m.matchIdentSlice(n.Names) && m.matchNode(n.Type)
	case opTypedValueInitSpec:
		n, ok := n.(*ast.ValueSpec)
		return ok && len(n.Values) != 0 && n.Type != nil &&
			m.matchIdentSlice(n.Names) && m.matchNode(n.Type) && m.matchExprSlice(n.Values)

	case opTypeSpec:
		n, ok := n.(*ast.TypeSpec)
		return ok && !n.Assign.IsValid() && m.matchNode(n.Name) && m.matchNode(n.Type)
	case opTypeAliasSpec:
		n, ok := n.(*ast.TypeSpec)
		return ok && n.Assign.IsValid() && m.matchNode(n.Name) && m.matchNode(n.Type)

	case opConstDecl:
		n, ok := n.(*ast.GenDecl)
		return ok && n.Tok == token.CONST && m.matchSpecSlice(n.Specs)
	case opVarDecl:
		n, ok := n.(*ast.GenDecl)
		return ok && n.Tok == token.VAR && m.matchSpecSlice(n.Specs)
	case opTypeDecl:
		n, ok := n.(*ast.GenDecl)
		return ok && n.Tok == token.TYPE && m.matchSpecSlice(n.Specs)

	case opEmptyPackage:
		n, ok := n.(*ast.File)
		return ok && len(n.Imports) == 0 && len(n.Decls) == 0 && m.matchNode(n.Name)

	default:
		panic(fmt.Sprintf("unexpected op %s", inst.op))
	}
}

func (m *matcher) matchNode(n ast.Node) bool {
	return m.matchNodeWithInst(m.nextInst(), n)
}

func (m *matcher) matchStmtSlice(stmts []ast.Stmt) bool {
	matched, _ := m.matchNodeList(stmtSlice(stmts), false)
	return matched != nil
}

func (m *matcher) matchExprSlice(exprs []ast.Expr) bool {
	matched, _ := m.matchNodeList(exprSlice(exprs), false)
	return matched != nil
}

func (m *matcher) matchFieldSlice(fields []*ast.Field) bool {
	matched, _ := m.matchNodeList(fieldSlice(fields), false)
	return matched != nil
}

func (m *matcher) matchIdentSlice(idents []*ast.Ident) bool {
	matched, _ := m.matchNodeList(identSlice(idents), false)
	return matched != nil
}

func (m *matcher) matchSpecSlice(specs []ast.Spec) bool {
	matched, _ := m.matchNodeList(specSlice(specs), false)
	return matched != nil
}

// matchNodeList matches two lists of nodes. It uses a common algorithm to match
// wildcard patterns with any number of nodes without recursion.
func (m *matcher) matchNodeList(nodes nodeSlice, partial bool) (ast.Node, int) {
	sliceLen := nodes.len()
	inst := m.nextInst()
	if inst.op == opEnd {
		if sliceLen == 0 {
			return nodes, 0
		}
		return nil, -1
	}
	pcBase := m.pc
	pcNext := 0
	j := 0
	jNext := 0
	partialStart, partialEnd := 0, sliceLen

	type restart struct {
		matches   []CapturedNode
		pc        int
		j         int
		wildStart int
		wildName  string
	}
	// We need to stack these because otherwise some edge cases
	// would not match properly. Since we have various kinds of
	// wildcards (nodes containing them, $_, and $*_), in some cases
	// we may have to go back and do multiple restarts to get to the
	// right starting position.
	var stack []restart
	wildName := ""
	wildStart := 0
	push := func(next int) {
		if next > sliceLen {
			return // would be discarded anyway
		}
		pcNext = m.pc - 1
		jNext = next
		stack = append(stack, restart{m.capture, pcNext, next, wildStart, wildName})
	}
	pop := func() {
		j = jNext
		m.pc = pcNext
		m.capture = stack[len(stack)-1].matches
		wildName = stack[len(stack)-1].wildName
		wildStart = stack[len(stack)-1].wildStart
		stack = stack[:len(stack)-1]
		pcNext = 0
		jNext = 0
		if len(stack) > 0 {
			pcNext = stack[len(stack)-1].pc
			jNext = stack[len(stack)-1].j
		}
	}

	// wouldMatch returns whether the current wildcard - if any -
	// matches the nodes we are currently trying it on.
	wouldMatch := func() bool {
		switch wildName {
		case "", "_":
			return true
		}
		return m.matchNamed(wildName, nodes.slice(wildStart, j))
	}
	for ; inst.op != opEnd || j < sliceLen; inst = m.nextInst() {
		if inst.op != opEnd {
			if inst.op == opNodeSeq || inst.op == opNamedNodeSeq {
				// keep track of where this wildcard
				// started (if name == wildName,
				// we're trying the same wildcard
				// matching one more node)
				name := "_"
				if inst.op == opNamedNodeSeq {
					name = m.stringValue(inst)
				}
				if name != wildName {
					wildStart = j
					wildName = name
				}
				// try to match zero or more at j,
				// restarting at j+1 if it fails
				push(j + 1)
				continue
			}
			if partial && m.pc == pcBase {
				// let "b; c" match "a; b; c"
				// (simulates a $*_ at the beginning)
				partialStart = j
				push(j + 1)
			}
			if j < sliceLen && wouldMatch() && m.matchNodeWithInst(inst, nodes.at(j)) {
				// ordinary match
				wildName = ""
				j++
				continue
			}
		}
		if partial && inst.op == opEnd && wildName == "" {
			partialEnd = j
			break // let "b; c" match "b; c; d"
		}
		// mismatch, try to restart
		if 0 < jNext && jNext <= sliceLen && (m.pc != pcNext || j != jNext) {
			pop()
			continue
		}
		return nil, -1
	}
	if !wouldMatch() {
		return nil, -1
	}
	return nodes.slice(partialStart, partialEnd), partialEnd + 1
}

func findNamed(capture []CapturedNode, name string) (ast.Node, bool) {
	for _, c := range capture {
		if c.Name == name {
			return c.Node, true
		}
	}
	return nil, false
}

func literalValue(lit *ast.BasicLit) interface{} {
	switch lit.Kind {
	case token.INT:
		v, err := strconv.ParseInt(lit.Value, 0, 64)
		if err == nil {
			return v
		}
	case token.CHAR:
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return nil
		}
		// Return the first rune.
		for _, c := range s {
			return c
		}
	case token.STRING:
		s, err := strconv.Unquote(lit.Value)
		if err == nil {
			return s
		}
	case token.FLOAT:
		v, err := strconv.ParseFloat(lit.Value, 64)
		if err == nil {
			return v
		}
	case token.IMAG:
		v, err := strconv.ParseComplex(lit.Value, 128)
		if err == nil {
			return v
		}
	}
	return nil
}

func equalNodes(x, y ast.Node) bool {
	if x == nil || y == nil {
		return x == y
	}
	switch x := x.(type) {
	case stmtSlice:
		y, ok := y.(stmtSlice)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !astequal.Stmt(x[i], y[i]) {
				return false
			}
		}
		return true
	case exprSlice:
		y, ok := y.(exprSlice)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !astequal.Expr(x[i], y[i]) {
				return false
			}
		}
		return true
	default:
		return astequal.Node(x, y)
	}
}

func toStmtSlice(nodes ...ast.Node) stmtSlice {
	var stmts []ast.Stmt
	for _, node := range nodes {
		switch x := node.(type) {
		case nil:
		case ast.Stmt:
			stmts = append(stmts, x)
		case ast.Expr:
			stmts = append(stmts, &ast.ExprStmt{X: x})
		default:
			panic(fmt.Sprintf("unexpected node type: %T", x))
		}
	}
	return stmtSlice(stmts)
}
