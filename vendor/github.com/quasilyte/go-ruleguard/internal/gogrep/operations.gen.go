// Code generated "gen_operations.go"; DO NOT EDIT.

package gogrep

import (
	"github.com/quasilyte/go-ruleguard/nodetag"
)

//go:generate stringer -type=operation -trimprefix=op
type operation uint8

const (
	opInvalid operation = 0

	// Tag: Node
	opNode operation = 1

	// Tag: Node
	// ValueIndex: strings | wildcard name
	opNamedNode operation = 2

	// Tag: Unknown
	opNodeSeq operation = 3

	// Tag: Unknown
	// ValueIndex: strings | wildcard name
	opNamedNodeSeq operation = 4

	// Tag: Unknown
	opOptNode operation = 5

	// Tag: Unknown
	// ValueIndex: strings | wildcard name
	opNamedOptNode operation = 6

	// Tag: StmtList
	// Args: stmts...
	// Example: f(); g()
	opMultiStmt operation = 7

	// Tag: ExprList
	// Args: exprs...
	// Example: f(), g()
	opMultiExpr operation = 8

	// Tag: Unknown
	opEnd operation = 9

	// Tag: BasicLit
	// ValueIndex: ifaces | parsed literal value
	opBasicLit operation = 10

	// Tag: BasicLit
	// ValueIndex: strings | raw literal value
	opStrictIntLit operation = 11

	// Tag: BasicLit
	// ValueIndex: strings | raw literal value
	opStrictFloatLit operation = 12

	// Tag: BasicLit
	// ValueIndex: strings | raw literal value
	opStrictCharLit operation = 13

	// Tag: BasicLit
	// ValueIndex: strings | raw literal value
	opStrictStringLit operation = 14

	// Tag: BasicLit
	// ValueIndex: strings | raw literal value
	opStrictComplexLit operation = 15

	// Tag: Ident
	// ValueIndex: strings | ident name
	opIdent operation = 16

	// Tag: IndexExpr
	// Args: x expr
	opIndexExpr operation = 17

	// Tag: SliceExpr
	// Args: x
	opSliceExpr operation = 18

	// Tag: SliceExpr
	// Args: x from
	// Example: x[from:]
	opSliceFromExpr operation = 19

	// Tag: SliceExpr
	// Args: x to
	// Example: x[:to]
	opSliceToExpr operation = 20

	// Tag: SliceExpr
	// Args: x from to
	// Example: x[from:to]
	opSliceFromToExpr operation = 21

	// Tag: SliceExpr
	// Args: x from cap
	// Example: x[:from:cap]
	opSliceToCapExpr operation = 22

	// Tag: SliceExpr
	// Args: x from to cap
	// Example: x[from:to:cap]
	opSliceFromToCapExpr operation = 23

	// Tag: FuncLit
	// Args: type block
	opFuncLit operation = 24

	// Tag: CompositeLit
	// Args: elts...
	// Example: {elts...}
	opCompositeLit operation = 25

	// Tag: CompositeLit
	// Args: typ elts...
	// Example: typ{elts...}
	opTypedCompositeLit operation = 26

	// Tag: SelectorExpr
	// Args: x
	// ValueIndex: strings | selector name
	opSimpleSelectorExpr operation = 27

	// Tag: SelectorExpr
	// Args: x sel
	opSelectorExpr operation = 28

	// Tag: TypeAssertExpr
	// Args: x typ
	opTypeAssertExpr operation = 29

	// Tag: TypeAssertExpr
	// Args: x
	opTypeSwitchAssertExpr operation = 30

	// Tag: FuncType
	// Args: params
	opVoidFuncType operation = 31

	// Tag: FuncType
	// Args: params results
	opFuncType operation = 32

	// Tag: ArrayType
	// Args: length elem
	opArrayType operation = 33

	// Tag: ArrayType
	// Args: elem
	opSliceType operation = 34

	// Tag: MapType
	// Args: key value
	opMapType operation = 35

	// Tag: ChanType
	// Args: value
	// Value: ast.ChanDir | channel direction
	opChanType operation = 36

	// Tag: KeyValueExpr
	// Args: key value
	opKeyValueExpr operation = 37

	// Tag: Ellipsis
	opEllipsis operation = 38

	// Tag: Ellipsis
	// Args: type
	opTypedEllipsis operation = 39

	// Tag: StarExpr
	// Args: x
	opStarExpr operation = 40

	// Tag: UnaryExpr
	// Args: x
	// Value: token.Token | unary operator
	opUnaryExpr operation = 41

	// Tag: BinaryExpr
	// Args: x y
	// Value: token.Token | binary operator
	opBinaryExpr operation = 42

	// Tag: ParenExpr
	// Args: x
	opParenExpr operation = 43

	// Tag: CallExpr
	// Args: fn args...
	// Example: f(1, xs...)
	opVariadicCallExpr operation = 44

	// Tag: CallExpr
	// Args: fn args...
	// Example: f(1, xs)
	opCallExpr operation = 45

	// Tag: AssignStmt
	// Args: lhs rhs
	// Example: lhs := rhs()
	// Value: token.Token | ':=' or '='
	opAssignStmt operation = 46

	// Tag: AssignStmt
	// Args: lhs... rhs...
	// Example: lhs1, lhs2 := rhs()
	// Value: token.Token | ':=' or '='
	opMultiAssignStmt operation = 47

	// Tag: BranchStmt
	// Args: x
	// Value: token.Token | branch kind
	opBranchStmt operation = 48

	// Tag: BranchStmt
	// Args: x
	// Value: token.Token | branch kind
	// ValueIndex: strings | label name
	opSimpleLabeledBranchStmt operation = 49

	// Tag: BranchStmt
	// Args: label x
	// Value: token.Token | branch kind
	opLabeledBranchStmt operation = 50

	// Tag: LabeledStmt
	// Args: x
	// ValueIndex: strings | label name
	opSimpleLabeledStmt operation = 51

	// Tag: LabeledStmt
	// Args: label x
	opLabeledStmt operation = 52

	// Tag: BlockStmt
	// Args: body...
	opBlockStmt operation = 53

	// Tag: ExprStmt
	// Args: x
	opExprStmt operation = 54

	// Tag: GoStmt
	// Args: x
	opGoStmt operation = 55

	// Tag: DeferStmt
	// Args: x
	opDeferStmt operation = 56

	// Tag: SendStmt
	// Args: ch value
	opSendStmt operation = 57

	// Tag: EmptyStmt
	opEmptyStmt operation = 58

	// Tag: IncDecStmt
	// Args: x
	// Value: token.Token | '++' or '--'
	opIncDecStmt operation = 59

	// Tag: ReturnStmt
	// Args: results...
	opReturnStmt operation = 60

	// Tag: IfStmt
	// Args: cond block
	// Example: if cond {}
	opIfStmt operation = 61

	// Tag: IfStmt
	// Args: init cond block
	// Example: if init; cond {}
	opIfInitStmt operation = 62

	// Tag: IfStmt
	// Args: cond block else
	// Example: if cond {} else ...
	opIfElseStmt operation = 63

	// Tag: IfStmt
	// Args: init cond block else
	// Example: if init; cond {} else ...
	opIfInitElseStmt operation = 64

	// Tag: IfStmt
	// Args: block
	// Example: if $*x {}
	// ValueIndex: strings | wildcard name
	opIfNamedOptStmt operation = 65

	// Tag: IfStmt
	// Args: block else
	// Example: if $*x {} else ...
	// ValueIndex: strings | wildcard name
	opIfNamedOptElseStmt operation = 66

	// Tag: SwitchStmt
	// Args: body...
	// Example: switch {}
	opSwitchStmt operation = 67

	// Tag: SwitchStmt
	// Args: tag body...
	// Example: switch tag {}
	opSwitchTagStmt operation = 68

	// Tag: SwitchStmt
	// Args: init body...
	// Example: switch init; {}
	opSwitchInitStmt operation = 69

	// Tag: SwitchStmt
	// Args: init tag body...
	// Example: switch init; tag {}
	opSwitchInitTagStmt operation = 70

	// Tag: SelectStmt
	// Args: body...
	opSelectStmt operation = 71

	// Tag: TypeSwitchStmt
	// Args: x block
	// Example: switch x.(type) {}
	opTypeSwitchStmt operation = 72

	// Tag: TypeSwitchStmt
	// Args: init x block
	// Example: switch init; x.(type) {}
	opTypeSwitchInitStmt operation = 73

	// Tag: CaseClause
	// Args: values... body...
	opCaseClause operation = 74

	// Tag: CaseClause
	// Args: body...
	opDefaultCaseClause operation = 75

	// Tag: CommClause
	// Args: comm body...
	opCommClause operation = 76

	// Tag: CommClause
	// Args: body...
	opDefaultCommClause operation = 77

	// Tag: ForStmt
	// Args: blocl
	// Example: for {}
	opForStmt operation = 78

	// Tag: ForStmt
	// Args: post block
	// Example: for ; ; post {}
	opForPostStmt operation = 79

	// Tag: ForStmt
	// Args: cond block
	// Example: for ; cond; {}
	opForCondStmt operation = 80

	// Tag: ForStmt
	// Args: cond post block
	// Example: for ; cond; post {}
	opForCondPostStmt operation = 81

	// Tag: ForStmt
	// Args: init block
	// Example: for init; ; {}
	opForInitStmt operation = 82

	// Tag: ForStmt
	// Args: init post block
	// Example: for init; ; post {}
	opForInitPostStmt operation = 83

	// Tag: ForStmt
	// Args: init cond block
	// Example: for init; cond; {}
	opForInitCondStmt operation = 84

	// Tag: ForStmt
	// Args: init cond post block
	// Example: for init; cond; post {}
	opForInitCondPostStmt operation = 85

	// Tag: RangeStmt
	// Args: x block
	// Example: for range x {}
	opRangeStmt operation = 86

	// Tag: RangeStmt
	// Args: key x block
	// Example: for key := range x {}
	// Value: token.Token | ':=' or '='
	opRangeKeyStmt operation = 87

	// Tag: RangeStmt
	// Args: key value x block
	// Example: for key, value := range x {}
	// Value: token.Token | ':=' or '='
	opRangeKeyValueStmt operation = 88

	// Tag: Unknown
	// Args: fields...
	opFieldList operation = 89

	// Tag: Unknown
	// Args: typ
	// Example: type
	opUnnamedField operation = 90

	// Tag: Unknown
	// Args: typ
	// Example: name type
	// ValueIndex: strings | field name
	opSimpleField operation = 91

	// Tag: Unknown
	// Args: name typ
	// Example: $name type
	opField operation = 92

	// Tag: Unknown
	// Args: names... typ
	// Example: name1, name2 type
	opMultiField operation = 93

	// Tag: ValueSpec
	// Args: lhs... rhs...
	// Example: lhs = rhs
	opValueInitSpec operation = 94

	// Tag: ValueSpec
	// Args: lhs... type rhs...
	// Example: lhs typ = rhs
	opTypedValueInitSpec operation = 95

	// Tag: ValueSpec
	// Args: lhs... type
	// Example: lhs typ
	opTypedValueSpec operation = 96

	// Tag: TypeSpec
	// Args: name type
	// Example: name type
	opTypeSpec operation = 97

	// Tag: TypeSpec
	// Args: name type
	// Example: name = type
	opTypeAliasSpec operation = 98

	// Tag: FuncDecl
	// Args: name type block
	opFuncDecl operation = 99

	// Tag: FuncDecl
	// Args: recv name type block
	opMethodDecl operation = 100

	// Tag: FuncDecl
	// Args: name type
	opFuncProtoDecl operation = 101

	// Tag: FuncDecl
	// Args: recv name type
	opMethodProtoDecl operation = 102

	// Tag: GenDecl
	// Args: valuespecs...
	opConstDecl operation = 103

	// Tag: GenDecl
	// Args: valuespecs...
	opVarDecl operation = 104

	// Tag: GenDecl
	// Args: typespecs...
	opTypeDecl operation = 105

	// Tag: File
	// Args: name
	opEmptyPackage operation = 106
)

type operationInfo struct {
	Tag            nodetag.Value
	NumArgs        int
	ValueKind      valueKind
	ExtraValueKind valueKind
	VariadicMap    bitmap64
}

var operationInfoTable = [256]operationInfo{
	opInvalid: {},

	opNode: {
		Tag:            nodetag.Node,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opNamedNode: {
		Tag:            nodetag.Node,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opNodeSeq: {
		Tag:            nodetag.Unknown,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opNamedNodeSeq: {
		Tag:            nodetag.Unknown,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opOptNode: {
		Tag:            nodetag.Unknown,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opNamedOptNode: {
		Tag:            nodetag.Unknown,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opMultiStmt: {
		Tag:            nodetag.StmtList,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opMultiExpr: {
		Tag:            nodetag.ExprList,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opEnd: {
		Tag:            nodetag.Unknown,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opBasicLit: {
		Tag:            nodetag.BasicLit,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: ifaceValue,
		VariadicMap:    0, // 0
	},
	opStrictIntLit: {
		Tag:            nodetag.BasicLit,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opStrictFloatLit: {
		Tag:            nodetag.BasicLit,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opStrictCharLit: {
		Tag:            nodetag.BasicLit,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opStrictStringLit: {
		Tag:            nodetag.BasicLit,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opStrictComplexLit: {
		Tag:            nodetag.BasicLit,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opIdent: {
		Tag:            nodetag.Ident,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opIndexExpr: {
		Tag:            nodetag.IndexExpr,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opSliceExpr: {
		Tag:            nodetag.SliceExpr,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opSliceFromExpr: {
		Tag:            nodetag.SliceExpr,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opSliceToExpr: {
		Tag:            nodetag.SliceExpr,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opSliceFromToExpr: {
		Tag:            nodetag.SliceExpr,
		NumArgs:        3,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opSliceToCapExpr: {
		Tag:            nodetag.SliceExpr,
		NumArgs:        3,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opSliceFromToCapExpr: {
		Tag:            nodetag.SliceExpr,
		NumArgs:        4,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opFuncLit: {
		Tag:            nodetag.FuncLit,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opCompositeLit: {
		Tag:            nodetag.CompositeLit,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opTypedCompositeLit: {
		Tag:            nodetag.CompositeLit,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    2, // 10
	},
	opSimpleSelectorExpr: {
		Tag:            nodetag.SelectorExpr,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opSelectorExpr: {
		Tag:            nodetag.SelectorExpr,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opTypeAssertExpr: {
		Tag:            nodetag.TypeAssertExpr,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opTypeSwitchAssertExpr: {
		Tag:            nodetag.TypeAssertExpr,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opVoidFuncType: {
		Tag:            nodetag.FuncType,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opFuncType: {
		Tag:            nodetag.FuncType,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opArrayType: {
		Tag:            nodetag.ArrayType,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opSliceType: {
		Tag:            nodetag.ArrayType,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opMapType: {
		Tag:            nodetag.MapType,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opChanType: {
		Tag:            nodetag.ChanType,
		NumArgs:        1,
		ValueKind:      chandirValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opKeyValueExpr: {
		Tag:            nodetag.KeyValueExpr,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opEllipsis: {
		Tag:            nodetag.Ellipsis,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opTypedEllipsis: {
		Tag:            nodetag.Ellipsis,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opStarExpr: {
		Tag:            nodetag.StarExpr,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opUnaryExpr: {
		Tag:            nodetag.UnaryExpr,
		NumArgs:        1,
		ValueKind:      tokenValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opBinaryExpr: {
		Tag:            nodetag.BinaryExpr,
		NumArgs:        2,
		ValueKind:      tokenValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opParenExpr: {
		Tag:            nodetag.ParenExpr,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opVariadicCallExpr: {
		Tag:            nodetag.CallExpr,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    2, // 10
	},
	opCallExpr: {
		Tag:            nodetag.CallExpr,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    2, // 10
	},
	opAssignStmt: {
		Tag:            nodetag.AssignStmt,
		NumArgs:        2,
		ValueKind:      tokenValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opMultiAssignStmt: {
		Tag:            nodetag.AssignStmt,
		NumArgs:        2,
		ValueKind:      tokenValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    3, // 11
	},
	opBranchStmt: {
		Tag:            nodetag.BranchStmt,
		NumArgs:        1,
		ValueKind:      tokenValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opSimpleLabeledBranchStmt: {
		Tag:            nodetag.BranchStmt,
		NumArgs:        1,
		ValueKind:      tokenValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opLabeledBranchStmt: {
		Tag:            nodetag.BranchStmt,
		NumArgs:        2,
		ValueKind:      tokenValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opSimpleLabeledStmt: {
		Tag:            nodetag.LabeledStmt,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opLabeledStmt: {
		Tag:            nodetag.LabeledStmt,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opBlockStmt: {
		Tag:            nodetag.BlockStmt,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opExprStmt: {
		Tag:            nodetag.ExprStmt,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opGoStmt: {
		Tag:            nodetag.GoStmt,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opDeferStmt: {
		Tag:            nodetag.DeferStmt,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opSendStmt: {
		Tag:            nodetag.SendStmt,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opEmptyStmt: {
		Tag:            nodetag.EmptyStmt,
		NumArgs:        0,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opIncDecStmt: {
		Tag:            nodetag.IncDecStmt,
		NumArgs:        1,
		ValueKind:      tokenValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opReturnStmt: {
		Tag:            nodetag.ReturnStmt,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opIfStmt: {
		Tag:            nodetag.IfStmt,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opIfInitStmt: {
		Tag:            nodetag.IfStmt,
		NumArgs:        3,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opIfElseStmt: {
		Tag:            nodetag.IfStmt,
		NumArgs:        3,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opIfInitElseStmt: {
		Tag:            nodetag.IfStmt,
		NumArgs:        4,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opIfNamedOptStmt: {
		Tag:            nodetag.IfStmt,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opIfNamedOptElseStmt: {
		Tag:            nodetag.IfStmt,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opSwitchStmt: {
		Tag:            nodetag.SwitchStmt,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opSwitchTagStmt: {
		Tag:            nodetag.SwitchStmt,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    2, // 10
	},
	opSwitchInitStmt: {
		Tag:            nodetag.SwitchStmt,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    2, // 10
	},
	opSwitchInitTagStmt: {
		Tag:            nodetag.SwitchStmt,
		NumArgs:        3,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    4, // 100
	},
	opSelectStmt: {
		Tag:            nodetag.SelectStmt,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opTypeSwitchStmt: {
		Tag:            nodetag.TypeSwitchStmt,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opTypeSwitchInitStmt: {
		Tag:            nodetag.TypeSwitchStmt,
		NumArgs:        3,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opCaseClause: {
		Tag:            nodetag.CaseClause,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    3, // 11
	},
	opDefaultCaseClause: {
		Tag:            nodetag.CaseClause,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opCommClause: {
		Tag:            nodetag.CommClause,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    2, // 10
	},
	opDefaultCommClause: {
		Tag:            nodetag.CommClause,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opForStmt: {
		Tag:            nodetag.ForStmt,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opForPostStmt: {
		Tag:            nodetag.ForStmt,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opForCondStmt: {
		Tag:            nodetag.ForStmt,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opForCondPostStmt: {
		Tag:            nodetag.ForStmt,
		NumArgs:        3,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opForInitStmt: {
		Tag:            nodetag.ForStmt,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opForInitPostStmt: {
		Tag:            nodetag.ForStmt,
		NumArgs:        3,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opForInitCondStmt: {
		Tag:            nodetag.ForStmt,
		NumArgs:        3,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opForInitCondPostStmt: {
		Tag:            nodetag.ForStmt,
		NumArgs:        4,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opRangeStmt: {
		Tag:            nodetag.RangeStmt,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opRangeKeyStmt: {
		Tag:            nodetag.RangeStmt,
		NumArgs:        3,
		ValueKind:      tokenValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opRangeKeyValueStmt: {
		Tag:            nodetag.RangeStmt,
		NumArgs:        4,
		ValueKind:      tokenValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opFieldList: {
		Tag:            nodetag.Unknown,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opUnnamedField: {
		Tag:            nodetag.Unknown,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opSimpleField: {
		Tag:            nodetag.Unknown,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: stringValue,
		VariadicMap:    0, // 0
	},
	opField: {
		Tag:            nodetag.Unknown,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opMultiField: {
		Tag:            nodetag.Unknown,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opValueInitSpec: {
		Tag:            nodetag.ValueSpec,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    3, // 11
	},
	opTypedValueInitSpec: {
		Tag:            nodetag.ValueSpec,
		NumArgs:        3,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    5, // 101
	},
	opTypedValueSpec: {
		Tag:            nodetag.ValueSpec,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opTypeSpec: {
		Tag:            nodetag.TypeSpec,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opTypeAliasSpec: {
		Tag:            nodetag.TypeSpec,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opFuncDecl: {
		Tag:            nodetag.FuncDecl,
		NumArgs:        3,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opMethodDecl: {
		Tag:            nodetag.FuncDecl,
		NumArgs:        4,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opFuncProtoDecl: {
		Tag:            nodetag.FuncDecl,
		NumArgs:        2,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opMethodProtoDecl: {
		Tag:            nodetag.FuncDecl,
		NumArgs:        3,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
	opConstDecl: {
		Tag:            nodetag.GenDecl,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opVarDecl: {
		Tag:            nodetag.GenDecl,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opTypeDecl: {
		Tag:            nodetag.GenDecl,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    1, // 1
	},
	opEmptyPackage: {
		Tag:            nodetag.File,
		NumArgs:        1,
		ValueKind:      emptyValue,
		ExtraValueKind: emptyValue,
		VariadicMap:    0, // 0
	},
}
