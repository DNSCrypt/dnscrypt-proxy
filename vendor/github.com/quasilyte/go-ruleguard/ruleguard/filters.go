package ruleguard

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"path/filepath"
	"regexp"

	"github.com/quasilyte/go-ruleguard/internal/xtypes"
	"github.com/quasilyte/go-ruleguard/nodetag"
	"github.com/quasilyte/go-ruleguard/ruleguard/quasigo"
	"github.com/quasilyte/go-ruleguard/ruleguard/typematch"
)

const filterSuccess = matchFilterResult("")

func filterFailure(reason string) matchFilterResult {
	return matchFilterResult(reason)
}

func makeNotFilter(src string, x matchFilter) filterFunc {
	return func(params *filterParams) matchFilterResult {
		if x.fn(params).Matched() {
			return matchFilterResult(src)
		}
		return ""
	}
}

func makeAndFilter(lhs, rhs matchFilter) filterFunc {
	return func(params *filterParams) matchFilterResult {
		if lhsResult := lhs.fn(params); !lhsResult.Matched() {
			return lhsResult
		}
		return rhs.fn(params)
	}
}

func makeOrFilter(lhs, rhs matchFilter) filterFunc {
	return func(params *filterParams) matchFilterResult {
		if lhsResult := lhs.fn(params); lhsResult.Matched() {
			return filterSuccess
		}
		return rhs.fn(params)
	}
}

func makeFileImportsFilter(src, pkgPath string) filterFunc {
	return func(params *filterParams) matchFilterResult {
		_, imported := params.imports[pkgPath]
		if imported {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeFilePkgPathMatchesFilter(src string, re *regexp.Regexp) filterFunc {
	return func(params *filterParams) matchFilterResult {
		pkgPath := params.ctx.Pkg.Path()
		if re.MatchString(pkgPath) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeFileNameMatchesFilter(src string, re *regexp.Regexp) filterFunc {
	return func(params *filterParams) matchFilterResult {
		if re.MatchString(filepath.Base(params.filename)) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makePureFilter(src, varname string) filterFunc {
	return func(params *filterParams) matchFilterResult {
		n := params.subExpr(varname)
		if isPure(params.ctx.Types, n) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeConstFilter(src, varname string) filterFunc {
	return func(params *filterParams) matchFilterResult {
		n := params.subExpr(varname)
		if isConstant(params.ctx.Types, n) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeAddressableFilter(src, varname string) filterFunc {
	return func(params *filterParams) matchFilterResult {
		n := params.subExpr(varname)
		if isAddressable(params.ctx.Types, n) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeCustomVarFilter(src, varname string, fn *quasigo.Func) filterFunc {
	return func(params *filterParams) matchFilterResult {
		// TODO(quasilyte): what if bytecode function panics due to the programming error?
		// We should probably catch the panic here, print trace and return "false"
		// from the filter (or even propagate that panic to let it crash).
		params.varname = varname
		result := quasigo.Call(params.env, fn, params)
		if result.Value().(bool) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeTypeImplementsFilter(src, varname string, iface *types.Interface) filterFunc {
	return func(params *filterParams) matchFilterResult {
		typ := params.typeofNode(params.subExpr(varname))
		if xtypes.Implements(typ, iface) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeTypeIsFilter(src, varname string, underlying bool, pat *typematch.Pattern) filterFunc {
	if underlying {
		return func(params *filterParams) matchFilterResult {
			typ := params.typeofNode(params.subExpr(varname)).Underlying()
			if pat.MatchIdentical(typ) {
				return filterSuccess
			}
			return filterFailure(src)
		}
	}
	return func(params *filterParams) matchFilterResult {
		typ := params.typeofNode(params.subExpr(varname))
		if pat.MatchIdentical(typ) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeTypeConvertibleToFilter(src, varname string, dstType types.Type) filterFunc {
	return func(params *filterParams) matchFilterResult {
		typ := params.typeofNode(params.subExpr(varname))
		if types.ConvertibleTo(typ, dstType) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeTypeAssignableToFilter(src, varname string, dstType types.Type) filterFunc {
	return func(params *filterParams) matchFilterResult {
		typ := params.typeofNode(params.subExpr(varname))
		if types.AssignableTo(typ, dstType) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeTypeSizeConstFilter(src, varname string, op token.Token, rhsValue constant.Value) filterFunc {
	return func(params *filterParams) matchFilterResult {
		typ := params.typeofNode(params.subExpr(varname))
		lhsValue := constant.MakeInt64(params.ctx.Sizes.Sizeof(typ))
		if constant.Compare(lhsValue, op, rhsValue) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeValueIntConstFilter(src, varname string, op token.Token, rhsValue constant.Value) filterFunc {
	return func(params *filterParams) matchFilterResult {
		lhsValue := intValueOf(params.ctx.Types, params.subExpr(varname))
		if lhsValue == nil {
			return filterFailure(src) // The value is unknown
		}
		if constant.Compare(lhsValue, op, rhsValue) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeValueIntFilter(src, varname string, op token.Token, rhsVarname string) filterFunc {
	return func(params *filterParams) matchFilterResult {
		lhsValue := intValueOf(params.ctx.Types, params.subExpr(varname))
		if lhsValue == nil {
			return filterFailure(src)
		}
		rhsValue := intValueOf(params.ctx.Types, params.subExpr(rhsVarname))
		if rhsValue == nil {
			return filterFailure(src)
		}
		if constant.Compare(lhsValue, op, rhsValue) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeTextConstFilter(src, varname string, op token.Token, rhsValue constant.Value) filterFunc {
	return func(params *filterParams) matchFilterResult {
		s := params.nodeText(params.subNode(varname))
		lhsValue := constant.MakeString(string(s))
		if constant.Compare(lhsValue, op, rhsValue) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeTextFilter(src, varname string, op token.Token, rhsVarname string) filterFunc {
	return func(params *filterParams) matchFilterResult {
		s1 := params.nodeText(params.subNode(varname))
		lhsValue := constant.MakeString(string(s1))
		n, _ := params.match.CapturedByName(rhsVarname)
		s2 := params.nodeText(n)
		rhsValue := constant.MakeString(string(s2))
		if constant.Compare(lhsValue, op, rhsValue) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeTextMatchesFilter(src, varname string, re *regexp.Regexp) filterFunc {
	return func(params *filterParams) matchFilterResult {
		if re.Match(params.nodeText(params.subNode(varname))) {
			return filterSuccess
		}
		return filterFailure(src)
	}
}

func makeNodeIsFilter(src, varname string, tag nodetag.Value) filterFunc {
	// TODO: add comment nodes support?
	return func(params *filterParams) matchFilterResult {
		n := params.subExpr(varname)
		var matched bool
		switch tag {
		case nodetag.Expr:
			_, matched = n.(ast.Expr)
		case nodetag.Stmt:
			_, matched = n.(ast.Stmt)
		case nodetag.Node:
			_, matched = n.(ast.Node)
		default:
			matched = (tag == nodetag.FromNode(n))
		}
		if matched {
			return filterSuccess
		}
		return filterFailure(src)
	}
}
