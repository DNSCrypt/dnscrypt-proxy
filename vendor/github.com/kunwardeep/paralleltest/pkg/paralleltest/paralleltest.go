package paralleltest

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const Doc = `check that tests use t.Parallel() method
It also checks that the t.Parallel is used if multiple tests cases are run as part of single test.
As part of ensuring parallel tests works as expected it checks for reinitialising of the range value
over the test cases.(https://tinyurl.com/y6555cy6)`

func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     "paralleltest",
		Doc:      Doc,
		Run:      run,
		Requires: []*analysis.Analyzer{inspect.Analyzer},
	}
}

func run(pass *analysis.Pass) (interface{}, error) {
	inspector := inspector.New(pass.Files)

	nodeFilter := []ast.Node{
		(*ast.FuncDecl)(nil),
	}

	inspector.Preorder(nodeFilter, func(node ast.Node) {
		funcDecl := node.(*ast.FuncDecl)
		var funcHasParallelMethod,
			rangeStatementOverTestCasesExists,
			rangeStatementHasParallelMethod,
			testLoopVariableReinitialised bool
		var testRunLoopIdentifier string
		var numberOfTestRun int
		var positionOfTestRunNode []ast.Node
		var rangeNode ast.Node

		// Check runs for test functions only
		if !isTestFunction(funcDecl) {
			return
		}

		for _, l := range funcDecl.Body.List {
			switch v := l.(type) {

			case *ast.ExprStmt:
				ast.Inspect(v, func(n ast.Node) bool {
					// Check if the test method is calling t.parallel
					if !funcHasParallelMethod {
						funcHasParallelMethod = methodParallelIsCalledInTestFunction(n)
					}

					// Check if the t.Run within the test function is calling t.parallel
					if methodRunIsCalledInTestFunction(n) {
						hasParallel := false
						numberOfTestRun++
						ast.Inspect(v, func(p ast.Node) bool {
							if !hasParallel {
								hasParallel = methodParallelIsCalledInTestFunction(p)
							}
							return true
						})
						if !hasParallel {
							positionOfTestRunNode = append(positionOfTestRunNode, n)
						}
					}
					return true
				})

			// Check if the range over testcases is calling t.parallel
			case *ast.RangeStmt:
				rangeNode = v

				ast.Inspect(v, func(n ast.Node) bool {
					// nolint: gocritic
					switch r := n.(type) {
					case *ast.ExprStmt:
						if methodRunIsCalledInRangeStatement(r.X) {
							rangeStatementOverTestCasesExists = true
							testRunLoopIdentifier = methodRunFirstArgumentObjectName(r.X)

							if !rangeStatementHasParallelMethod {
								rangeStatementHasParallelMethod = methodParallelIsCalledInMethodRun(r.X)
							}
						}
					}
					return true
				})

				// Check for the range loop value identifier re assignment
				// More info here https://gist.github.com/kunwardeep/80c2e9f3d3256c894898bae82d9f75d0
				if rangeStatementOverTestCasesExists {
					var rangeValueIdentifier string
					if i, ok := v.Value.(*ast.Ident); ok {
						rangeValueIdentifier = i.Name
					}

					testLoopVariableReinitialised = testCaseLoopVariableReinitialised(v.Body.List, rangeValueIdentifier, testRunLoopIdentifier)
				}
			}
		}

		if !funcHasParallelMethod {
			pass.Reportf(node.Pos(), "Function %s missing the call to method parallel\n", funcDecl.Name.Name)
		}

		if rangeStatementOverTestCasesExists && rangeNode != nil {
			if !rangeStatementHasParallelMethod {
				pass.Reportf(rangeNode.Pos(), "Range statement for test %s missing the call to method parallel in test Run\n", funcDecl.Name.Name)
			} else {
				if testRunLoopIdentifier == "" {
					pass.Reportf(rangeNode.Pos(), "Range statement for test %s does not use range value in test Run\n", funcDecl.Name.Name)
				} else if !testLoopVariableReinitialised {
					pass.Reportf(rangeNode.Pos(), "Range statement for test %s does not reinitialise the variable %s\n", funcDecl.Name.Name, testRunLoopIdentifier)
				}
			}
		}

		// Check if the t.Run is more than one as there is no point making one test parallel
		if numberOfTestRun > 1 && len(positionOfTestRunNode) > 0 {
			for _, n := range positionOfTestRunNode {
				pass.Reportf(n.Pos(), "Function %s has missing the call to method parallel in the test run\n", funcDecl.Name.Name)
			}
		}
	})

	return nil, nil
}

func testCaseLoopVariableReinitialised(statements []ast.Stmt, rangeValueIdentifier string, testRunLoopIdentifier string) bool {
	if len(statements) > 1 {
		for _, s := range statements {
			leftIdentifier, rightIdentifier := getLeftAndRightIdentifier(s)
			if leftIdentifier == testRunLoopIdentifier && rightIdentifier == rangeValueIdentifier {
				return true
			}
		}
	}
	return false
}

// Return the left hand side and the right hand side identifiers name
func getLeftAndRightIdentifier(s ast.Stmt) (string, string) {
	var leftIdentifier, rightIdentifier string
	// nolint: gocritic
	switch v := s.(type) {
	case *ast.AssignStmt:
		if len(v.Rhs) == 1 {
			if i, ok := v.Rhs[0].(*ast.Ident); ok {
				rightIdentifier = i.Name
			}
		}
		if len(v.Lhs) == 1 {
			if i, ok := v.Lhs[0].(*ast.Ident); ok {
				leftIdentifier = i.Name
			}
		}
	}
	return leftIdentifier, rightIdentifier
}

func methodParallelIsCalledInMethodRun(node ast.Node) bool {
	var methodParallelCalled bool
	// nolint: gocritic
	switch callExp := node.(type) {
	case *ast.CallExpr:
		for _, arg := range callExp.Args {
			if !methodParallelCalled {
				ast.Inspect(arg, func(n ast.Node) bool {
					if !methodParallelCalled {
						methodParallelCalled = methodParallelIsCalledInRunMethod(n)
						return true
					}
					return false
				})
			}
		}
	}
	return methodParallelCalled
}

func methodParallelIsCalledInRunMethod(node ast.Node) bool {
	return exprCallHasMethod(node, "Parallel")
}

func methodParallelIsCalledInTestFunction(node ast.Node) bool {
	return exprCallHasMethod(node, "Parallel")
}

func methodRunIsCalledInRangeStatement(node ast.Node) bool {
	return exprCallHasMethod(node, "Run")
}

func methodRunIsCalledInTestFunction(node ast.Node) bool {
	return exprCallHasMethod(node, "Run")
}
func exprCallHasMethod(node ast.Node, methodName string) bool {
	// nolint: gocritic
	switch n := node.(type) {
	case *ast.CallExpr:
		if fun, ok := n.Fun.(*ast.SelectorExpr); ok {
			return fun.Sel.Name == methodName
		}
	}
	return false
}

// Gets the object name `tc` from method t.Run(tc.Foo, func(t *testing.T)
func methodRunFirstArgumentObjectName(node ast.Node) string {
	// nolint: gocritic
	switch n := node.(type) {
	case *ast.CallExpr:
		for _, arg := range n.Args {
			if s, ok := arg.(*ast.SelectorExpr); ok {
				if i, ok := s.X.(*ast.Ident); ok {
					return i.Name
				}
			}
		}
	}
	return ""
}

// Checks if the function has the param type *testing.T)
func isTestFunction(funcDecl *ast.FuncDecl) bool {
	testMethodPackageType := "testing"
	testMethodStruct := "T"
	testPrefix := "Test"

	if !strings.HasPrefix(funcDecl.Name.Name, testPrefix) {
		return false
	}

	if funcDecl.Type.Params != nil && len(funcDecl.Type.Params.List) != 1 {
		return false
	}

	param := funcDecl.Type.Params.List[0]
	if starExp, ok := param.Type.(*ast.StarExpr); ok {
		if selectExpr, ok := starExp.X.(*ast.SelectorExpr); ok {
			if selectExpr.Sel.Name == testMethodStruct {
				if s, ok := selectExpr.X.(*ast.Ident); ok {
					return s.Name == testMethodPackageType
				}
			}
		}
	}

	return false
}
