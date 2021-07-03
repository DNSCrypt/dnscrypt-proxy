package commentmap

import (
	"reflect"

	"github.com/gostaticanalysis/comment"
	"golang.org/x/tools/go/analysis"
)

var Analyzer = &analysis.Analyzer{
	Name:             "commentmap",
	Doc:              "create comment map",
	Run:              run,
	RunDespiteErrors: true,
	ResultType:       reflect.TypeOf(comment.Maps{}),
}

func run(pass *analysis.Pass) (interface{}, error) {
	return comment.New(pass.Fset, pass.Files), nil
}
