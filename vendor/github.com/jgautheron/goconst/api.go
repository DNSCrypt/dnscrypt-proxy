package goconst

import (
	"go/ast"
	"go/token"
)

type Issue struct {
	Pos              token.Position
	OccurrencesCount int
	Str              string
	MatchingConst    string
}

type Config struct {
	MatchWithConstants bool
	MinStringLength    int
	MinOccurrences     int
	ParseNumbers       bool
	NumberMin          int
	NumberMax          int
	ExcludeTypes       map[Type]bool
}

func Run(files []*ast.File, fset *token.FileSet, cfg *Config) ([]Issue, error) {
	p := New(
		"",
		"",
		false,
		cfg.MatchWithConstants,
		cfg.ParseNumbers,
		cfg.NumberMin,
		cfg.NumberMax,
		cfg.MinStringLength,
		cfg.MinOccurrences,
		cfg.ExcludeTypes,
	)
	var issues []Issue
	for _, f := range files {
		ast.Walk(&treeVisitor{
			fileSet:     fset,
			packageName: "",
			fileName:    "",
			p:           p,
		}, f)
	}
	p.ProcessResults()

	for str, item := range p.strs {
		fi := item[0]
		i := Issue{
			Pos:              fi.Position,
			OccurrencesCount: len(item),
			Str:              str,
		}

		if len(p.consts) != 0 {
			if cst, ok := p.consts[str]; ok {
				// const should be in the same package and exported
				i.MatchingConst = cst.Name
			}
		}
		issues = append(issues, i)
	}

	return issues, nil
}
