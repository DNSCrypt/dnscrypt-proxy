package checkers

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/token"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-critic/go-critic/framework/linter"
	"github.com/quasilyte/go-ruleguard/ruleguard"
)

func init() {
	var info linter.CheckerInfo
	info.Name = "ruleguard"
	info.Tags = []string{"style", "experimental"}
	info.Params = linter.CheckerParams{
		"rules": {
			Value: "",
			Usage: "comma-separated list of gorule file paths. Glob patterns such as 'rules-*.go' may be specified",
		},
		"debug": {
			Value: "",
			Usage: "enable debug for the specified named rules group",
		},
		"failOnError": {
			Value: false,
			Usage: "If true, panic when the gorule files contain a syntax error. If false, log and skip rules that contain an error",
		},
	}
	info.Summary = "Runs user-defined rules using ruleguard linter"
	info.Details = "Reads a rules file and turns them into go-critic checkers."
	info.Before = `N/A`
	info.After = `N/A`
	info.Note = "See https://github.com/quasilyte/go-ruleguard."

	collection.AddChecker(&info, func(ctx *linter.CheckerContext) (linter.FileWalker, error) {
		return newRuleguardChecker(&info, ctx)
	})
}

func newRuleguardChecker(info *linter.CheckerInfo, ctx *linter.CheckerContext) (*ruleguardChecker, error) {
	c := &ruleguardChecker{
		ctx:        ctx,
		debugGroup: info.Params.String("debug"),
	}
	rulesFlag := info.Params.String("rules")
	if rulesFlag == "" {
		return c, nil
	}
	failOnErrorFlag := info.Params.Bool("failOnError")

	// TODO(quasilyte): handle initialization errors better when we make
	// a transition to the go/analysis framework.
	//
	// For now, we log error messages and return a ruleguard checker
	// with an empty rules set.

	engine := ruleguard.NewEngine()
	fset := token.NewFileSet()
	filePatterns := strings.Split(rulesFlag, ",")

	parseContext := &ruleguard.ParseContext{
		Fset: fset,
	}

	loaded := 0
	for _, filePattern := range filePatterns {
		filenames, err := filepath.Glob(strings.TrimSpace(filePattern))
		if err != nil {
			// The only possible returned error is ErrBadPattern, when pattern is malformed.
			log.Printf("ruleguard init error: %+v", err)
			continue
		}
		for _, filename := range filenames {
			data, err := ioutil.ReadFile(filename)
			if err != nil {
				if failOnErrorFlag {
					return nil, fmt.Errorf("ruleguard init error: %+v", err)
				}
				log.Printf("ruleguard init error: %+v", err)
				continue
			}
			if err := engine.Load(parseContext, filename, bytes.NewReader(data)); err != nil {
				if failOnErrorFlag {
					return nil, fmt.Errorf("ruleguard init error: %+v", err)
				}
				log.Printf("ruleguard init error: %+v", err)
				continue
			}
			loaded++
		}
	}

	if loaded != 0 {
		c.engine = engine
	}
	return c, nil
}

type ruleguardChecker struct {
	ctx *linter.CheckerContext

	debugGroup string
	engine     *ruleguard.Engine
}

func (c *ruleguardChecker) WalkFile(f *ast.File) {
	if c.engine == nil {
		return
	}

	type ruleguardReport struct {
		node    ast.Node
		message string
	}
	var reports []ruleguardReport

	ctx := &ruleguard.RunContext{
		Debug: c.debugGroup,
		DebugPrint: func(s string) {
			fmt.Fprintln(os.Stderr, s)
		},
		Pkg:   c.ctx.Pkg,
		Types: c.ctx.TypesInfo,
		Sizes: c.ctx.SizesInfo,
		Fset:  c.ctx.FileSet,
		Report: func(_ ruleguard.GoRuleInfo, n ast.Node, msg string, _ *ruleguard.Suggestion) {
			// TODO(quasilyte): investigate whether we should add a rule name as
			// a message prefix here.
			reports = append(reports, ruleguardReport{
				node:    n,
				message: msg,
			})
		},
	}

	if err := c.engine.Run(ctx, f); err != nil {
		// Normally this should never happen, but since
		// we don't have a better mechanism to report errors,
		// emit a warning.
		c.ctx.Warn(f, "execution error: %v", err)
	}

	sort.Slice(reports, func(i, j int) bool {
		return reports[i].message < reports[j].message
	})
	for _, report := range reports {
		c.ctx.Warn(report.node, report.message)
	}
}
