package golinters

import (
	"sync"

	"github.com/ryancurrah/gomodguard"
	"golang.org/x/tools/go/analysis"

	"github.com/golangci/golangci-lint/pkg/golinters/goanalysis"
	"github.com/golangci/golangci-lint/pkg/lint/linter"
	"github.com/golangci/golangci-lint/pkg/result"
)

const (
	gomodguardName = "gomodguard"
)

// NewGomodguard returns a new Gomodguard linter.
func NewGomodguard() *goanalysis.Linter {
	var (
		issues   []goanalysis.Issue
		mu       = sync.Mutex{}
		analyzer = &analysis.Analyzer{
			Name: goanalysis.TheOnlyAnalyzerName,
			Doc:  goanalysis.TheOnlyanalyzerDoc,
		}
	)

	return goanalysis.NewLinter(
		gomodguardName,
		"Allow and block list linter for direct Go module dependencies. "+
			"This is different from depguard where there are different block "+
			"types for example version constraints and module recommendations.",
		[]*analysis.Analyzer{analyzer},
		nil,
	).WithContextSetter(func(lintCtx *linter.Context) {
		analyzer.Run = func(pass *analysis.Pass) (interface{}, error) {
			var (
				files        = []string{}
				linterCfg    = lintCtx.Cfg.LintersSettings.Gomodguard
				processorCfg = &gomodguard.Configuration{}
			)
			processorCfg.Allowed.Modules = linterCfg.Allowed.Modules
			processorCfg.Allowed.Domains = linterCfg.Allowed.Domains
			for n := range linterCfg.Blocked.Modules {
				for k, v := range linterCfg.Blocked.Modules[n] {
					m := map[string]gomodguard.BlockedModule{k: {
						Recommendations: v.Recommendations,
						Reason:          v.Reason,
					}}
					processorCfg.Blocked.Modules = append(processorCfg.Blocked.Modules, m)
					break
				}
			}

			for n := range linterCfg.Blocked.Versions {
				for k, v := range linterCfg.Blocked.Versions[n] {
					m := map[string]gomodguard.BlockedVersion{k: {
						Version: v.Version,
						Reason:  v.Reason,
					}}
					processorCfg.Blocked.Versions = append(processorCfg.Blocked.Versions, m)
					break
				}
			}

			for _, file := range pass.Files {
				files = append(files, pass.Fset.PositionFor(file.Pos(), false).Filename)
			}

			processorCfg.Blocked.LocalReplaceDirectives = linterCfg.Blocked.LocalReplaceDirectives

			processor, err := gomodguard.NewProcessor(processorCfg)
			if err != nil {
				lintCtx.Log.Warnf("running gomodguard failed: %s: if you are not using go modules "+
					"it is suggested to disable this linter", err)
				return nil, nil
			}

			gomodguardErrors := processor.ProcessFiles(files)
			if len(gomodguardErrors) == 0 {
				return nil, nil
			}

			mu.Lock()
			defer mu.Unlock()

			for _, err := range gomodguardErrors {
				issues = append(issues, goanalysis.NewIssue(&result.Issue{
					FromLinter: gomodguardName,
					Pos:        err.Position,
					Text:       err.Reason,
				}, pass))
			}

			return nil, nil
		}
	}).WithIssuesReporter(func(*linter.Context) []goanalysis.Issue {
		return issues
	}).WithLoadMode(goanalysis.LoadModeSyntax)
}
