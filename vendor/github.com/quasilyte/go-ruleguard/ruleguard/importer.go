package ruleguard

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"runtime"

	"github.com/quasilyte/go-ruleguard/internal/golist"
)

// goImporter is a `types.Importer` that tries to load a package no matter what.
// It iterates through multiple import strategies and accepts whatever succeeds first.
type goImporter struct {
	// TODO(quasilyte): share importers with gogrep?

	state *engineState

	defaultImporter types.Importer
	srcImporter     types.Importer

	fset *token.FileSet

	debugImports bool
	debugPrint   func(string)
}

type goImporterConfig struct {
	fset         *token.FileSet
	debugImports bool
	debugPrint   func(string)
}

func newGoImporter(state *engineState, config goImporterConfig) *goImporter {
	return &goImporter{
		state:           state,
		fset:            config.fset,
		debugImports:    config.debugImports,
		debugPrint:      config.debugPrint,
		defaultImporter: importer.Default(),
		srcImporter:     importer.ForCompiler(config.fset, "source", nil),
	}
}

func (imp *goImporter) Import(path string) (*types.Package, error) {
	if pkg := imp.state.GetCachedPackage(path); pkg != nil {
		if imp.debugImports {
			imp.debugPrint(fmt.Sprintf(`imported "%s" from importer cache`, path))
		}
		return pkg, nil
	}

	pkg, err1 := imp.srcImporter.Import(path)
	if err1 == nil {
		imp.state.AddCachedPackage(path, pkg)
		if imp.debugImports {
			imp.debugPrint(fmt.Sprintf(`imported "%s" from source importer`, path))
		}
		return pkg, nil
	}

	pkg, err2 := imp.defaultImporter.Import(path)
	if err2 == nil {
		imp.state.AddCachedPackage(path, pkg)
		if imp.debugImports {
			imp.debugPrint(fmt.Sprintf(`imported "%s" from %s importer`, path, runtime.Compiler))
		}
		return pkg, nil
	}

	// Fallback to `go list` as a last resort.
	pkg, err3 := imp.golistImport(path)
	if err3 == nil {
		imp.state.AddCachedPackage(path, pkg)
		if imp.debugImports {
			imp.debugPrint(fmt.Sprintf(`imported "%s" from golist importer`, path))
		}
		return pkg, nil
	}

	if imp.debugImports {
		imp.debugPrint(fmt.Sprintf(`failed to import "%s":`, path))
		imp.debugPrint(fmt.Sprintf("  source importer: %v", err1))
		imp.debugPrint(fmt.Sprintf("  %s importer: %v", runtime.Compiler, err2))
		imp.debugPrint(fmt.Sprintf("  golist importer: %v", err3))
	}

	return nil, err2
}

func (imp *goImporter) golistImport(path string) (*types.Package, error) {
	golistPkg, err := golist.JSON(path)
	if err != nil {
		return nil, err
	}

	files := make([]*ast.File, 0, len(golistPkg.GoFiles))
	for _, filename := range golistPkg.GoFiles {
		fullname := filepath.Join(golistPkg.Dir, filename)
		f, err := parser.ParseFile(imp.fset, fullname, nil, 0)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}

	// TODO: do we want to assign imp as importer for this nested typecherker?
	// Otherwise it won't be able to resolve imports.
	var typecheker types.Config
	var info types.Info
	return typecheker.Check(path, imp.fset, files, &info)
}
