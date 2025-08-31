package main

import (
	"fmt"
	"go/token"
	"go/types"
	"os"

	"go.uber.org/mock/mockgen/model"

	"golang.org/x/tools/go/gcexportdata"
)

func archiveMode(importPath string, symbols []string, archive string) (*model.Package, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := gcexportdata.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("read export data %q: %v", archive, err)
	}

	fset := token.NewFileSet()
	imports := make(map[string]*types.Package)
	tp, err := gcexportdata.Read(r, fset, imports, importPath)
	if err != nil {
		return nil, err
	}

	pkg := &model.Package{
		Name:       tp.Name(),
		PkgPath:    tp.Path(),
		Interfaces: make([]*model.Interface, 0, len(symbols)),
	}
	for _, name := range symbols {
		m := tp.Scope().Lookup(name)
		tn, ok := m.(*types.TypeName)
		if !ok {
			continue
		}
		ti, ok := tn.Type().Underlying().(*types.Interface)
		if !ok {
			continue
		}
		it, err := model.InterfaceFromGoTypesType(ti)
		if err != nil {
			return nil, err
		}
		it.Name = m.Name()
		pkg.Interfaces = append(pkg.Interfaces, it)
	}
	return pkg, nil
}
