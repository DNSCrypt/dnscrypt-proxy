// +build go1.8

package main

import (
	"io/ioutil"
	"path/filepath"

	"golang.org/x/mod/modfile"
)

func findRootPackage(rootDirectory string) string {
	modPath := filepath.Join(rootDirectory, "go.mod")
	content, err := ioutil.ReadFile(modPath)
	if err != nil {
		return ""
	}
	return modfile.ModulePath(content)
}
