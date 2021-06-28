package main

// Much of the core of this is copied from go's cover tool itself.

// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The rest is written by Dustin Sallings

import (
	"fmt"
	"go/build"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/cover"
)

func findFile(rootPackage string, rootDir string, file string) (string, error) {
	// If we find a file that is inside the root package, we already know
	// where it should be!
	if rootPackage != "" {
		if relPath, _ := filepath.Rel(rootPackage, file); !strings.HasPrefix(relPath, "..") {
			// The file is inside the root package...
			return filepath.Join(rootDir, relPath), nil
		}
	}

	dir, file := filepath.Split(file)
	pkg, err := build.Import(dir, ".", build.FindOnly)
	if err != nil {
		return "", fmt.Errorf("can't find %q: %v", file, err)
	}
	return filepath.Join(pkg.Dir, file), nil
}

// mergeProfs merges profiles for same target packages.
// It assumes each profiles have same sorted FileName and Blocks.
func mergeProfs(pfss [][]*cover.Profile) []*cover.Profile {
	if len(pfss) == 0 {
		return nil
	}
	for len(pfss) > 1 {
		i := 0
		for ; 2*i+1 < len(pfss); i++ {
			pfss[i] = mergeTwoProfs(pfss[2*i], pfss[2*i+1])
		}
		if 2*i < len(pfss) {
			pfss[i] = pfss[2*i]
			i++
		}
		pfss = pfss[:i]
	}
	return pfss[0]
}

func mergeTwoProfs(left, right []*cover.Profile) []*cover.Profile {
	ret := make([]*cover.Profile, 0, len(left)+len(right))
	for len(left) > 0 && len(right) > 0 {
		if left[0].FileName == right[0].FileName {
			profile := &cover.Profile{
				FileName: left[0].FileName,
				Mode:     left[0].Mode,
				Blocks:   mergeTwoProfBlock(left[0].Blocks, right[0].Blocks),
			}
			ret = append(ret, profile)
			left = left[1:]
			right = right[1:]
		} else if left[0].FileName < right[0].FileName {
			ret = append(ret, left[0])
			left = left[1:]
		} else {
			ret = append(ret, right[0])
			right = right[1:]
		}
	}
	ret = append(ret, left...)
	ret = append(ret, right...)
	return ret
}

func mergeTwoProfBlock(left, right []cover.ProfileBlock) []cover.ProfileBlock {
	ret := make([]cover.ProfileBlock, 0, len(left)+len(right))
	for len(left) > 0 && len(right) > 0 {
		a, b := left[0], right[0]
		if a.StartLine == b.StartLine && a.StartCol == b.StartCol && a.EndLine == b.EndLine && a.EndCol == b.EndCol {
			ret = append(ret, cover.ProfileBlock{
				StartLine: a.StartLine,
				StartCol:  a.StartCol,
				EndLine:   a.EndLine,
				EndCol:    a.EndCol,
				NumStmt:   a.NumStmt,
				Count:     a.Count + b.Count,
			})
			left = left[1:]
			right = right[1:]
		} else if a.StartLine < b.StartLine || (a.StartLine == b.StartLine && a.StartCol < b.StartCol) {
			ret = append(ret, a)
			left = left[1:]
		} else {
			ret = append(ret, b)
			right = right[1:]
		}
	}
	ret = append(ret, left...)
	ret = append(ret, right...)
	return ret
}

// toSF converts profiles to sourcefiles for coveralls.
func toSF(profs []*cover.Profile) ([]*SourceFile, error) {
	// find root package to reduce build.Import calls when importing files from relative root
	// https://github.com/mattn/goveralls/pull/195
	rootDirectory, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get working dir: %v", err)
	}
	rootPackage := findRootPackage(rootDirectory)

	var rv []*SourceFile
	for _, prof := range profs {
		path, err := findFile(rootPackage, rootDirectory, prof.FileName)
		if err != nil {
			return nil, fmt.Errorf("cannot find file %q: %v", prof.FileName, err)
		}
		sf := &SourceFile{
			Name: getCoverallsSourceFileName(path),
		}
		lineLookup := map[int]int{}
		maxLineNo := 0
		for _, block := range prof.Blocks {
			for i := block.StartLine; i <= block.EndLine; i++ {
				lineLookup[i] += block.Count
			}
			if block.EndLine > maxLineNo {
				maxLineNo = block.EndLine
			}
		}
		sf.Coverage = make([]interface{}, maxLineNo)
		for i := 1; i <= maxLineNo; i++ {
			if c, ok := lineLookup[i]; ok {
				sf.Coverage[i-1] = c
			}
		}
		if *uploadSource {
			fb, err := ioutil.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("cannot read source of file %q: %v", path, err)
			}
			sf.Source = string(fb)
		}

		rv = append(rv, sf)
	}

	return rv, nil
}

func parseCover(fn string) ([]*SourceFile, error) {
	var pfss [][]*cover.Profile
	for _, p := range strings.Split(fn, ",") {
		profs, err := cover.ParseProfiles(p)
		if err != nil {
			return nil, fmt.Errorf("error parsing coverage: %v", err)
		}
		pfss = append(pfss, profs)
	}

	sourceFiles, err := toSF(mergeProfs(pfss))
	if err != nil {
		return nil, err
	}

	return sourceFiles, nil
}
