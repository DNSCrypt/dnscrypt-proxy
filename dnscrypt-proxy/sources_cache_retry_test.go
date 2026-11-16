package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSourceCacheRetriesUnchangedContent(t *testing.T) {
	bin := readFixture(t, "sources/minimal_relay.md")
	sig := readFixture(t, "sources/minimal_relay.md.minisig")
	dir := filepath.Join(t.TempDir(), "missing")
	source := &Source{cacheFile: filepath.Join(dir, "resolvers.md")}

	source.updateCache(bin, sig)
	if !bytes.Equal(source.bin, bin) {
		t.Fatal("failed cache write discarded the accepted source")
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	source.updateCache(bin, sig)
	for _, file := range []struct {
		path string
		want []byte
	}{
		{source.cacheFile, bin},
		{source.cacheFile + ".minisig", sig},
	} {
		got, err := os.ReadFile(file.path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, file.want) {
			t.Fatalf("unexpected cache content in %s", file.path)
		}
	}
}

func TestSourceCachePreservesUnchangedFiles(t *testing.T) {
	bin := readFixture(t, "sources/minimal_relay.md")
	sig := readFixture(t, "sources/minimal_relay.md.minisig")
	source := &Source{cacheFile: filepath.Join(t.TempDir(), "resolvers.md")}
	source.updateCache(bin, sig)
	paths := []string{source.cacheFile, source.cacheFile + ".minisig"}
	before := make([]os.FileInfo, len(paths))
	for i, path := range paths {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		var err error
		before[i], err = os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	source.updateCache(bin, sig)
	for i, path := range paths {
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before[i], after) || after.Mode().Perm() != 0o600 {
			t.Fatalf("unchanged cache file replaced: %s", path)
		}
	}
}

func TestSourceCacheRepairsUnchangedContent(t *testing.T) {
	bin := readFixture(t, "sources/minimal_relay.md")
	sig := readFixture(t, "sources/minimal_relay.md.minisig")
	for _, tt := range []struct {
		name     string
		bin, sig []byte
	}{
		{"missing-data", nil, sig},
		{"missing-signature", bin, nil},
		{"invalid-data", []byte("invalid"), sig},
		{"invalid-signature", bin, []byte("invalid")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := &Source{cacheFile: filepath.Join(t.TempDir(), "resolvers.md"), bin: bin}
			for _, file := range []struct {
				path string
				data []byte
			}{
				{source.cacheFile, tt.bin},
				{source.cacheFile + ".minisig", tt.sig},
			} {
				if file.data != nil {
					if err := os.WriteFile(file.path, file.data, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			source.updateCache(bin, sig)
			for _, file := range []struct {
				path string
				want []byte
			}{
				{source.cacheFile, bin},
				{source.cacheFile + ".minisig", sig},
			} {
				got, err := os.ReadFile(file.path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, file.want) {
					t.Fatalf("cache pair not repaired: %s", file.path)
				}
			}
		})
	}
}
