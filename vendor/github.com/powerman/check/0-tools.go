//go:build generate

// NOTE: Prefix 0- in this file's name ensures that `go generate ./...` processes it first.

//go:generate mkdir -p .buildcache/bin
//go:generate -command GOINSTALL env "GOBIN=$PWD/.buildcache/bin" go install
//go:generate -command INSTALL-SHELLCHECK sh -c ".buildcache/bin/shellcheck --version 2>/dev/null | grep -wq \"$DOLLAR{DOLLAR}{1}\" || curl -sSfL https://github.com/koalaman/shellcheck/releases/download/v\"$DOLLAR{DOLLAR}{1}\"/shellcheck-v\"$DOLLAR{DOLLAR}{1}\".\"$(uname)\".x86_64.tar.xz | tar xJf - -C .buildcache/bin --strip-components=1 shellcheck-v\"$DOLLAR{DOLLAR}{1}\"/shellcheck" -sh

package tools

//go:generate GOINSTALL github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0
//go:generate GOINSTALL github.com/mattn/goveralls@v0.0.12
//go:generate GOINSTALL gotest.tools/gotestsum@v1.12.0
//go:generate INSTALL-SHELLCHECK 0.10.0
