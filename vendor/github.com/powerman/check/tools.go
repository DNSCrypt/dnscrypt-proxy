// +build tools generate

//go:generate sh -c "GOBIN=$PWD/.gobincache go install $(sed -n 's/.*_ \"\\(.*\\)\".*/\\1/p' <$GOFILE)"

package tools

import (
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "github.com/mattn/goveralls"
)
