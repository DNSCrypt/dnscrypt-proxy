# check [![GoDoc](https://godoc.org/github.com/powerman/check?status.svg)](http://godoc.org/github.com/powerman/check) [![Go Report Card](https://goreportcard.com/badge/github.com/powerman/check)](https://goreportcard.com/report/github.com/powerman/check) [![CircleCI](https://circleci.com/gh/powerman/check.svg?style=svg)](https://circleci.com/gh/powerman/check) [![Coverage Status](https://coveralls.io/repos/github/powerman/check/badge.svg?branch=master)](https://coveralls.io/github/powerman/check?branch=master)

Helpers to complement Go [testing](https://golang.org/pkg/testing/)
package.

Write tests with ease and fun!

This package is like
[testify/assert](https://godoc.org/github.com/test-go/testify/assert)
on steroids. :)

## Features

- Compelling output from failed tests:
    - Very easy-to-read dumps for expected and actual values.
    - Same text diff you loved in testify/assert.
    - Also visual diff in [GoConvey](http://goconvey.co/) web UI, if you
      use it (recommended).
- Statistics with amount of passed/failed checks.
- Colored output in terminal.
- 100% compatible with testing package - check package just provide
  convenient wrappers for `*testing.T` methods and doesn't introduce new
  concepts like BDD, custom test suite or unusual execution flow.
- All checks you may ever need! :)
- Very easy to add your own check functions.
- Concise, handy and consistent API, without dot-import!

## Quickstart

Just wrap each (including subtests) `*testing.T` using `check.T()` and write
tests as usually with testing package. Call new methods provided by this
package to have more clean/concise test code and cool dump/diff.

```go
import "github.com/powerman/check"

func TestSomething(tt *testing.T) {
	t := check.T(tt)
	t.Equal(2, 2)
	t.Log("You can use new t just like usual *testing.T")
	t.Run("Subtests/Parallel example", func(tt *testing.T) {
		t := check.T(tt)
		t.Parallel()
		t.NotEqual(2, 3, "should not be 3!")
		obj, err := NewObj()
		if t.Nil(err) {
			t.Match(obj.field, `^\d+$`)
		}
	})
}
```

To get optional statistics about executed checkers add:

```go
func TestMain(m *testing.M) { check.TestMain(m) }
```

When use goconvey tool, to get nice diff in web UI
[add](https://github.com/smartystreets/goconvey/issues/513):

```go
import _ "github.com/smartystreets/goconvey/convey"
```

## Installation

Require [Go 1.9](https://golang.org/doc/go1.9#test-helper).

```
go get github.com/powerman/check
```
