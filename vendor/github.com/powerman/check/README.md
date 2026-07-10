# check

[![License MIT](https://img.shields.io/badge/license-MIT-royalblue.svg)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/powerman/check?color=blue)](https://go.dev/)
[![Test](https://img.shields.io/github/actions/workflow/status/powerman/check/test.yml?label=test)](https://github.com/powerman/check/actions/workflows/test.yml)
[![Coverage Status](https://raw.githubusercontent.com/powerman/check/gh-badges/coverage.svg)](https://github.com/powerman/check/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/powerman/check?color=blue)](https://github.com/powerman/check/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/powerman/check.svg)](https://pkg.go.dev/github.com/powerman/check)

![Linux | amd64 arm64 armv7 ppc64le s390x riscv64](https://img.shields.io/badge/Linux-amd64%20arm64%20armv7%20ppc64le%20s390x%20riscv64-royalblue)
![macOS | amd64 arm64](https://img.shields.io/badge/macOS-amd64%20arm64-royalblue)
![Windows | amd64 arm64](https://img.shields.io/badge/Windows-amd64%20arm64-royalblue)

Helpers to complement Go [testing](https://golang.org/pkg/testing/) package.

Write tests with ease and fun!

This package is like
[testify/assert](https://godoc.org/github.com/stretchr/testify/assert)/
[testify/require](https://godoc.org/github.com/stretchr/testify/require)
on steroids. :)

## Features

- Compelling output from failed tests:
  - Very easy-to-read dumps for expected and actual values.
  - Same text diff you loved in testify.
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

> [!INFO]
>
> If you use `t.Parallel()` prefer calling `tt.Parallel()` on the original `*testing.T`
> before wrapping with `check.T()` — this satisfies the `paralleltest` linter:

```go
import "github.com/powerman/check"

func TestSomething(tt *testing.T) {
    tt.Parallel()
    t := check.T(tt)
    t.Equal(2, 2)
    t.Log("You can use new t just like usual *testing.T")
    t.Run("Subtests/Parallel example", func(tt *testing.T) {
        tt.Parallel()
        t := check.T(tt)
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

## Installation

```sh
go get github.com/powerman/check
```

## Custom Checkers

You can extend `DeepEqual`/`NotDeepEqual` and `Err`/`NotErr`
with custom comparison logic via `RegisterEqualChecker` and `RegisterErrChecker`.

- This package enables [validator](https://github.com/go-playground/validator)
  `FieldError` and `[]FieldError` comparison by `Namespace()`+`Tag()`
  via `check.Err`/`check.NotErr`.

### Protobuf / gRPC Support

Protobuf message comparison and gRPC status error comparison have been extracted
into separate modules to keep the core dependency-light:

- **[checkproto](https://github.com/powerman/checkproto)** — enables
  `proto.Equal` via `check.DeepEqual`/`check.NotDeepEqual` for protobuf messages.
- **[checkgrpc](https://github.com/powerman/checkgrpc)** — enables
  gRPC status comparison via `check.Err`/`check.NotErr`.
  It also imports checkproto, so a single blank import covers both.

Usage: just add a blank import in your test file or `TestMain`:

```go
import _ "github.com/powerman/checkgrpc"
```

## TODO

- Doc:
  - [ ] Add testable examples.
  - [ ] Show how text diff and stats looks like (both text and screenshot with colors).
- Questionable:
  - [ ] Provide a way to force binary dump for utf8.Valid `string`/`[]byte`?
  - [ ] Count skipped tests (will have to overload `Skip`, `Skipf`, `SkipNow`)?
- Complicated:
  - [ ] Show line of source_test.go with failed test.
