[![CircleCI](https://circleci.com/gh/charithe/durationcheck.svg?style=svg)](https://circleci.com/gh/charithe/durationcheck)



Duration Check
===============

A Go linter to detect cases where two `time.Duration` values are being multiplied in possibly erroneous ways.

For example, consider the following (highly contrived) function:

```go
func waitFor(someDuration time.Duration) {
    timeToWait := someDuration * time.Second
    time.Sleep(timeToWait)
}
```

Although the above code would compile without any errors, its runtime behaviour would almost certainly be incorrect. 
A caller would reasonably expect `waitFor(5 * time.Seconds)` to wait for ~5 seconds but they would actually end up 
waiting for ~1,388,889 hours.

The above example is just for illustration purposes only. The problem is glaringly obvious in such a simple function 
and even the greenest Gopher would discover the issue immediately. However, imagine a much more complicated function 
with many more lines and it is not inconceivable that such logic errors could go unnoticed. 

See the [test cases](testdata/src/a/a.go) for more examples of the types of errors detected by the linter.


Installation
-------------

Requires Go 1.11 or above.

```
go get -u github.com/charithe/durationcheck/cmd/durationcheck
```

Usage
-----

Invoke `durationcheck` with your package name

```
durationcheck ./...
# or
durationcheck github.com/you/yourproject/...
```
