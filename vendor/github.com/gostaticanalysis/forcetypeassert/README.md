# forcetypeassert

[![godoc.org][godoc-badge]][godoc]

`forcetypeassert` finds type assertions which did forcely such as below.

```go
func f() {
	var a interface{}
	_ = a.(int) // type assertion must be checked
}
```

<!-- links -->
[godoc]: https://godoc.org/github.com/gostaticanalysis/forcetypeassert
[godoc-badge]: https://img.shields.io/badge/godoc-reference-4F73B3.svg?style=flat-square&label=%20godoc.org

