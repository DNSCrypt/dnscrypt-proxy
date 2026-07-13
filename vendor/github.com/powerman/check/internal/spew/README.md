# spew

Upstream: <https://github.com/davecgh/go-spew> (ISC licensed).

Version copied: v1.1.1.

Reason: upstream repository is archived/unmaintained (last release 2018);
vendored to avoid an external dependency.

Local changes policy: only the subset needed for `ConfigState.Sdump` is included.

`common.go` patches two `.Interface()` call sites in the map-key sort path
to route unexported map keys (array or struct keys)
through the existing `unsafeReflectValue` bypass,
fixing a panic on `reflect.Value.Interface: cannot return value obtained from
unexported field or method` (go-spew#108, unfixed upstream).
The vendored copy intentionally diverges from upstream v1.1.1 in this respect.
