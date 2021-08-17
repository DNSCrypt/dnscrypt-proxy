# Go package with improved reflect.DeepEqual

Most of the code is copied from Go reflect package with slight
modifications.

Differences from reflect.DeepEqual:

- If compared value implements `.Equal(valueOfSameType) bool` method then
  it will be called instead of comparing values as is.
- If called `Equal` method will panics then whole DeepEqual will panics too.

This means you can use this DeepEqual method to correctly compare types
like time.Time or decimal.Decimal, without taking in account unimportant
differences (like time zone or exponent).
