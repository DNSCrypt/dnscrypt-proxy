# wastedassign
`wastedassign` finds wasted assignment statements

found the value ...

- reassigned, but never used afterward
- reassigned, but reassigned without using the value

## Example

The comment on the right is what this tool reports

```
func f() int {
	a := 0 
        b := 0
        fmt.Print(a)
        fmt.Print(b)
        a = 1  // This reassignment is wasted, because never used afterwards. Wastedassign find this 

        b = 1  // This reassignment is wasted, because reassigned without use this value. Wastedassign find this 
        b = 2
        fmt.Print(b)
        
	return 1 + 2
}
```


## Installation

```
go get -u github.com/sanposhiho/wastedassign/cmd/wastedassign
```

## Usage

```
# in your project

go vet -vettool=`which wastedassign` ./...
```

And, you can use wastedassign in [golangci-lint](https://github.com/golangci/golangci-lint).

## Contribution

I am waiting for your contribution. Feel free to create an issue or a PR!

### Run test

```
go test
```
