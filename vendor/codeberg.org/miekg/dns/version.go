package dns

import "fmt"

// Version is current version of this library.
var Version = v{0, 6, 59}

type v struct {
	Major, Minor, Patch int
}

func (v v) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}
