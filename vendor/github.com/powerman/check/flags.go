package check

import (
	"flag"
	"sync"
)

type peekFlags struct {
	sync.Once
	conveyJSON bool
}

//nolint:gochecknoglobals // By design.
var flags peekFlags

func (p *peekFlags) detect() *peekFlags {
	flags.Do(func() {
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "convey-json" {
				p.conveyJSON = f.Value.String() == "true"
			}
		})
	})
	return p
}
