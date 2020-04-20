package main

import (
	"os"

	"github.com/jedisct1/dlog"
)

func (proxy *Proxy) dropPrivilege(userStr string, fds []*os.File) {
	dlog.Warn("Dropping privileges doesn't work reliably on MacOS")
}
