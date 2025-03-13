//go:build unix

package main

import (
	"os"
	"path"

	"github.com/jedisct1/dlog"
)

func maybeWritableByOtherUsers(p string) (bool, string, error) {
	p = path.Clean(p)
	for p != "/" && p != "." {
		st, err := os.Stat(p)
		if err != nil {
			return false, p, err
		}
		mode := st.Mode()
		if mode.Perm()&2 != 0 && !(st.IsDir() && mode&os.ModeSticky == os.ModeSticky) {
			return true, p, nil
		}
		p = path.Dir(p)
	}
	return false, "", nil
}

func WarnIfMaybeWritableByOtherUsers(p string) {
	if ok, px, err := maybeWritableByOtherUsers(p); ok {
		if px == p {
			dlog.Criticalf("[%s] is writable by other system users - If this is not intentional, it is recommended to fix the access permissions", p)
		} else {
			dlog.Warnf("[%s] can be modified by other system users because [%s] is writable by other users - If this is not intentional, it is recommended to fix the access permissions", p, px)
		}
	} else if err != nil {
		dlog.Warnf("Error while checking if [%s] is accessible: [%s] : [%s]", p, px, err)
	}
}
