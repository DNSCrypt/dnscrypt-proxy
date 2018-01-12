package godaemon

import (
	"bytes"
	"os"
	"syscall"
)

// Readlink returns the file pointed to by the given soft link, or an error of
// type PathError otherwise. This mimics the os.Readlink() function, but works
// around a bug we've seen in CentOS 5.10 (kernel 2.6.27.10 on x86_64) where the
// underlying OS function readlink() returns a wrong number of bytes for the
// result (see man readlink). Here we don't rely blindly on that value; if
// there's a zero byte among that number of bytes, then we keep only up to that
// point.
//
// NOTE: We chose not to use os.Readlink() and then search on its result to
// avoid an extra overhead of converting back to []byte. The function to search
// for a byte over the string itself (strings.IndexByte()) is only available
// starting with Go 1.2. Also, we're not searching at every iteration to save
// some CPU time, even though that could mean extra iterations for systems
// affected with this bug. But it's wiser to optimize for the general case
// (i.e., those not affected).
func Readlink(name string) (string, error) {
	for len := 128; ; len *= 2 {
		b := make([]byte, len)
		n, e := syscall.Readlink(name, b)
		if e != nil {
			return "", &os.PathError{"readlink", name, e}
		}
		if n < len {
			if z := bytes.IndexByte(b[:n], 0); z >= 0 {
				n = z
			}
			return string(b[:n]), nil
		}
	}
}
