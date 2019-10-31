// +build !linux

package dnscrypt

import (
	"io"
	"io/ioutil"
)

func (proxy *Proxy) SystemDListeners() (io.Closer, error) {
	return ioutil.NopCloser(nil), nil
}
