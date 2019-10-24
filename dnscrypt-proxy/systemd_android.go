package main

import (
	"io"
)

func (proxy *Proxy) SystemDListeners() (io.Closer, error) {
	return ioutil.NopCloser(nil), nil
}
