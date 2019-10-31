// +build !linux

package main

func (proxy *Proxy) SystemDListeners() error {
	return nil
}
