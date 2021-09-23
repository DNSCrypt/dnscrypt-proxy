//go:build !linux
// +build !linux

package main

func (proxy *Proxy) addSystemDListeners() error {
	return nil
}
