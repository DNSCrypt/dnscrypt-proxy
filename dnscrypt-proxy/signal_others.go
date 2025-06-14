//go:build windows || (js && wasm) || wasip1

package main

const HasSIGHUP = false

// setupSignalHandler sets up a SIGHUP handler to manually trigger reloads
func setupSignalHandler(proxy *Proxy, plugins []Plugin) {
	return
}
