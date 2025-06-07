//go:build unix && !(js && wasm) && !wasip1

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/jedisct1/dlog"
)

const HasSIGHUP = true

// setupSignalHandler sets up a SIGHUP handler to manually trigger reloads
func setupSignalHandler(proxy *Proxy, plugins []Plugin) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)

	go func() {
		for {
			sig := <-sigChan
			if sig == syscall.SIGHUP {
				dlog.Notice("Received SIGHUP signal, reloading configurations")

				// Reload each plugin that supports hot-reloading
				for _, plugin := range plugins {
					if err := plugin.Reload(); err != nil {
						dlog.Errorf("Failed to reload plugin [%s]: %v", plugin.Name(), err)
					} else {
						dlog.Noticef("Successfully reloaded plugin [%s]", plugin.Name())
					}
				}
			}
		}
	}()
}
