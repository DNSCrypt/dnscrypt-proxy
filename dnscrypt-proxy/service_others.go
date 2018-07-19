// +build !linux,!windows

package main

func ServiceManagerStartNotify() error {
	return nil
}

func ServiceManagerReadyNotify() {
}
