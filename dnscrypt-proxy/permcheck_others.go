//go:build !unix

package main

func WarnIfMaybeWritableByOtherUsers(p string) {
	// No-op
}
