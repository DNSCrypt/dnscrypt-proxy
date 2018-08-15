// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build openbsd
// +build 386 amd64 arm

package unix

import (
	"syscall"
	"unsafe"
)

const (
	_SYS_PLEDGE = 108
)

// Pledge implements the pledge syscall. For more information see pledge(2).
func Pledge(promises string, execpromises string) error {
	promisesPtr, err := syscall.BytePtrFromString(promises)
	if err != nil {
		return err
	}
	/*
		if paths != nil {
			var pathsPtr []*byte
			if pathsPtr, err = syscall.SlicePtrFromStrings(paths); err != nil {
				return err
			}
			pathsUnsafe = unsafe.Pointer(&pathsPtr[0])
		}
	*/

	execPromisesPtr, err := syscall.BytePtrFromString(execpromises)
	if err != nil {
		return err
	}
	promisesUnsafe, execPromisesUnsafe := unsafe.Pointer(promisesPtr), unsafe.Pointer(execPromisesPtr)

	_, _, e := syscall.Syscall(_SYS_PLEDGE, uintptr(promisesUnsafe), uintptr(execPromisesUnsafe), 0)
	if e != 0 {
		return e
	}
	return nil
}
