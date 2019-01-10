package main

import "os"

func serviceStartupUserName() *string {
	userName := "NT AUTHORITY\\NetworkService"
	return &userName
}

func (proxy *Proxy) dropPrivilege(userStr string, fds []*os.File) {}
