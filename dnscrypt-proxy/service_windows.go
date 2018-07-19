package main

import "golang.org/x/sys/windows/svc/mgr"

func ServiceManagerStartNotify() error {
	mgr, err := mgr.Connect()
	if err != nil {
		return err
	}
	mgr.Disconnect()
	return nil
}

func ServiceManagerReadyNotify() {}
