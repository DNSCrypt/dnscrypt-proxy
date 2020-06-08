package main

import "golang.org/x/sys/windows/svc/mgr"

func ServiceManagerStartNotify() error {
	mgr, err := mgr.Connect()
	if err != nil {
		return err
	}
	_ = mgr.Disconnect()

	return nil
}

func ServiceManagerReadyNotify() error {
	return nil
}
