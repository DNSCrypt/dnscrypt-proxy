package main

import "golang.org/x/sys/windows/svc/mgr"

func ServiceManagerStartNotify() error {
	mgr, err := mgr.Connect()
	if err != nil {
		return err
	}

	if err = mgr.Disconnect(); err != nil {
		return err
	}
	return nil
}

func ServiceManagerReadyNotify() error {
	return nil
}
