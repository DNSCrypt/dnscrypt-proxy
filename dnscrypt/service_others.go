// +build !linux,!windows

package dnscrypt

func ServiceManagerStartNotify() error {
	return nil
}

func ServiceManagerReadyNotify() error {
	return nil
}
