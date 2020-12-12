package main

import (
	"net"
	"syscall"
)

func (proxy *Proxy) udpListenerConfig() (*net.ListenConfig, error) {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			_ = c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_FREEBIND, 1)
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_DF, 0)
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, 0x70)
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DONT)
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, 4096)
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, 4096)
			})
			return nil
		},
	}, nil
}

func (proxy *Proxy) tcpListenerConfig() (*net.ListenConfig, error) {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			_ = c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_FREEBIND, 1)
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, 0x70)
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1)
			})
			return nil
		},
	}, nil
}
