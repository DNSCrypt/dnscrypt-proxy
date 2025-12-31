package main

import (
    "errors"
    "net"
    "strings"
    "syscall"

    "golang.org/x/sys/unix"
)

type Proxy struct{}

func (proxy *Proxy) udpListenerConfig() (*net.ListenConfig, error) {
    return &net.ListenConfig{
        Control: func(network, address string, c syscall.RawConn) error {
            var innerErr error

            err := c.Control(func(fd uintptr) {
                fdi := int(fd)

                set := func(err error) {
                    if innerErr == nil && err != nil {
                        innerErr = err
                    }
                }

                setIgnorePerm := func(err error) {
                    if err == nil {
                        return
                    }
                    if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
                        return
                    }
                    set(err)
                }

                isV6 := strings.HasSuffix(network, "6")
                isV4 := strings.HasSuffix(network, "4") || (!isV6 && (network == "udp" || network == "tcp"))

                set(unix.SetsockoptInt(fdi, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1))
                setIgnorePerm(unix.SetsockoptInt(fdi, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1))

                // Optional: bind to non-local addresses (may require privileges/sysctls).
                if isV4 {
                    setIgnorePerm(unix.SetsockoptInt(fdi, unix.IPPROTO_IP, unix.IP_FREEBIND, 1))
                }
                if isV6 {
                    setIgnorePerm(unix.SetsockoptInt(fdi, unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1))
                }

                // QoS / DSCP (0x70 was in your original).
                if isV4 {
                    set(unix.SetsockoptInt(fdi, unix.IPPROTO_IP, unix.IP_TOS, 0x70))
                }
                if isV6 {
                    set(unix.SetsockoptInt(fdi, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, 0x70))
                }

                // UDP buffering: avoid tiny 4 KiB buffers; tune as needed.
                set(unix.SetsockoptInt(fdi, unix.SOL_SOCKET, unix.SO_RCVBUF, 256*1024))
                set(unix.SetsockoptInt(fdi, unix.SOL_SOCKET, unix.SO_SNDBUF, 256*1024))

                // Prefer not fragmenting (better latency than fragmentation); handle EMSGSIZE upstream if needed.
                if isV4 {
                    set(unix.SetsockoptInt(fdi, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO))
                }
            })
            if err != nil {
                return err
            }
            return innerErr
        },
    }, nil
}

func (proxy *Proxy) tcpListenerConfig() (*net.ListenConfig, error) {
    return &net.ListenConfig{
        Control: func(network, address string, c syscall.RawConn) error {
            var innerErr error

            err := c.Control(func(fd uintptr) {
                fdi := int(fd)

                set := func(err error) {
                    if innerErr == nil && err != nil {
                        innerErr = err
                    }
                }

                setIgnorePerm := func(err error) {
                    if err == nil {
                        return
                    }
                    if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
                        return
                    }
                    set(err)
                }

                isV6 := strings.HasSuffix(network, "6")
                isV4 := strings.HasSuffix(network, "4") || (!isV6 && (network == "udp" || network == "tcp"))

                set(unix.SetsockoptInt(fdi, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1))
                setIgnorePerm(unix.SetsockoptInt(fdi, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1))

                // Optional: bind to non-local addresses (may require privileges/sysctls).
                if isV4 {
                    setIgnorePerm(unix.SetsockoptInt(fdi, unix.IPPROTO_IP, unix.IP_FREEBIND, 1))
                }
                if isV6 {
                    setIgnorePerm(unix.SetsockoptInt(fdi, unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1))
                }

                if isV4 {
                    set(unix.SetsockoptInt(fdi, unix.IPPROTO_IP, unix.IP_TOS, 0x70))
                }
                if isV6 {
                    set(unix.SetsockoptInt(fdi, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, 0x70))
                }

                // Low-latency small writes.
                set(unix.SetsockoptInt(fdi, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1))

                // Optional listener-side fast open (requires sysctl support).
                // set(unix.SetsockoptInt(fdi, unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 256))
            })
            if err != nil {
                return err
            }
            return innerErr
        },
    }, nil
}
