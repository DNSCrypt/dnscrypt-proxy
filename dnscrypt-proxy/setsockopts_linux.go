package main

import (
    "errors"
    "net"
    "strings"
    "syscall"

    "golang.org/x/sys/unix"
)

// NOTE: 'type Proxy struct{}' is removed here because it is already defined in proxy.go.
// The methods below effectively extend the existing Proxy struct.

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

                // QoS / DSCP: Changed to 0xB8 (DSCP 46 / EF - Expedited Forwarding) for low latency.
                if isV4 {
                    set(unix.SetsockoptInt(fdi, unix.IPPROTO_IP, unix.IP_TOS, 0xB8))
                }
                if isV6 {
                    set(unix.SetsockoptInt(fdi, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, 0xB8))
                }

                // UDP buffering: Increased to 4 MiB to handle micro-bursts without packet loss.
                // Ensure 'sysctl -w net.core.rmem_max=4194304' (or higher) is set on the host.
                set(unix.SetsockoptInt(fdi, unix.SOL_SOCKET, unix.SO_RCVBUF, 4*1024*1024))
                set(unix.SetsockoptInt(fdi, unix.SOL_SOCKET, unix.SO_SNDBUF, 4*1024*1024))

                // Fragmentation: Changed to IP_PMTUDISC_DONT to allow fragmentation.
                // This prevents UDP drops when responses exceed MTU (critical for large DNSSEC records).
                if isV4 {
                    set(unix.SetsockoptInt(fdi, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT))
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

                // Optional: bind to non-local addresses.
                if isV4 {
                    setIgnorePerm(unix.SetsockoptInt(fdi, unix.IPPROTO_IP, unix.IP_FREEBIND, 1))
                }
                if isV6 {
                    setIgnorePerm(unix.SetsockoptInt(fdi, unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1))
                }

                // QoS / DSCP: Changed to 0xB8 (EF).
                if isV4 {
                    set(unix.SetsockoptInt(fdi, unix.IPPROTO_IP, unix.IP_TOS, 0xB8))
                }
                if isV6 {
                    set(unix.SetsockoptInt(fdi, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, 0xB8))
                }

                // Low-latency small writes.
                set(unix.SetsockoptInt(fdi, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1))

                // TCP Fast Open: Enabled with queue length 256.
                // Reduces handshake to 1 RTT. Requires 'sysctl net.ipv4.tcp_fastopen=3'.
                set(unix.SetsockoptInt(fdi, unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 256))

                // Congestion Control: Explicitly set to BBR for better throughput on lossy links.
                // Requires 'tcp_bbr' kernel module loaded.
                set(unix.SetsockoptString(fdi, unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr"))
            })
            if err != nil {
                return err
            }
            return innerErr
        },
    }, nil
}
