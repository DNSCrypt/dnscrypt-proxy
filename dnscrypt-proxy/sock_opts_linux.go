package main

import (
	"net"
	"syscall"

	"github.com/jedisct1/dlog"
	"golang.org/x/sys/unix"
)

const (
	// sockBufSize: 4 MiB — absorbs bursts of ~1000 max-size EDNS0 datagrams.
	sockBufSize = 4 * 1024 * 1024

	// busyPollUs: busy-poll window in microseconds.
	// Trades a small amount of CPU for ~7 µs lower interrupt latency.
	busyPollUs = 50

	// maxDNSPacketSize: maximum DNS packet size for UDP GSO segmentation.
	maxDNSPacketSize = 4096
)

// udpListenerConfig returns a ListenConfig with optimised UDP socket options.
func (proxy *Proxy) udpListenerConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			return controlFd(c, setUDPSockOpts)
		},
	}
}

// tcpListenerConfig returns a ListenConfig with optimised TCP socket options.
func (proxy *Proxy) tcpListenerConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			return controlFd(c, setTCPSockOpts)
		},
	}
}

// controlFd unwraps a RawConn and calls fn with the raw file descriptor.
func controlFd(c syscall.RawConn, fn func(int)) error {
	return c.Control(func(fd uintptr) { fn(int(fd)) })
}

// trySet calls setsockopt and logs on failure.
// All options here are best-effort optimisations; errors are never propagated.
func trySet(fd, level, opt, val int, name string) {
	if err := unix.SetsockoptInt(fd, level, opt, val); err != nil {
		dlog.Debugf("setsockopt %s: %v", name, err)
	}
}

// setSockBuf sets SO_RCVBUF/SO_SNDBUF, preferring the FORCE variants which
// bypass rmem_max/wmem_max system limits (requires CAP_NET_ADMIN).
func setSockBuf(fd int) {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, sockBufSize); err != nil {
		trySet(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, sockBufSize, "SO_RCVBUF")
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, sockBufSize); err != nil {
		trySet(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, sockBufSize, "SO_SNDBUF")
	}
}

// setCommonSockOpts applies socket options shared by both UDP and TCP listeners.
func setCommonSockOpts(fd int) {
	// IP_FREEBIND / IPV6_FREEBIND: allow binding to addresses that don't exist
	// yet (e.g. a WireGuard interface that hasn't come up, or a floating VIP).
	trySet(fd, unix.IPPROTO_IP, unix.IP_FREEBIND, 1, "IP_FREEBIND")
	trySet(fd, unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1, "IPV6_FREEBIND")

	// IP_TOS / IPV6_TCLASS: Expedited Forwarding (DSCP EF = 0xB8).
	// EF is the correct DSCP class for latency-sensitive DNS traffic.
	// CS7 (0x70) is reserved for routing-plane traffic (BGP/OSPF) and may be
	// stripped or remarked by intermediate routers.
	trySet(fd, unix.IPPROTO_IP, unix.IP_TOS, 0xB8, "IP_TOS")
	trySet(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, 0xB8, "IPV6_TCLASS")

	// SO_REUSEPORT: fan out incoming packets/connections across multiple goroutines
	// bound to the same port. The kernel hashes each flow to a single socket,
	// avoiding the thundering-herd problem on accept()/recvmsg().
	trySet(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1, "SO_REUSEPORT")

	// SO_PRIORITY: value 7 maps to band 0 (highest) in pfifo_fast/mq qdiscs.
	// Complements IP_TOS — TOS marks the wire packet; PRIORITY affects the
	// local kernel qdisc before the packet is even serialised.
	trySet(fd, unix.SOL_SOCKET, unix.SO_PRIORITY, 7, "SO_PRIORITY")

	// SO_BUSY_POLL: spin-poll the NIC receive queue for this many microseconds
	// before sleeping. Eliminates the interrupt→scheduler→wakeup round-trip
	// for latency-critical DNS traffic at the cost of a small idle-CPU increase.
	trySet(fd, unix.SOL_SOCKET, unix.SO_BUSY_POLL, busyPollUs, "SO_BUSY_POLL")

	setSockBuf(fd)
}

// SetReuseportCPU pins the socket to a specific CPU for cache-local receive
// processing. Must be called after socket creation with the goroutine locked
// to an OS thread (runtime.LockOSThread) and cpuID set to that thread's core.
// Pairs with SO_REUSEPORT: the kernel steers packets arriving on cpuID's NIC
// queue directly to this socket, eliminating cross-CPU cache invalidation.
func SetReuseportCPU(fd, cpuID int) {
	trySet(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU, cpuID, "SO_INCOMING_CPU")
}

// setUDPSockOpts applies UDP-specific socket options.
func setUDPSockOpts(fd int) {
	setCommonSockOpts(fd)

	// IP_MTU_DISCOVER: disable Path MTU discovery.
	// DNS truncation is handled at the application layer (TC flag + retry over
	// TCP); kernel fragmentation is never wanted. Also clears the DF bit,
	// making the separate IP_DF setsockopt call unnecessary.
	trySet(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT, "IP_MTU_DISCOVER")

	// IP_PKTINFO / IPV6_RECVPKTINFO: deliver the destination address and
	// interface index as ancillary data on each recvmsg. Required on multi-homed
	// hosts and VRF setups to reply from the correct source address.
	trySet(fd, unix.IPPROTO_IP, unix.IP_PKTINFO, 1, "IP_PKTINFO")
	trySet(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1, "IPV6_RECVPKTINFO")

	// UDP_GRO: coalesce multiple datagrams from the same flow into a single
	// recvmsg call, reducing syscall overhead under query bursts.
	// Requires kernel >= 5.0.
	trySet(fd, unix.IPPROTO_UDP, unix.UDP_GRO, 1, "UDP_GRO")

	// UDP_SEGMENT: GSO batch send — write multiple responses in one sendmsg
	// call with a stride hint; the kernel or NIC segments them.
	// Pairs with UDP_GRO on the receive side.
	trySet(fd, unix.IPPROTO_UDP, unix.UDP_SEGMENT, maxDNSPacketSize, "UDP_SEGMENT")
}

// setTCPSockOpts applies TCP-specific socket options.
func setTCPSockOpts(fd int) {
	setCommonSockOpts(fd)

	// TCP_NODELAY: disable Nagle's algorithm — send response frames immediately
	// without waiting to coalesce with subsequent data.
	trySet(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1, "TCP_NODELAY")

	// TCP_QUICKACK: disable delayed ACKs on the receive side.
	// Pairs with TCP_NODELAY on the sender to minimise DNS-over-TCP round-trips.
	trySet(fd, unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1, "TCP_QUICKACK")

	// TCP_DEFER_ACCEPT: do not complete accept() until the peer sends data.
	// Avoids waking a goroutine for SYN-only connections (port scans, probes).
	trySet(fd, unix.IPPROTO_TCP, unix.TCP_DEFER_ACCEPT, 1, "TCP_DEFER_ACCEPT")

	// TCP_FASTOPEN: server-side TFO backlog. Allows data in the SYN-ACK for
	// repeat connections, saving one full RTT for DNS-over-TCP clients that
	// reconnect frequently.
	trySet(fd, unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 5, "TCP_FASTOPEN")

	// TCP_THIN_LINEAR_TIMEOUTS / TCP_THIN_DUPACK: DNS-over-TCP is a thin stream
	// (<4 packets in flight). Standard fast-retransmit requires 3 duplicate ACKs
	// and can never trigger on such streams. These options switch retransmission
	// to linear backoff and trigger on the first duplicate ACK, cutting retry
	// latency significantly for small DNS exchanges.
	trySet(fd, unix.IPPROTO_TCP, unix.TCP_THIN_LINEAR_TIMEOUTS, 1, "TCP_THIN_LINEAR_TIMEOUTS")
	trySet(fd, unix.IPPROTO_TCP, unix.TCP_THIN_DUPACK, 1, "TCP_THIN_DUPACK")

	// TCP_NOTSENT_LOWAT: limit unsent data in the send buffer beyond the
	// congestion window. Prevents head-of-line blocking when multiple DNS
	// responses are queued behind a stalled connection.
	trySet(fd, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, 4096, "TCP_NOTSENT_LOWAT")

	// TCP_CONGESTION: BBR probes bandwidth via RTT rather than packet loss,
	// avoiding buffer bloat and artificial stalls. Measurably better than CUBIC
	// for DNS-over-TCP on lossy or high-BDP links.
	if err := unix.SetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr"); err != nil {
		dlog.Debugf("setsockopt TCP_CONGESTION bbr: %v", err)
	}

	// SO_KEEPALIVE + TCP_KEEPIDLE/INTVL/CNT: detect dead DNS-over-TCP clients.
	// TCP_USER_TIMEOUT provides an absolute deadline; keepalive handles the
	// idle-but-alive case. Together they prevent zombie sockets under all
	// failure modes.
	trySet(fd, unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1, "SO_KEEPALIVE")
	trySet(fd, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, 30, "TCP_KEEPIDLE")
	trySet(fd, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, 5, "TCP_KEEPINTVL")
	trySet(fd, unix.IPPROTO_TCP, unix.TCP_KEEPCNT, 3, "TCP_KEEPCNT")

	// TCP_USER_TIMEOUT: close the connection if data goes unacknowledged for
	// longer than this many milliseconds. Overrides keepalive-based dead-peer
	// detection and prevents ~15-minute zombie sockets on catastrophic path loss.
	trySet(fd, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, 10_000, "TCP_USER_TIMEOUT")
}
