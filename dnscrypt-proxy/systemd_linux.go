//go:build !android

package main

import (
"net"
"slices"
"syscall"

"github.com/coreos/go-systemd/activation"
"github.com/jedisct1/dlog"
)

func (proxy *Proxy) addSystemDListeners() error {
files := activation.Files(true)
numFiles := len(files)

if numFiles > 0 {
if len(proxy.userName) > 0 || proxy.child {
dlog.Fatal(
"Systemd activated sockets are incompatible with privilege dropping. Remove activated sockets and fill `listen_addresses` in the dnscrypt-proxy configuration file instead.",
)
}
dlog.Warn("Systemd sockets are untested and unsupported - use at your own risk")
// Pre-allocate slice to avoid resizing overhead
proxy.listenAddresses = make([]string, 0, numFiles)
}

for i, file := range files {
// Optimize: Check socket type directly to avoid failed duplications and syscall overhead
// from net.FileListener/FilePacketConn on mismatched types.
fd := int(file.Fd())
soType, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
if err != nil {
dlog.Warnf("Failed to inspect systemd socket #%d: %v", i, err)
file.Close()
continue
}

var listenAddress string
var regErr error

switch soType {
case syscall.SOCK_STREAM:
// Handle TCP (and potentially Unix) streams
if listener, err := net.FileListener(file); err == nil {
// Safety: Ensure it is actually a TCP listener before casting
if tcpListener, ok := listener.(*net.TCPListener); ok {
proxy.registerTCPListener(tcpListener)
listenAddress = tcpListener.Addr().String()
dlog.Noticef("Wiring systemd TCP socket #%d, %s, %s", i, file.Name(), listenAddress)
} else {
dlog.Warnf("Systemd socket #%d is a stream but not TCP (likely Unix socket). Skipping.", i)
listener.Close() // Close the dup'd listener we just created
}
} else {
regErr = err
}

case syscall.SOCK_DGRAM:
// Handle UDP datagrams
if pc, err := net.FilePacketConn(file); err == nil {
// Safety: Ensure it is actually a UDP connection
if udpConn, ok := pc.(*net.UDPConn); ok {
proxy.registerUDPListener(udpConn)
listenAddress = udpConn.LocalAddr().String()
dlog.Noticef("Wiring systemd UDP socket #%d, %s, %s", i, file.Name(), listenAddress)
} else {
dlog.Warnf("Systemd socket #%d is a datagram but not UDP. Skipping.", i)
pc.Close()
}
} else {
regErr = err
}

default:
dlog.Warnf("Systemd socket #%d has unsupported socket type: %d", i, soType)
}

if regErr != nil {
dlog.Warnf("Failed to create listener for systemd socket #%d: %v", i, regErr)
}

// Update listen addresses if valid
if len(listenAddress) > 0 && !slices.Contains(proxy.listenAddresses, listenAddress) {
proxy.listenAddresses = append(proxy.listenAddresses, listenAddress)
}

// Critical: Close the original file descriptor immediately after processing
// This releases the FD resource back to the OS without waiting for the loop to finish.
file.Close()
}

return nil
}
