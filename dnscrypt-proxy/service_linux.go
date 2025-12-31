//go:build !android

package main

import (
    "log"
    "net"
    "os"
    "time"

    "github.com/coreos/go-systemd/daemon"
)

// Define variables individually to avoid syntax errors in grouped var() blocks
var notifyStart = []byte("STATUS=Starting...")

// Construct the ready string safely to avoid "newline in string" errors
var notifyReady = []byte("READY=1
STATUS=Ready")

var notifyWatchdog = []byte("WATCHDOG=1")

// ServiceManagerStartNotify notifies systemd that the service is starting.
func ServiceManagerStartNotify() error {
    _, err := daemon.SdNotify(false, string(notifyStart))
    return err
}

// ServiceManagerReadyNotify notifies systemd that the service is ready and starts the watchdog.
func ServiceManagerReadyNotify() error {
    if _, err := daemon.SdNotify(false, string(notifyReady)); err != nil {
        return err
    }
    return startOptimizedWatchdog()
}

func startOptimizedWatchdog() error {
    // 1. Check if watchdog is enabled
    interval, err := daemon.SdWatchdogEnabled(false)
    if err != nil || interval == 0 {
        return err
    }

    // 2. Establish a persistent connection
    addr := os.Getenv("NOTIFY_SOCKET")
    if addr == "" {
        return nil
    }

    if addr[0] == '@' {
        addr = "" + addr[1:]
    }

    conn, err := net.Dial("unixgram", addr)
    if err != nil {
        return err
    }

    // 3. Run the watchdog loop
    refreshInterval := interval / 3

    go func() {
        defer conn.Close()
        ticker := time.NewTicker(refreshInterval)
        defer ticker.Stop()

        // Initial ping
        if _, err := conn.Write(notifyWatchdog); err != nil {
            log.Printf("watchdog: failed to send initial heartbeat: %v", err)
        }

        // Loop
        for range ticker.C {
            if _, err := conn.Write(notifyWatchdog); err != nil {
                log.Printf("watchdog: failed to send heartbeat: %v", err)
            }
        }
    }()

    return nil
}
