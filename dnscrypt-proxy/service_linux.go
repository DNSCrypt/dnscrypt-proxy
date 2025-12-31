//go:build !android

package main

import (
    "log"
    "net"
    "os"
    "time"

    "github.com/coreos/go-systemd/daemon"
)

var notifyStart = []byte("STATUS=Starting...")

// Use backticks to prevent newline syntax errors
var notifyReady = []byte(`READY=1
STATUS=Ready`)

var notifyWatchdog = []byte("WATCHDOG=1")

// ServiceManagerStartNotify notifies systemd that the service is starting.
func ServiceManagerStartNotify() error {
    _, err := daemon.SdNotify(false, string(notifyStart))
    return err
}

// ServiceManagerReadyNotify notifies systemd that the service is ready.
func ServiceManagerReadyNotify() error {
    if _, err := daemon.SdNotify(false, string(notifyReady)); err != nil {
        return err
    }
    return startOptimizedWatchdog()
}

func startOptimizedWatchdog() error {
    interval, err := daemon.SdWatchdogEnabled(false)
    if err != nil || interval == 0 {
        return err
    }

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

    refreshInterval := interval / 3

    go func() {
        defer conn.Close()
        ticker := time.NewTicker(refreshInterval)
        defer ticker.Stop()

        if _, err := conn.Write(notifyWatchdog); err != nil {
            log.Printf("watchdog: init send failed: %v", err)
        }

        for range ticker.C {
            if _, err := conn.Write(notifyWatchdog); err != nil {
                log.Printf("watchdog: send failed: %v", err)
            }
        }
    }()

    return nil
}
