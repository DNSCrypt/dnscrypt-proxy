//go:build !android

package main

import (
    "log"
    "net"
    "os"
    "time"

    "github.com/coreos/go-systemd/daemon"
)

var (
    // Pre-allocate messages as bytes to avoid runtime conversion overhead
    notifyStart    = []byte("STATUS=Starting...")
    
    // Split the string to prevent "newline in string" syntax errors
    notifyReady    = []byte("READY=1
" + "STATUS=Ready")
    
    notifyWatchdog = []byte("WATCHDOG=1")
)

// ServiceManagerStartNotify notifies systemd that the service is starting.
func ServiceManagerStartNotify() error {
    // Start is a one-time event, so we use the standard helper for simplicity
    _, err := daemon.SdNotify(false, string(notifyStart))
    return err
}

// ServiceManagerReadyNotify notifies systemd that the service is ready and starts the watchdog.
func ServiceManagerReadyNotify() error {
    // Send "Ready" notification
    if _, err := daemon.SdNotify(false, string(notifyReady)); err != nil {
        return err
    }
    // Start the optimized watchdog in the background
    return startOptimizedWatchdog()
}

func startOptimizedWatchdog() error {
    // 1. Check if watchdog is enabled using the library (parses timestamps correctly)
    interval, err := daemon.SdWatchdogEnabled(false)
    if err != nil || interval == 0 {
        return err
    }

    // 2. Establish a persistent connection to the socket
    // This avoids dialing and looking up env vars in every loop iteration
    addr := os.Getenv("NOTIFY_SOCKET")
    if addr == "" {
        return nil
    }

    // Handle Linux abstract namespace sockets (starting with @)
    if addr[0] == '@' {
        addr = "" + addr[1:]
    }

    conn, err := net.Dial("unixgram", addr)
    if err != nil {
        return err
    }

    // 3. Run the watchdog loop
    // Using refreshInterval / 3 is safe (recommended is / 2, but / 3 provides buffer)
    refreshInterval := interval / 3

    go func() {
        defer conn.Close()
        ticker := time.NewTicker(refreshInterval)
        defer ticker.Stop()

        // Send initial ping immediately
        if _, err := conn.Write(notifyWatchdog); err != nil {
            log.Printf("watchdog: failed to send initial heartbeat: %v", err)
        }

        for range ticker.C {
            // Zero-allocation write directly to the open socket
            if _, err := conn.Write(notifyWatchdog); err != nil {
                // Log error but attempt to continue; broken pipes might recover on restart
                log.Printf("watchdog: failed to send heartbeat: %v", err)
            }
        }
    }()

    return nil
}
