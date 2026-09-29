package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/jedisct1/dlog"
)

// determineNetprobeIntervals - Determines an interval that should finish at least margin before deadline
//
// mostly useful with a context.Context deadline
func determineNetprobeIntervals(
	ideal time.Duration,
	deadline time.Time,
	margin time.Duration,
) (interval time.Duration, count int, ok bool) {
	remaining := time.Until(deadline) - margin

	if ideal <= 0 || remaining <= 0 {
		return 0, 0, false
	}

	// Smallest number of intervals that does not require
	// an interval larger than the ideal.
	count = int((remaining + ideal - 1) / ideal)

	interval = remaining / time.Duration(count)

	if interval <= 0 {
		return 0, 0, false
	}

	return interval, count, true
}

func NetProbe(
	proxy *Proxy,
	hosts_port []string,
	ctx context.Context,
) error {
	if len(hosts_port) == 0 || ctx.Err() != nil {
		return nil
	}
	if captivePortalHandler, err := ColdStart(proxy); err == nil {
		if captivePortalHandler != nil {
			defer captivePortalHandler.Stop()
		}
	} else {
		dlog.Critical(err)
	}


	ctx, cancelDial := context.WithCancel(ctx)
	defer cancelDial()

	type result struct {
		host string
		ok   bool
		err  error
	}

	results := make(chan result, len(hosts_port))

	var probesPending int = 0
	for _, host := range hosts_port {
		if len(host) <= 0 {
			continue
		}

		probesPending++
		go func(host string) {
			ok, err := NetProbeSingle(proxy, host, ctx)
			results <- result{
				host: host,
				ok:   ok,
				err:  err,
			}
			if ok {
				cancelDial()
			}
		}(host)
	}
	if probesPending <= 0 {
		dlog.Error(
			"netprobe_addresses non-zero length but all addresses are invalid somehow",
		)
		return nil
	}

	for {
		select {
		case res := <-results:
			if res.ok && res.err == nil {
				dlog.Noticef(
					"Network connectivity detected (%s)",
					res.host,
				)
				return nil
			} else if !errors.Is(res.err, context.Canceled) &&
					  !errors.Is(res.err, context.DeadlineExceeded) {
				dlog.Noticef("(%s) %v", res.host, res.err)
			}

			probesPending--
			if probesPending <= 0 {
				dlog.Error("Timeout while waiting for network connectivity")
				return nil
			}

		}
	}
}

func NetProbeSingle(
	proxy *Proxy,
	host_port string,
	ctx context.Context,
) (ok bool, err error) {
	if len(host_port) <= 0 {
		return false, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if _, _, err := net.SplitHostPort(host_port); err != nil {
		return false, err
	}

	loggedMessages := make(map[string]struct{})

	dialer := net.Dialer{
		Timeout: proxy.timeout,
	}

	deadline, deadlineOk := ctx.Deadline()

	interval := time.Second

	if deadlineOk {
		if i, _, ok := determineNetprobeIntervals(
			time.Second,
			deadline,
			10*time.Millisecond,
		); ok {
			interval = i
		}
	}

	for {
		startTimer := time.NewTimer(interval)

		pc, err := dialer.DialContext(
			ctx,
			"udp",
			host_port,
		)
		if runtime.GOOS == "windows" && err == nil {
			// Write at least 1 byte. This ensures that sockets are ready to use for writing.
			// Windows specific: during the system startup, sockets can be created but the underlying buffers may not be
			// set up yet. If this is the case Write fails with WSAENOBUFS: "An operation on a socket could not be
			// performed because the system lacked sufficient buffer space or because a queue was full"
			_, err = pc.Write([]byte{0})
			if err != nil {
				pc.Close()
			}
		}

		if err != nil {
			msg := ""
			var dnsErr *net.DNSError

			switch {
			case ctx.Err() != nil:
				msg = ""
			case errors.As(err, &dnsErr):
				msg = fmt.Sprintf(
					"(%s) Name resolution error: %v",
					host_port,
					dnsErr,
				)
			default:
				msg = fmt.Sprintf(
					"(%s) Network not available yet -- waiting...",
					host_port,
				)
			}


			if _, exists := loggedMessages[msg]; !exists && msg != "" {
				dlog.Notice(msg)
				loggedMessages[msg] = struct{}{}
			}

			dlog.Debugf(
				"(%s) %v",
				host_port,
				err,
			)

			select {
			case <-ctx.Done():
				dlog.Debugf(
					"(%s) context done",
					host_port,
				)
				return false, ctx.Err()
			case <-startTimer.C:
			}

			continue
		}
		pc.Close()
		return true, nil
	}
}
