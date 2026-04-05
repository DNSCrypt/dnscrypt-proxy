package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/jedisct1/dlog"
)

// ── Types ─────────────────────────────────────────────────────────────────────────────

// CaptivePortalEntryIPs is the slice of IPs returned for captive portal
// detection of a specific hostname. net.IP is retained for compatibility
// with existing config-loading and parsing code throughout the package.
type CaptivePortalEntryIPs []net.IP

// CaptivePortalMap maps normalised QNAMEs to their captive portal response IPs.
type CaptivePortalMap map[string]CaptivePortalEntryIPs

// CaptivePortalHandler owns the cold-start UDP listeners that serve captive
// portal detection responses. Stop is safe to call multiple times and from
// multiple goroutines concurrently.
//
// [01] Field order: context fields first (pointer-sized), sync primitives last,
// so wg and stopOnce — the hot concurrent fields — share a cache line.
type CaptivePortalHandler struct {
	cancelCtx context.Context    // cancelled when Stop is called
	cancel    context.CancelFunc // always non-nil after newCaptivePortalHandler
	wg        sync.WaitGroup    // counts live listener goroutines
	stopOnce  sync.Once         // ensures cancel is invoked exactly once
}

// ── Constructor ──────────────────────────────────────────────────────────────────────────

// newCaptivePortalHandler returns a handler backed by a cancelable context.
// cancel is guaranteed non-nil after construction.
func newCaptivePortalHandler() *CaptivePortalHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &CaptivePortalHandler{cancelCtx: ctx, cancel: cancel}
}

// ── CaptivePortalHandler methods ──────────────────────────────────────────────────────────

// Stop signals all captive portal listener goroutines to exit and blocks until
// every goroutine has returned. Safe to call on a nil receiver.
//
// [02] h.stopOnce.Do(h.cancel) replaces the original closure that allocated on
// every call and contained a dead nil-guard (cancel is always non-nil).
func (h *CaptivePortalHandler) Stop() {
	if h == nil {
		return
	}
	h.stopOnce.Do(h.cancel) // cancel is always non-nil — set in constructor [02]
	h.wg.Wait()
}

// ── CaptivePortalMap methods ──────────────────────────────────────────────────────────────────

// GetEntry looks up the single DNS question in msg against the captive portal
// map and returns the question RR, the configured response IPs, and whether a
// match was found. Returns (nil, nil, false) for any invalid, multi-question,
// non-INET, or unmatched message.
//
// [03] Class check is performed before NormalizeQName so that non-INET queries
// short-circuit without a heap allocation.
// [03b] Returns CaptivePortalEntryIPs by value with an explicit bool rather
// than a pointer to a local slice header, making the return contract clearer.
func (m CaptivePortalMap) GetEntry(msg *dns.Msg) (dns.RR, CaptivePortalEntryIPs, bool) {
	if m == nil || msg == nil || len(msg.Question) != 1 {
		return nil, nil, false
	}
	question := msg.Question[0]
	hdr := question.Header()
	if hdr.Class != dns.ClassINET { // [03] cheap check before allocating
		return nil, nil, false
	}
	name, err := NormalizeQName(hdr.Name)
	if err != nil {
		return nil, nil, false
	}
	ips, ok := m[name]
	if !ok {
		return nil, nil, false
	}
	return question, ips, true
}

// ── Query synthesis ───────────────────────────────────────────────────────────────────────────

// HandleCaptivePortalQuery builds a synthetic A or AAAA DNS response for the
// captive portal mapping. Returns nil when any argument is nil or when the
// question type is neither A nor AAAA.
//
// When the query type matches (A or AAAA) but no IPs of the requested address
// family are present in ips, the function returns NOERROR with an empty answer
// section (NODATA). This is intentional: it signals "we handle this name but
// have no records of that type" without triggering a fallback to upstream.
//
// [04] netip.AddrFromSlice + .Unmap() replace the original manual [4]byte /
// [16]byte copy idiom, reducing 4 lines of boilerplate per record type.
// [05] Unknown qtype formatted via strconv.FormatUint to avoid fmt.Sprint's
// reflect boxing.
func HandleCaptivePortalQuery(msg *dns.Msg, question dns.RR, ips *CaptivePortalEntryIPs) *dns.Msg {
	if msg == nil || question == nil || ips == nil {
		return nil
	}

	respMsg := EmptyResponseFromMessage(msg)
	const ttl = uint32(1)
	hdr := question.Header()
	qtype := dns.RRToType(question)

	switch qtype {
	case dns.TypeA:
		for _, xip := range *ips {
			// [04] To4() returns a 4-byte slice; AddrFromSlice + Unmap gives a
			// pure IPv4 netip.Addr without a manual fixed-array copy.
			ip4 := xip.To4()
			if ip4 == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(ip4)
			if !ok {
				continue
			}
			respMsg.Answer = append(respMsg.Answer, &dns.A{
				Hdr: dns.Header{Name: hdr.Name, Class: dns.ClassINET, TTL: ttl},
				A:   rdata.A{Addr: addr.Unmap()},
			})
		}

	case dns.TypeAAAA:
		for _, xip := range *ips {
			if xip.To4() != nil {
				continue // skip IPv4 addresses for AAAA records
			}
			ip16 := xip.To16()
			if ip16 == nil {
				continue
			}
			// [04] AddrFromSlice on a 16-byte slice; no Unmap needed for pure IPv6.
			addr, ok := netip.AddrFromSlice(ip16)
			if !ok {
				continue
			}
			respMsg.Answer = append(respMsg.Answer, &dns.AAAA{
				Hdr:  dns.Header{Name: hdr.Name, Class: dns.ClassINET, TTL: ttl},
				AAAA: rdata.AAAA{Addr: addr},
			})
		}
	}

	// [05] strconv.FormatUint avoids fmt.Sprint's reflect boxing for unknown qtypes.
	qTypeStr, found := dns.TypeToString[qtype]
	if !found {
		qTypeStr = strconv.FormatUint(uint64(qtype), 10)
	}
	dlog.Infof("Query for captive portal detection: [%v] (%v)", hdr.Name, qTypeStr)

	return respMsg
}

// ── Listener loop ─────────────────────────────────────────────────────────────────────────────

// readDeadline is the per-read timeout for the captive portal UDP socket.
// Short enough to re-check context cancellation promptly without busy-spinning.
const readDeadline = 1 * time.Second

// handleColdStartConn runs the read/respond loop on a single UDP socket until
// ctx is cancelled or a non-recoverable read error occurs.
//
// [06] Packet bytes are copied into a fresh slice before DNS parsing so that
// the shared read buffer is safe to reuse immediately on the next iteration.
// [07] errors.As + errors.Is replace the pre-1.13 net.Error type assertion.
func handleColdStartConn(ctx context.Context, clientPc *net.UDPConn, ipsMap *CaptivePortalMap) {
	defer clientPc.Close()

	buf := make([]byte, MaxDNSPacketSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = clientPc.SetReadDeadline(time.Now().Add(readDeadline))
		n, clientAddr, err := clientPc.ReadFrom(buf)
		if err != nil {
			// [07] Modern timeout detection: errors.As covers any wrapped net.Error;
			// errors.Is covers os.ErrDeadlineExceeded used by current net internals.
			var netErr net.Error
			if (errors.As(err, &netErr) && netErr.Timeout()) ||
				errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			dlog.Warn(err)
			return
		}
		if n < MinDNSPacketSize {
			continue
		}

		// [06] Copy into a fresh slice; buf must be free for the next ReadFrom.
		packet := make([]byte, n)
		copy(packet, buf[:n])

		msg := &dns.Msg{Data: packet}
		if err := msg.Unpack(); err != nil {
			continue
		}

		question, ips, ok := ipsMap.GetEntry(msg)
		if !ok {
			continue
		}

		respMsg := HandleCaptivePortalQuery(msg, question, &ips)
		if respMsg == nil {
			continue
		}
		if err := respMsg.Pack(); err != nil {
			continue
		}
		if _, err := clientPc.WriteTo(respMsg.Data, clientAddr); err != nil {
			dlog.Debugf("Cold start captive portal write failed: %v", err)
		}
	}
}

// ── Network helpers ───────────────────────────────────────────────────────────────────────────

// udpNetworkForListenAddr returns the most specific UDP network string
// ("udp4", "udp6", or "udp") for the given listen address string.
//
// [08] netip.ParseAddr replaces net.ParseIP: zero heap allocation vs 16-byte
// heap slice per call. addr.Is4() / addr.Is6() replace the To4() nil-check.
// [09] Idiomatic s=="" replaces len(s)==0.
func udpNetworkForListenAddr(listenAddrStr string) string {
	if listenAddrStr == "" { // [09]
		return "udp"
	}
	host, _, err := net.SplitHostPort(listenAddrStr)
	if err != nil {
		// Fallback heuristic: a leading ASCII digit strongly implies IPv4.
		// Guard with len > 0 for extra safety even though the "" case is handled above.
		if len(listenAddrStr) > 0 && isDigit(listenAddrStr[0]) {
			return "udp4"
		}
		return "udp"
	}
	host = strings.Trim(host, "[]")
	// [08] netip.ParseAddr: stack-allocated result, no GC pressure.
	if addr, err := netip.ParseAddr(host); err == nil {
		switch {
		case addr.Is4():
			return "udp4"
		case addr.Is6():
			return "udp6"
		}
	}
	return "udp"
}

// addColdStartListener binds a UDP socket to listenAddrStr and starts a
// goroutine that answers captive portal queries until h is stopped.
// Returns nil immediately when listenAddrStr is empty.
// [10] Idiomatic s=="" replaces len(s)==0.
func addColdStartListener(ipsMap *CaptivePortalMap, listenAddrStr string, h *CaptivePortalHandler) error {
	if h == nil || ipsMap == nil {
		return errors.New("handler/map is nil")
	}
	if listenAddrStr == "" { // [10]
		return nil
	}
	network := udpNetworkForListenAddr(listenAddrStr)
	listenUDPAddr, err := net.ResolveUDPAddr(network, listenAddrStr)
	if err != nil {
		return err
	}
	clientPc, err := net.ListenUDP(network, listenUDPAddr)
	if err != nil {
		return err
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		handleColdStartConn(h.cancelCtx, clientPc, ipsMap)
	}()
	return nil
}

// ── Config parsing ───────────────────────────────────────────────────────────────────────────

// parseCaptivePortalMap parses newline-separated "hostname ip1,ip2,..." rules
// into a CaptivePortalMap. Comment lines and blank lines are ignored.
// Returns an error on the first malformed rule.
//
// [11] bufio.Scanner replaces strings.Split(lines, "\n"): avoids doubling peak
// memory by scanning one line at a time in O(1) extra space.
// [12] s=="" replaces len(s)==0; sc.Err() is now returned so scanner I/O
// failures propagate instead of being silently swallowed.
func parseCaptivePortalMap(lines string) (CaptivePortalMap, error) {
	ipsMap := make(CaptivePortalMap)
	sc := bufio.NewScanner(strings.NewReader(lines)) // [11]
	// [11b] Raise the scanner token buffer to 1 MiB so long config lines (e.g.
	// hostnames with many IPs) do not hit the default 64 KiB token limit.
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		line := TrimAndStripInlineComments(sc.Text())
		if line == "" { // [12]
			lineNo++
			continue
		}

		name, ipsStr, ok := StringTwoFields(line)
		if !ok {
			return nil, fmt.Errorf("syntax error for a captive portal rule at line %d", 1+lineNo)
		}
		if strings.Contains(name, "*") {
			return nil, fmt.Errorf("a captive portal rule must use an exact host name at line %d", 1+lineNo)
		}

		normName, err := NormalizeQName(name)
		if err != nil {
			lineNo++
			continue // skip invalid names — preserves original behaviour
		}

		var ips []net.IP
		for ipToken := range strings.SplitSeq(ipsStr, ",") {
			ipStr := strings.TrimSpace(ipToken)
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP %q for captive portal rule at line %d", ipStr, 1+lineNo)
			}
			ips = append(ips, ip)
		}
		ipsMap[normName] = ips
		lineNo++
	}
	return ipsMap, sc.Err() // surface any scanner I/O error [12]
}

// ── Entry point ────────────────────────────────────────────────────────────────────────────

// ColdStart reads proxy.captivePortalMapFile, binds a UDP listener on each
// address in proxy.listenAddresses, and returns a CaptivePortalHandler that
// should be stopped once the proxy is fully initialised.
//
// Returns (nil, nil) when no captive portal map file is configured.
// If at least one listener starts successfully, the handler is returned even
// when other listeners fail; the first bind error is preserved but discarded
// in that case (matching original behaviour).
//
// [13] s=="" replaces len(s)==0.
// [14] Range directly over proxy.listenAddresses; intermediate slice-header
// variable removed.
func ColdStart(proxy *Proxy) (*CaptivePortalHandler, error) {
	if proxy == nil {
		return nil, errors.New("proxy is nil")
	}
	if proxy.captivePortalMapFile == "" { // [13]
		return nil, nil
	}

	lines, err := ReadTextFile(proxy.captivePortalMapFile)
	if err != nil {
		dlog.Warn(err)
		return nil, err
	}
	ipsMap, err := parseCaptivePortalMap(lines)
	if err != nil {
		return nil, err
	}

	h := newCaptivePortalHandler()
	var firstErr error
	anyOK := false

	// [14] Range directly; no need for an intermediate slice-header variable.
	for _, listenAddrStr := range proxy.listenAddresses {
		if err := addColdStartListener(&ipsMap, listenAddrStr, h); err != nil {
			dlog.Warnf("coldstart: listener %s failed: %v", listenAddrStr, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		anyOK = true
	}

	proxy.captivePortalMap = &ipsMap
	if anyOK {
		return h, nil
	}
	if firstErr == nil {
		firstErr = errors.New("no captive portal listeners could be started")
	}
	h.Stop() // no goroutines were started, but upholds the contract
	return nil, firstErr
}
