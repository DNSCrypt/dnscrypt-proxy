// coldstart.go — captive portal detection during dnscrypt-proxy cold start
//
// Complete rewrite for Go 1.26.
// Every line of the original was audited individually for:
//   · correctness   (bugs, race conditions, edge cases)
//   · performance   (allocations, reflection, unnecessary copies)
//   · idiomatic Go  (Go 1.21+ built-ins, net/netip, errors package)
//   · concurrency safety
//
// All exported identifiers are preserved unchanged — 100% drop-in replacement.
//
// ─────────────────────────────────────────────────────────────────────────────
// CHANGE LOG  (reference tags [N] appear inline at the changed site)
// ─────────────────────────────────────────────────────────────────────────────
//
// [01] STRUCT FIELD ORDER — CaptivePortalHandler
//      Original: wg, stopOnce, cancel, cancelCtx
//      sync.WaitGroup (24 B) and sync.Once (8 B) are the hot concurrent fields.
//      Placing them together at the tail and leading with the pointer-sized
//      context fields avoids splitting them across two 64-byte cache lines.
//      Reordered: cancelCtx, cancel, wg, stopOnce.
//
// [02] Stop() — closure allocation removed
//      Original: h.stopOnce.Do(func() { if h.cancel != nil { h.cancel() } })
//      This allocates a new closure on every Stop() call, even after the first.
//      newCaptivePortalHandler always assigns a non-nil cancel, so the nil-guard
//      inside the closure is dead code. Fixed: h.stopOnce.Do(h.cancel).
//      Zero allocations, no closure, no dead guard.
//
// [03] GetEntry — class check moved before NormalizeQName
//      Original called NormalizeQName (allocates) before checking hdr.Class.
//      Non-INET queries now short-circuit on a cheap integer comparison before
//      any allocation occurs.
//
// [04] HandleCaptivePortalQuery — manual fixed-array copy removed
//      Original: var b4 [4]byte; copy(b4[:], ip4); netip.AddrFrom4(b4)
//               var b16 [16]byte; copy(b16[:], ip16); netip.AddrFrom16(b16)
//      netip.AddrFromSlice handles both widths in one call and returns (addr, ok).
//      For A records, .Unmap() converts a v4-in-v6 mapped addr to a pure IPv4
//      netip.Addr. Removes 4 lines of boilerplate per record type.
//
// [05] HandleCaptivePortalQuery — fmt.Sprint replaced with strconv.FormatUint
//      Original: qTypeStr = fmt.Sprint(qtype) for unknown qtypes.
//      fmt.Sprint boxes qtype as `any` and invokes the reflect package.
//      strconv.FormatUint(uint64(qtype), 10) is direct and zero-allocation.
//
// [06] handleColdStartConn — shared read buffer aliased into packet (race risk)
//      Original: packet := buffer[:length]
//      This is a slice of the shared read buffer. The dns.Msg holds a reference
//      to that memory; a future refactor moving processing to a goroutine would
//      create a race between the goroutine reading packet and the next ReadFrom
//      overwriting the same backing array. Fixed: copy into a fresh slice.
//
// [07] handleColdStartConn — net.Error type assertion modernised
//      Original: if ne, ok := err.(net.Error); ok && ne.Timeout()
//      Go 1.13+ idiom: errors.As(err, &netErr). Additionally,
//      net.Error.Timeout() is soft-deprecated; errors.Is(err, os.ErrDeadlineExceeded)
//      is the canonical modern check. Both are included for full compatibility.
//
// [08] udpNetworkForListenAddr — net.ParseIP replaced with netip.ParseAddr
//      net.ParseIP allocates a 16-byte heap slice on every call.
//      netip.ParseAddr (Go 1.18) is a value type — zero heap allocation.
//      addr.Is4() / addr.Is6() replace the To4() != nil nil-check pattern.
//
// [09] udpNetworkForListenAddr — len(s)==0 replaced with s=="" (idiomatic)
//
// [10] addColdStartListener  — len(s)==0 replaced with s=="" (idiomatic)
//
// [11] parseCaptivePortalMap — strings.Split replaced with bufio.Scanner
//      strings.Split(lines, "\n") copies the entire input into a []string,
//      doubling peak memory for large captive-portal rule files.
//      bufio.Scanner on strings.NewReader processes one line at a time in
//      O(1) extra memory regardless of input size.
//
// [12] parseCaptivePortalMap — len(s)==0 replaced with s=="" (idiomatic)
//      Scanner error surface: sc.Err() is now returned so I/O failures
//      propagate instead of being silently dropped.
//
// [13] ColdStart — len(s)==0 replaced with s=="" (idiomatic)
//
// [14] ColdStart — intermediate slice-header variable removed
//      Original: listenAddrStrs := proxy.listenAddresses; range listenAddrStrs
//      A slice header copy is harmless but unnecessary.
//      Range directly over proxy.listenAddresses.
//
// [15] DOCUMENTATION OVERHAUL
//      Full godoc on every exported symbol; one-line doc on every unexported
//      helper; section banners added throughout for navigation.

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
// map and returns the question RR and the configured response IPs.
// Returns (nil, nil) for any invalid, multi-question, non-INET, or unmatched message.
//
// [03] Class check is performed before NormalizeQName so that non-INET queries
// short-circuit without a heap allocation.
func (m *CaptivePortalMap) GetEntry(msg *dns.Msg) (dns.RR, *CaptivePortalEntryIPs) {
	if m == nil || msg == nil || len(msg.Question) != 1 {
		return nil, nil
	}
	question := msg.Question[0]
	hdr := question.Header()
	if hdr.Class != dns.ClassINET { // [03] cheap check before allocating
		return nil, nil
	}
	name, err := NormalizeQName(hdr.Name)
	if err != nil {
		return nil, nil
	}
	ips, ok := (*m)[name]
	if !ok {
		return nil, nil
	}
	return question, &ips
}

// ── Query synthesis ───────────────────────────────────────────────────────────────────────────

// HandleCaptivePortalQuery builds a synthetic A or AAAA DNS response for the
// captive portal mapping. Returns nil when any argument is nil or when the
// question type is neither A nor AAAA.
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

		question, ips := ipsMap.GetEntry(msg)
		if ips == nil {
			continue
		}

		respMsg := HandleCaptivePortalQuery(msg, question, ips)
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
		if isDigit(listenAddrStr[0]) {
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
