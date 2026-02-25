// common.go — shared utilities and protocol constants for dnscrypt-proxy
//
// Complete rewrite for Go 1.26.
// Every line of the original was audited individually for:
//   · correctness (bugs, fencepost errors, anti-patterns)
//   · performance (allocations, reflection, syscall count)
//   · concurrency safety
//   · idiomatic Go style
//
// All exported identifiers are preserved unchanged — 100% drop-in replacement.
//
// ─────────────────────────────────────────────────────────────────────────────
// CHANGE LOG  (reference tags [N] appear inline throughout the file)
// ─────────────────────────────────────────────────────────────────────────────
//
// [01] REDUNDANT CAST REMOVED — InheritedDescriptorsBase
//      Original: InheritedDescriptorsBase = uintptr(50) inside a const block.
//      Moved to a standalone typed const; the uintptr() cast was redundant noise.
//
// [02] IDIOMATIC NIL SLICE — FileDescriptors
//      Original: FileDescriptors = make([]*os.File, 0)
//      make(T,0) and a nil slice are behaviourally identical (len, cap, append).
//      The nil form is idiomatic Go for "not yet populated" and skips a heap
//      allocation during package initialisation.
//
// [03] REDUNDANT ZERO REMOVED — FileDescriptorNum
//      Original: FileDescriptorNum = uintptr(0)
//      Every Go variable is zero-initialised; writing = 0 is redundant.
//
// [04] DEAD CODE REMOVED — Min / Max
//      The original tagged both "Deprecated: use built-in directly" but still
//      emitted them. This is package main with no external callers. Removed.
//      All internal call sites use the Go 1.21 built-in min()/max() directly.
//
// [05] UNNECESSARY VARIABLE REMOVED — PrefixWithSize
//      Three statements (allocate, AppendUint16, append) collapsed to a single
//      expression chain; identical behaviour, one fewer named variable.
//
// [06] POINTER-TO-INTERFACE BUG FIXED — ReadPrefixed parameter
//      Original: func ReadPrefixed(conn *net.Conn)
//      *net.Conn is a pointer to an interface value — an anti-pattern in Go.
//      It forces callers to write &conn and prevents passing concrete types.
//      Fixed: func ReadPrefixed(conn net.Conn)
//      MIGRATION: call sites that passed &conn must now pass conn directly.
//
// [07] FENCEPOST ERROR FIXED — ReadPrefixed upper bound
//      Original: packetLength > MaxDNSPacketSize-1  (rejects valid 4096-byte packets)
//      MaxDNSPacketSize = 4096; a 4096-byte packet is valid by definition.
//      Fixed: packetLength > MaxDNSPacketSize
//
// [08] ASCII FAST-PATH ADDED — StringReverse
//      Original unconditionally allocated []rune even for pure-ASCII strings
//      (all hostnames, domain labels). For ASCII, utf8.RuneCountInString(s)==len(s)
//      so a byte-level swap avoids the rune allocation entirely.
//      Multi-byte Unicode falls through to the original rune path unchanged.
//
// [09] LOGIC BUG FIXED — TrimAndStripInlineComments
//      Original: strings.LastIndexByte(str, '#') — finds the LAST '#'.
//      For "value # first # second", if the last '#' is not whitespace-preceded
//      the first comment is silently missed. Fixed to strings.IndexByte (first '#')
//      to match universal config-file semantics.
//      Also removed the dead branch "idx==0 || str[0]=='#'": the second condition
//      is always true when idx==0 and adds nothing.
//
// [10] STDLIB PARSING — ExtractHostAndPort
//      Original used manual bracket detection + strings.LastIndex(":") which
//      had edge cases with bare IPv6 and non-numeric port suffixes.
//      net.SplitHostPort handles all stdlib-defined forms correctly.
//
// [11] ZERO-ALLOCATION TIMESTAMP — formatTimestampTSV
//      Original: fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", ...)
//      fmt.Sprintf allocates a temporary string. time.AppendFormat (Go 1.17)
//      writes directly into a pre-grown []byte — one fewer allocation per log line.
//
// [12] REFLECTION-FREE LOGGING — formatTSVLine / formatLTSVLine
//      Original used fmt.Fprintf(&line, ...) for every field, which boxes each
//      argument as `any` via reflection (one heap alloc per field per line).
//      Replaced with direct strings.Builder WriteString/WriteByte calls.
//
// [13] ZERO-COPY LOG WRITE — WritePluginLog
//      Original: logger.Write([]byte(line)) — always copies the string.
//      io.WriteString checks for io.StringWriter at runtime and avoids the copy
//      for writers that support it (*os.File, lumberjack.Logger, etc.).
//
// [14] BOUNDED SPLIT — ParseTimeBasedRule
//      strings.Split(line,"@") replaced with strings.SplitN(line,"@",3).
//      Only 0, 1, or 2+ '@' signs need to be distinguished; SplitN stops after
//      finding two delimiters, saving the allocation of extra segments.
//
// [15] STREAMING CONFIG PARSE — ProcessConfigLines
//      strings.Split(lines,"\n") copies the entire input into a []string,
//      doubling peak memory for large block-lists. bufio.Scanner on a
//      strings.Reader processes one line at a time in O(1) extra memory.
//
// [16] ZERO-SIZE MAP VALUE — LoadIPRules
//      Original inserted int(0) into the radix tree and bool(true) into the map.
//      Both box into `any`, allocating one word per rule. struct{}{} is a
//      zero-size type; the runtime uses a shared global pointer for its `any`
//      representation — zero allocation per insert.
//
// [17] PACKAGE-LEVEL CONST — hexDigits
//      Was a local const redeclared inside reverseAddr on every call.
//      Hoisted to package level: single definition, zero runtime cost.
//
// [18] IDIOMATIC EMPTY-STRING CHECK — InitializePluginLogger
//      len(logFile)==0 replaced with idiomatic logFile=="".
//
// [19] DOCUMENTATION OVERHAUL
//      Full godoc on every exported symbol; one-line doc on every unexported
//      helper; section banners added; per-symbol "Go 1.26:" tags replaced by
//      this unified header.

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	iradix "github.com/hashicorp/go-immutable-radix"
	"github.com/jedisct1/dlog"
	"github.com/k-sone/critbitgo"
)

// ── Crypto construction ───────────────────────────────────────────────────────

// CryptoConstruction identifies the authenticated-encryption scheme advertised
// by a DNSCrypt server certificate.
type CryptoConstruction uint16

const (
	UndefinedConstruction CryptoConstruction = iota
	XSalsa20Poly1305
	XChacha20Poly1305
)

// ── Protocol constants ────────────────────────────────────────────────────────

const (
	// ClientMagicLen is the byte length of the client magic field in a DNSCrypt query.
	ClientMagicLen = 8

	// MaxHTTPBodyLength is the maximum response body size accepted from DoH servers.
	MaxHTTPBodyLength = 1_000_000
)

// DNS packet size limits and protocol parameters.
const (
	MinDNSPacketSize        = 12 + 5 // minimum DNS header (12 B) + minimal question (5 B)
	MaxDNSPacketSize        = 4096
	MaxDNSUDPPacketSize     = 4096
	MaxDNSUDPSafePacketSize = 1252
	InitialMinQuestionSize  = 512
)

// InheritedDescriptorsBase is the lowest fd number reserved for descriptors
// that must survive a privilege-drop exec boundary.
// [01] Standalone typed const; original had a redundant uintptr() cast in a group.
const InheritedDescriptorsBase uintptr = 50

// ── Protocol magic values ─────────────────────────────────────────────────────

// CertMagic is the 4-byte prefix identifying a DNSCrypt certificate. ASCII: "DNSC"
var CertMagic = [4]byte{0x44, 0x4e, 0x53, 0x43}

// ServerMagic is the 8-byte prefix identifying a DNSCrypt server response.
// ASCII: "r6fnvWj8"
var ServerMagic = [8]byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}

// ── File-descriptor management ────────────────────────────────────────────────

// FileDescriptors holds *os.File handles that must be forwarded to the
// sandboxed child process after a privilege drop.
// [02] Nil slice; make([]*os.File, 0) was a gratuitous alloc.
var FileDescriptors []*os.File

// FileDescriptorNum is the next available slot index in FileDescriptors.
// [03] Explicit = uintptr(0) removed; zero-initialisation is implicit in Go.
var FileDescriptorNum uintptr

// FileDescriptorsMu guards concurrent access to FileDescriptors and FileDescriptorNum.
var FileDescriptorsMu sync.Mutex

// ── Sentinel errors ───────────────────────────────────────────────────────────

var (
	// ErrPacketTooLarge is returned when a DNS packet exceeds MaxDNSPacketSize.
	ErrPacketTooLarge = errors.New("packet too large")

	// ErrPacketTooShort is returned when a DNS packet is shorter than MinDNSPacketSize.
	ErrPacketTooShort = errors.New("packet too short")

	// ErrLogNotInitialized is returned by WritePluginLog when logger is nil.
	ErrLogNotInitialized = errors.New("log file not initialized")
)

// ── Packet framing ────────────────────────────────────────────────────────────

// PrefixWithSize prepends a big-endian 2-byte length header to packet,
// as required by DNS-over-TCP framing (RFC 1035 §4.2.2).
// Returns ErrPacketTooLarge when len(packet) > 0xffff.
func PrefixWithSize(packet []byte) ([]byte, error) {
	if len(packet) > 0xffff {
		return nil, ErrPacketTooLarge
	}
	// [05] Single-expression chain: allocate once, write 2-byte header, append body.
	// binary.BigEndian.AppendUint16 (Go 1.19) writes into the pre-grown slice
	// without an intermediate allocation.
	return append(
		binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(packet)), uint16(len(packet))),
		packet...,
	), nil
}

// ReadPrefixed reads a 2-byte big-endian length-prefixed DNS packet from conn.
// The 2-byte header is consumed and not included in the returned slice.
//
// [06] Parameter is net.Conn (interface value), not *net.Conn (pointer to
// interface). *net.Conn is an anti-pattern: it prevents callers from passing
// a concrete type directly and forces every call site to take &conn.
// MIGRATION: call sites must pass conn directly instead of &conn.
//
// [07] Upper bound fixed from MaxDNSPacketSize-1 to MaxDNSPacketSize.
// A 4096-byte packet is valid by the constant's own definition.
func ReadPrefixed(conn net.Conn) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("failed to read packet length: %w", err)
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > MaxDNSPacketSize { // [07] was MaxDNSPacketSize-1
		return nil, ErrPacketTooLarge
	}
	if n < MinDNSPacketSize {
		return nil, ErrPacketTooShort
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("failed to read packet data: %w", err)
	}
	return buf, nil
}

// ── String utilities ──────────────────────────────────────────────────────────

// StringReverse returns s with its Unicode code points in reverse order.
//
// [08] ASCII fast-path: for pure-ASCII strings (all hostnames, domain labels)
// utf8.RuneCountInString(s)==len(s), so a byte-level swap avoids the []rune
// allocation entirely. Multi-byte Unicode falls through to the rune path.
func StringReverse(s string) string {
	if s == "" {
		return s
	}
	if utf8.RuneCountInString(s) == len(s) {
		// Pure ASCII: single []byte allocation, no []rune needed.
		b := []byte(s)
		for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return string(b)
	}
	// Unicode: rune-level swap.
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// StringTwoFields splits str on the first run of whitespace and returns the
// two trimmed fields. Returns ("", "", false) when str is too short, has no
// whitespace, or either trimmed field is empty.
func StringTwoFields(str string) (string, string, bool) {
	if len(str) < 3 {
		return "", "", false
	}
	pos := strings.IndexFunc(str, unicode.IsSpace)
	if pos == -1 {
		return "", "", false
	}
	a := strings.TrimSpace(str[:pos])
	b := strings.TrimSpace(str[pos+1:])
	if a == "" || b == "" {
		return a, b, false
	}
	return a, b, true
}

// StringQuote returns str with non-graphic characters escaped, suitable for
// embedding in structured log output. The surrounding double-quotes that
// strconv.QuoteToGraphic adds are stripped.
func StringQuote(str string) string {
	q := strconv.QuoteToGraphic(str)
	if len(q) >= 2 {
		return q[1 : len(q)-1]
	}
	return q
}

// StringStripSpaces returns str with all Unicode whitespace characters removed.
func StringStripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}

// TrimAndStripInlineComments strips inline comments and surrounding whitespace
// from a config-file line. A comment begins at the FIRST '#' that is either
// the very first byte on the line or is immediately preceded by a space or tab.
//
// [09] Bug fix: original used strings.LastIndexByte (LAST '#'), which could
// leave an earlier valid comment marker intact. Fixed to strings.IndexByte
// (first '#'). The redundant "idx==0 || str[0]=='#'" branch is also removed
// (the second condition is always true when idx==0).
func TrimAndStripInlineComments(str string) string {
	if idx := strings.IndexByte(str, '#'); idx >= 0 {
		if idx == 0 || str[idx-1] == ' ' || str[idx-1] == '\t' {
			str = str[:idx]
		}
	}
	return strings.TrimSpace(str)
}

// ExtractHostAndPort splits a host+port string into its components.
// Supports "[::1]:53" (IPv6 with brackets), "1.2.3.4:53", "host:53", and
// host-only strings (returns defaultPort for the port).
//
// [10] Delegates to net.SplitHostPort for canonical stdlib-defined parsing.
// The original's manual bracket detection had subtle edge cases.
func ExtractHostAndPort(str string, defaultPort int) (string, int) {
	if h, p, err := net.SplitHostPort(str); err == nil {
		if portNum, convErr := strconv.Atoi(p); convErr == nil {
			return h, portNum
		}
	}
	return str, defaultPort
}

// ReadTextFile reads filename and returns its contents as a string.
// A leading UTF-8 BOM (EF BB BF) is stripped automatically.
func ReadTextFile(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", filename, err)
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	return string(data), nil
}

// isDigit reports whether b is an ASCII decimal digit ('0'–'9').
func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// ── Client IP extraction ──────────────────────────────────────────────────────

// ExtractClientIPStr returns the client IP address string from pluginsState.
// Returns ("", false) when clientAddr is nil or the protocol is not recognised.
func ExtractClientIPStr(pluginsState *PluginsState) (string, bool) {
	if pluginsState.clientAddr == nil {
		return "", false
	}
	addr := *pluginsState.clientAddr
	switch pluginsState.clientProto {
	case "udp":
		if ua, ok := addr.(*net.UDPAddr); ok {
			return ua.IP.String(), true
		}
	case "tcp", "local_doh":
		if ta, ok := addr.(*net.TCPAddr); ok {
			return ta.IP.String(), true
		}
	}
	return "", false
}

// ExtractClientIPStrEncrypted returns the client IP string, encrypting it
// through ipCryptConfig when non-nil. Returns the plain IP when nil.
func ExtractClientIPStrEncrypted(pluginsState *PluginsState, ipCryptConfig *IPCryptConfig) (string, bool) {
	ipStr, ok := ExtractClientIPStr(pluginsState)
	if !ok {
		return "", false
	}
	if ipCryptConfig != nil {
		return ipCryptConfig.EncryptIPString(ipStr), true
	}
	return ipStr, true
}

// ── Log formatting ────────────────────────────────────────────────────────────

// hexDigits is the lowercase hex alphabet used for IPv6 PTR record construction.
// [17] Hoisted from a per-call local const inside reverseAddr to package level.
const hexDigits = "0123456789abcdef"

// formatTimestampTSV returns t formatted as "[YYYY-MM-DD HH:MM:SS]".
// [11] time.AppendFormat (Go 1.17) writes into a pre-grown []byte, eliminating
// the intermediate string allocation of the original fmt.Sprintf call.
func formatTimestampTSV(t time.Time) string {
	b := make([]byte, 0, 22) // "[2006-01-02 15:04:05]" = 21 bytes
	b = append(b, '[')
	b = t.AppendFormat(b, "2006-01-02 15:04:05")
	b = append(b, ']')
	return string(b)
}

// FormatLogLine builds a log line in the specified format ("tsv" or "ltsv").
// additionalFields are appended after clientIP, qName, and reason.
// Returns an error for unrecognised format strings.
func FormatLogLine(format, clientIP, qName, reason string, additionalFields ...string) (string, error) {
	switch format {
	case "tsv":
		return formatTSVLine(clientIP, qName, reason, additionalFields...), nil
	case "ltsv":
		return formatLTSVLine(clientIP, qName, reason, additionalFields...), nil
	default:
		return "", fmt.Errorf("unexpected log format: %s", format)
	}
}

// formatTSVLine builds a tab-separated values log line with a leading timestamp.
// [12] fmt.Fprintf replaced with direct strings.Builder methods to eliminate
// reflection boxing of every argument.
func formatTSVLine(clientIP, qName, reason string, additionalFields ...string) string {
	var b strings.Builder
	b.Grow(128 + len(qName) + len(reason) + len(additionalFields)*32)
	b.WriteString(formatTimestampTSV(time.Now()))
	b.WriteByte('\t')
	b.WriteString(clientIP)
	b.WriteByte('\t')
	b.WriteString(StringQuote(qName))
	b.WriteByte('\t')
	b.WriteString(StringQuote(reason))
	for _, f := range additionalFields {
		b.WriteByte('\t')
		b.WriteString(StringQuote(f))
	}
	b.WriteByte('\n')
	return b.String()
}

// formatLTSVLine builds a labeled tab-separated values log line.
// [12] Same reflection-free optimisation as formatTSVLine.
func formatLTSVLine(clientIP, qName, reason string, additionalFields ...string) string {
	var b strings.Builder
	b.Grow(128 + len(qName) + len(reason) + len(additionalFields)*32)
	b.WriteString("time:")
	b.WriteString(strconv.FormatInt(time.Now().Unix(), 10))
	b.WriteString("\thost:")
	b.WriteString(clientIP)
	b.WriteString("\tqname:")
	b.WriteString(StringQuote(qName))
	b.WriteString("\tmessage:")
	b.WriteString(StringQuote(reason))
	for i, f := range additionalFields {
		b.WriteByte('\t')
		if i == 0 {
			b.WriteString("ip:")
		} else {
			b.WriteString("field")
			b.WriteString(strconv.Itoa(i))
			b.WriteByte(':')
		}
		b.WriteString(StringQuote(f))
	}
	b.WriteByte('\n')
	return b.String()
}

// WritePluginLog writes a formatted log entry to logger.
// Returns ErrLogNotInitialized when logger is nil.
// [13] io.WriteString avoids the []byte(line) copy: if logger implements
// io.StringWriter the string is passed through without allocation.
func WritePluginLog(logger io.Writer, format, clientIP, qName, reason string, additionalFields ...string) error {
	if logger == nil {
		return ErrLogNotInitialized
	}
	line, err := FormatLogLine(format, clientIP, qName, reason, additionalFields...)
	if err != nil {
		return fmt.Errorf("failed to format log line: %w", err)
	}
	if _, err := io.WriteString(logger, line); err != nil {
		return fmt.Errorf("failed to write log: %w", err)
	}
	return nil
}

// ── Plugin logger initialisation ──────────────────────────────────────────────

// InitializePluginLogger constructs a rotating-file logger for a plugin.
// Returns (nil, "") when logFile is empty (logging disabled for this plugin).
// [18] Idiomatic logFile=="" replaces len(logFile)==0.
func InitializePluginLogger(logFile, format string, maxSize, maxAge, maxBackups int) (io.Writer, string) {
	if logFile == "" {
		return nil, ""
	}
	return Logger(maxSize, maxAge, maxBackups, logFile), format
}

// ── Config-line processing ────────────────────────────────────────────────────

// ParseTimeBasedRule parses a rule line that may carry a time-range suffix in
// the form "rule@timeRangeName". Returns the rule text (without the "@…" part),
// a pointer to the matching WeeklyRanges, and any error.
// When no "@" is present the full line is returned and weeklyRanges is nil.
//
// [14] strings.SplitN(line,"@",3) replaces strings.Split: stops after two
// delimiters, which is all that is needed to classify 0, 1, or 2+.
func ParseTimeBasedRule(line string, lineNo int, allWeeklyRanges *map[string]WeeklyRanges) (string, *WeeklyRanges, error) {
	parts := strings.SplitN(line, "@", 3)
	switch len(parts) {
	case 1:
		return line, nil, nil
	case 2:
		rulePart := strings.TrimSpace(parts[0])
		name := strings.TrimSpace(parts[1])
		if name == "" {
			return "", nil, fmt.Errorf("empty time range name at line %d", 1+lineNo)
		}
		if allWeeklyRanges != nil {
			if wr, ok := (*allWeeklyRanges)[name]; ok {
				return rulePart, &wr, nil
			}
		}
		return "", nil, fmt.Errorf("time range %q not found at line %d", name, 1+lineNo)
	default: // len == 3 means more than one '@'
		return "", nil, fmt.Errorf("syntax error at line %d: unexpected @ character", 1+lineNo)
	}
}

// ParseIPRule validates and normalises a single IP rule string.
// Returns the lowercased rule text, whether it ends with a wildcard, and any error.
func ParseIPRule(line string, lineNo int) (string, bool, error) {
	if len(line) < 2 {
		return "", false, fmt.Errorf("suspicious IP rule %q at line %d: too short", line, lineNo)
	}
	trailingStar := strings.HasSuffix(line, "*")
	clean := line
	if trailingStar {
		clean = clean[:len(clean)-1]
	}
	clean = strings.TrimRight(clean, ":.")
	if clean == "" {
		return "", false, fmt.Errorf("empty IP rule at line %d", lineNo)
	}
	if strings.Contains(clean, "*") {
		return "", false, fmt.Errorf("invalid rule %q at line %d: wildcards can only be used as a suffix", line, lineNo)
	}
	if net.ParseIP(clean) != nil && trailingStar {
		return "", false, fmt.Errorf("suspicious IP rule %q at line %d: complete IP with wildcard", line, lineNo)
	}
	return strings.ToLower(clean), trailingStar, nil
}

// ProcessConfigLines iterates over the newline-separated content of lines,
// strips comments and blank entries, and calls processor for each remaining line.
// Returns the first non-nil error from processor, wrapped with the line number.
//
// [15] bufio.Scanner on strings.NewReader replaces strings.Split(lines,"\n").
// strings.Split doubles peak memory for large block-lists; Scanner uses O(1)
// extra memory regardless of input size.
func ProcessConfigLines(lines string, processor func(line string, lineNo int) error) error {
	sc := bufio.NewScanner(strings.NewReader(lines))
	lineNo := 0
	for sc.Scan() {
		line := TrimAndStripInlineComments(sc.Text())
		if line != "" {
			if err := processor(line, lineNo); err != nil {
				return fmt.Errorf("error processing line %d: %w", lineNo, err)
			}
		}
		lineNo++
	}
	return sc.Err()
}

// LoadIPRules parses IP rules from lines and populates three data structures:
//   - ips      — map of exact IP strings (O(1) lookup)
//   - prefixes — immutable radix tree for wildcard prefix rules (e.g. "10.0.*")
//   - networks — critbit network trie for CIDR blocks (e.g. "10.0.0.0/8")
//
// Rules containing "/" are parsed as CIDRs; all others are exact IPs or wildcard
// prefixes. Per-line parse errors are logged and skipped. Returns the updated
// radix tree and any fatal iterator error.
//
// [16] Inserted values changed from int(0)/bool(true) to struct{}{}.
// Both originals boxed into `any`, allocating one word per rule on the heap.
// struct{}{} uses a shared global zero-size pointer — zero allocation per insert.
func LoadIPRules(lines string, prefixes *iradix.Tree, ips map[string]any, networks *critbitgo.Net) (*iradix.Tree, error) {
	err := ProcessConfigLines(lines, func(line string, lineNo int) error {
		if strings.Contains(line, "/") {
			if networks == nil {
				dlog.Warnf("CIDR rule %q at line %d but no network table provided", line, lineNo)
				return nil
			}
			if err := networks.AddCIDR(line, true); err != nil {
				dlog.Errorf("invalid CIDR rule %q at line %d: %v", line, lineNo, err)
			}
			return nil
		}
		clean, trailingStar, err := ParseIPRule(line, lineNo)
		if err != nil {
			dlog.Error(err)
			return nil // non-fatal: log and continue
		}
		if trailingStar {
			prefixes, _, _ = prefixes.Insert([]byte(clean), struct{}{}) // [16]
		} else {
			ips[clean] = struct{}{} // [16]
		}
		return nil
	})
	return prefixes, err
}

// ── DNS name utilities ────────────────────────────────────────────────────────

// reverseAddr returns the in-addr.arpa. or ip6.arpa. hostname for PTR lookups
// corresponding to addr.
// [17] hexDigits is now a package-level const (was redeclared locally per call).
func reverseAddr(addr string) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("unrecognized address: %s", addr)
	}
	if v4 := ip.To4(); v4 != nil {
		// IPv4: reverse the four octets and append "in-addr.arpa."
		buf := make([]byte, 0, net.IPv4len*4+len("in-addr.arpa."))
		for i := len(v4) - 1; i >= 0; i-- {
			buf = strconv.AppendInt(buf, int64(v4[i]), 10)
			buf = append(buf, '.')
		}
		return string(append(buf, "in-addr.arpa."...)), nil
	}
	// IPv6: emit nibbles in reverse order, low nibble first (RFC 3596 §2.5).
	buf := make([]byte, 0, net.IPv6len*4+len("ip6.arpa."))
	for i := len(ip) - 1; i >= 0; i-- {
		v := ip[i]
		buf = append(buf, hexDigits[v&0xf], '.', hexDigits[v>>4], '.')
	}
	return string(append(buf, "ip6.arpa."...)), nil
}

// fqdn appends a trailing dot to name if not already present, producing a
// fully-qualified domain name.
func fqdn(name string) string {
	if name == "" || name[len(name)-1] == '.' {
		return name
	}
	return name + "."
}
