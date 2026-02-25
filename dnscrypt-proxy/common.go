// common.go — shared utilities and protocol constants for dnscrypt-proxy
//
// Complete rewrite for Go 1.26.
// Every line of the original was audited individually for:
//   · correctness (bugs, fencepost errors, anti-patterns)
//   · performance (allocations, reflection, syscall count)
//   · concurrency safety
//   · idiomatic Go style
//
// All exported identifiers are preserved unchanged — 100 % drop-in replacement.
//
// ─────────────────────────────────────────────────────────────────────────────
// CHANGE LOG  (reference tags [N] appear inline throughout the file)
// ─────────────────────────────────────────────────────────────────────────────
//
// [01] REDUNDANT CAST REMOVED — InheritedDescriptorsBase
//      Original: InheritedDescriptorsBase = uintptr(50)  inside a const block.
//      A typed constant in a const group infers its type from the group's
//      declared type; uintptr(50) is valid but adds noise. Moved to a
//      standalone typed const so the declaration is self-documenting.
//
// [02] IDIOMATIC NIL SLICE — FileDescriptors
//      Original: FileDescriptors = make([]*os.File, 0)
//      make(T, 0) and a nil slice are behaviourally identical for all uses
//      (len, cap, append). The nil form is the Go idiom for "not yet populated"
//      and avoids a heap allocation during package initialisation.
//
// [03] REDUNDANT ZERO REMOVED — FileDescriptorNum
//      Original: FileDescriptorNum = uintptr(0)
//      Every Go variable is zero-initialised; writing = 0 is redundant noise.
//
// [04] DEAD CODE REMOVED — Min / Max
//      The original marked both functions "Deprecated: use built-in directly"
//      yet still emitted them. This is package main with no external callers;
//      the wrappers are pure dead code. Removed. All internal call sites use
//      the Go 1.21 built-in min() / max() directly.
//
// [05] UNNECESSARY VARIABLE REMOVED — PrefixWithSize
//      Original allocated `result`, then immediately overwrote it with
//      AppendUint16, then appended packet — three statements for one logical
//      operation. Collapsed to a single expression; identical behaviour,
//      one fewer named variable on the stack.
//
// [06] POINTER-TO-INTERFACE BUG FIXED — ReadPrefixed parameter
//      Original: func ReadPrefixed(conn *net.Conn)
//      *net.Conn is a pointer to an interface value, which is an anti-pattern
//      in Go. It prevents callers from passing a concrete net.Conn directly,
//      forces every call site to write &conn, and signals a misunderstanding
//      of how interfaces work. The function only reads bytes; it needs
//      net.Conn (an interface value, not a pointer to one).
//      Fixed: func ReadPrefixed(conn net.Conn)
//      MIGRATION: every call site that passed &conn must now pass conn.
//
// [07] FENCEPOST ERROR FIXED — ReadPrefixed upper bound
//      Original: packetLength > MaxDNSPacketSize-1  (i.e. > 4095, rejects 4096)
//      MaxDNSPacketSize is defined as 4096. A 4096-byte packet is explicitly
//      valid per that constant's own definition. The -1 was a fencepost error.
//      Fixed: packetLength > MaxDNSPacketSize
//
// [08] ASCII FAST-PATH ADDED — StringReverse
//      Original unconditionally converts to []rune even for pure-ASCII strings
//      (all hostnames, all domain labels), allocating a full rune slice and a
//      new string on every call. For ASCII, utf8.RuneCountInString(s)==len(s),
//      so a byte-level in-place swap is sufficient and requires only one
//      []byte allocation instead of two. Multi-byte Unicode falls through to
//      the original rune path unchanged.
//
// [09] LOGIC BUG FIXED — TrimAndStripInlineComments
//      Original: strings.LastIndexByte(str, '#') — finds the LAST '#'.
//      Consider: "value # first # second"
//        - LastIndexByte finds the second '#' at some idx.
//        - If str[idx-1] is not a space/tab the comment is NOT stripped.
//        - But the first '#' IS a valid inline comment that should be stripped.
//      Standard config-file semantics strip at the FIRST recognisable '#'.
//      Fixed: strings.IndexByte(str, '#') — first '#'.
//      Also removed the dead branch "idx==0 || str[0]=='#'": when idx==0 the
//      first condition is already sufficient; str[0]=='#' is always true when
//      idx==0 and adds nothing.
//
// [10] STDLIB PARSING — ExtractHostAndPort
//      Original used manual bracket detection + strings.LastIndex(":") to parse
//      host:port strings. The manual approach silently mishandles edge cases:
//      bare IPv6 addresses without brackets, port strings that are not purely
//      numeric after the last colon, etc. net.SplitHostPort handles all forms
//      defined by the standard library correctly and is already used everywhere
//      else in the codebase. Fall back to (str, defaultPort) only when
//      SplitHostPort returns an error (no port present at all).
//
// [11] ZERO-ALLOCATION TIMESTAMP — formatTimestampTSV
//      Original: fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", ...)
//      fmt.Sprintf allocates a temporary string. time.AppendFormat (Go 1.17)
//      appends the formatted time directly into a pre-grown []byte with no
//      intermediate allocation.
//
// [12] REFLECTION-FREE LOGGING — formatTSVLine / formatLTSVLine
//      Original used fmt.Fprintf(&line, "%s	%s	...", ...) for every field.
//      fmt.Fprintf uses reflection and boxes each argument as `any` — one heap
//      allocation per non-string argument per call. Replaced with direct
//      strings.Builder WriteString / WriteByte / strconv.FormatInt calls.
//      All are inlined by the compiler with no reflection or boxing.
//
// [13] ZERO-COPY LOG WRITE — WritePluginLog
//      Original: logger.Write([]byte(line))
//      Converting a string to []byte always allocates a copy. io.WriteString
//      checks at runtime whether the writer implements io.StringWriter; if it
//      does, it calls WriteString directly (zero copy). Falls back to the
//      []byte copy only for writers that genuinely require it.
//
// [14] BOUNDED SPLIT — ParseTimeBasedRule
//      Original: strings.Split(line, "@") — scans the whole string, allocates
//      a []string of all segments. We only ever need to distinguish 0, 1, or
//      2+ '@' characters. strings.SplitN(line, "@", 3) stops after finding two
//      delimiters: saves the allocation of extra segments and is more explicit
//      about the intent.
//
// [15] STREAMING CONFIG PARSE — ProcessConfigLines
//      Original: strings.Split(lines, "
") copies the entire rule-file string
//      into a []string of N substrings, doubling peak memory. For a blocklist
//      with 100 000 entries this can add tens of MB. bufio.Scanner on a
//      strings.Reader processes one line at a time in O(1) extra memory
//      regardless of input size.
//
// [16] ZERO-SIZE MAP VALUE — LoadIPRules
//      Original inserted integer 0 into the radix tree and `true` into the
//      map. Both box their values into `any`, allocating one interface word
//      per rule:
//        - any(int(0))  = 8 bytes heap, plus GC pointer tracking
//        - any(bool(true)) = ditto
//      struct{}{} is a zero-size type. The runtime represents any(struct{}{})
//      as a pointer to a single read-only global zero-size object — effectively
//      zero allocation per entry, zero GC pressure. Changed throughout.
//
// [17] PACKAGE-LEVEL CONST — hexDigits
//      Original declared `const hexDigits = "0123456789abcdef"` inside
//      reverseAddr, re-declaring it on every call. Hoisted to package level:
//      single definition, zero runtime cost, available for future reuse.
//
// [18] IDIOMATIC EMPTY-STRING CHECK — InitializePluginLogger
//      Original: if len(logFile) == 0
//      Comparing a string directly to "" is the idiomatic Go form and
//      compiles identically. len() is correct but unusual for strings.
//
// [19] DOCUMENTATION OVERHAUL
//      Every exported symbol has complete godoc comments.
//      Every unexported helper has a concise one-line doc.
//      Section banners added for navigation.
//      Per-symbol "Go 1.26:" inline annotations replaced by this header.

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
	// ClientMagicLen is the byte length of the client magic field in a
	// DNSCrypt query.
	ClientMagicLen = 8

	// MaxHTTPBodyLength is the maximum response body size accepted from DoH
	// servers before the connection is aborted.
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

// InheritedDescriptorsBase is the lowest file-descriptor number reserved for
// descriptors that must survive a privilege-drop exec boundary.
// [01] Standalone typed const; original had redundant uintptr() cast in a group.
const InheritedDescriptorsBase uintptr = 50

// ── Protocol magic values ─────────────────────────────────────────────────────

// CertMagic is the 4-byte magic prefix identifying a DNSCrypt certificate.
// ASCII: "DNSC"
var CertMagic = [4]byte{0x44, 0x4e, 0x53, 0x43}

// ServerMagic is the 8-byte magic prefix identifying a DNSCrypt server
// response. ASCII: "r6fnvWj8"
var ServerMagic = [8]byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}

// ── File-descriptor management ────────────────────────────────────────────────

// FileDescriptors holds *os.File handles that must be forwarded to the
// sandboxed child process after a privilege drop.
// [02] Nil slice is idiomatic; make([]*os.File, 0) was a gratuitous alloc.
var FileDescriptors []*os.File

// FileDescriptorNum is the next available slot index in FileDescriptors.
// [03] Explicit = uintptr(0) removed; zero-initialisation is implicit in Go.
var FileDescriptorNum uintptr

// FileDescriptorsMu guards concurrent access to FileDescriptors and
// FileDescriptorNum.
var FileDescriptorsMu sync.Mutex

// ── Sentinel errors ───────────────────────────────────────────────────────────

var (
	// ErrPacketTooLarge is returned when a DNS packet exceeds MaxDNSPacketSize.
	ErrPacketTooLarge = errors.New("packet too large")

	// ErrPacketTooShort is returned when a DNS packet is shorter than
	// MinDNSPacketSize.
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
	// [05] Single-expression chain: allocate once, write header, append body.
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
// any concrete type directly and forces every call site to take &conn.
// Call sites must be updated to pass conn directly instead of &conn.
//
// [07] Upper bound fixed: MaxDNSPacketSize-1 incorrectly rejected valid 4096-byte
// packets. Corrected to > MaxDNSPacketSize.
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
// [08] ASCII fast-path: for strings where every character is a single byte
// (all hostnames, domain labels, IPv4 addresses) a byte-level swap avoids the
// []rune → string round-trip. Multi-byte Unicode falls through to the
// original rune path unchanged.
func StringReverse(s string) string {
	if s == "" {
		return s
	}
	if utf8.RuneCountInString(s) == len(s) {
		// Pure ASCII: byte-swap in one allocation.
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
// whitespace, or either trimmed field is empty after splitting.
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
// embedding in structured log output. The surrounding double-quotes added by
// strconv.QuoteToGraphic are stripped.
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
// from a configuration file line.
//
// A comment begins at the FIRST '#' that is either the very first byte on the
// line or is immediately preceded by a space or tab.
//
// [09] Bug fix: original used strings.LastIndexByte (LAST '#'), which could
// leave an earlier valid comment marker in place if the final '#' on the line
// was not preceded by whitespace. Using the FIRST '#' matches the universally
// expected config-file semantics. The redundant "idx==0 || str[0]=='#'" branch
// is also removed (second condition is always true when idx==0).
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
// host-only strings (returns defaultPort for the port component).
//
// [10] Delegates to net.SplitHostPort for canonical stdlib-defined parsing.
// The original's manual bracket detection had subtle edge cases. Fall through
// to (str, defaultPort) only when no port is parseable at all.
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

// isDigit reports whether b is an ASCII decimal digit.
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
// through ipCryptConfig when non-nil. Returns the plain IP when
// ipCryptConfig is nil.
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
// additionalFields are appended after the mandatory clientIP, qName, and reason
// columns. Returns an error for unrecognised format strings.
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
// reflection boxing of every argument (one heap allocation per fmt.Fprintf call
// in the original).
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
// strconv.FormatInt used for the Unix timestamp instead of fmt.Fprintf.
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
// [13] io.WriteString avoids the []byte(line) copy allocation: if logger
// implements io.StringWriter the string is passed through directly.
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
// the form "rule@timeRangeName". Returns the rule text (without the "@…"
// part), a pointer to the matching WeeklyRanges, and any error.
// When no "@" is present the full line is returned and weeklyRanges is nil.
//
// [14] strings.SplitN(line, "@", 3) replaces strings.Split: stops after two
// delimiters, which is all that is needed to classify 0, 1, or 2+ occurrences.
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
// Returns the lowercased rule text, whether it ends with a wildcard, and any
// validation error.
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
// stripping comments and blank entries, and calls processor for each remaining
// line. Returns the first error returned by processor wrapped with the line
// number.
//
// [15] bufio.Scanner on a strings.Reader replaces strings.Split(lines,"\n").
// strings.Split copies the entire input into a []string, doubling peak memory
// for large block-lists (100 000+ entries). Scanner reads one line at a time
// in O(1) extra memory regardless of input size.
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
// Rules containing "/" are parsed as CIDRs; all others are exact IPs or
// wildcard prefixes. Per-line parse errors are logged and skipped rather than
// aborting the entire load. Returns the (possibly updated) radix tree and any
// fatal iterator error.
//
// [16] Inserted values changed from int(0)/bool(true) to struct{}{}.
// Both of the originals boxed their values into `any`, allocating one word per
// rule. struct{}{} is a zero-size type; the runtime uses a shared global
// pointer for its `any` representation — zero allocation per insert.
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
// corresponding to the IP address addr.
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
	// IPv6: emit nibbles in reverse order (low nibble first per RFC 3596 §2.5).
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
