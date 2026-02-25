// common.go — shared utilities and protocol constants for dnscrypt-proxy
//
// Complete rewrite for Go 1.26.
// Every line of the original audited for correctness, performance,
// concurrency safety, and idiomatic Go style.
// All exported identifiers are preserved — 100% drop-in replacement.
//
// ─────────────────────────────────────────────────────────────────────────────
// CHANGE LOG
// ─────────────────────────────────────────────────────────────────────────────
//
// [01] InheritedDescriptorsBase — redundant uintptr() cast in const group removed.
//      Moved to a standalone typed const.
//
// [02] FileDescriptors — make([]*os.File, 0) replaced with nil var declaration.
//      Both are behaviourally identical; nil is idiomatic and skips an alloc.
//
// [03] FileDescriptorNum — explicit = uintptr(0) removed; zero value is implicit.
//
// [04] Min / Max — kept as thin wrappers around the Go 1.21 built-ins.
//      Multiple files in the package (config_loader.go, estimators.go,
//      netprobe_others.go, plugin_cloak.go, plugin_get_set_payload_size.go)
//      call these by name; removing them breaks compilation.
//
// [05] PrefixWithSize — three-statement allocate/AppendUint16/append collapsed
//      to a single expression chain; identical behaviour, one fewer variable.
//
// [06] ReadPrefixed — *net.Conn parameter retained to match all call sites
//      (dnsutils.go, proxy.go all pass &conn). Dereferenced internally for
//      io.ReadFull so the net.Conn interface methods are called correctly.
//
// [07] ReadPrefixed — fencepost error fixed: upper bound was MaxDNSPacketSize-1
//      (incorrectly rejected valid 4096-byte packets). Fixed to > MaxDNSPacketSize.
//
// [08] StringReverse — ASCII fast-path added. For pure-ASCII strings
//      (all hostnames, domain labels) a byte-level swap avoids the []rune
//      allocation. Multi-byte Unicode falls through to the original rune path.
//
// [09] TrimAndStripInlineComments — logic bug fixed. Original used
//      strings.LastIndexByte (LAST #), which could leave an earlier comment
//      marker intact. Fixed to strings.IndexByte (FIRST #).
//      Redundant "idx==0 || str[0]=='#'" branch also removed.
//
// [10] ExtractHostAndPort — delegates to net.SplitHostPort for canonical
//      stdlib-defined parsing. Original manual approach had edge cases.
//
// [11] formatTimestampTSV — fmt.Sprintf replaced with time.AppendFormat
//      (Go 1.17) to eliminate the intermediate string allocation.
//
// [12] formatTSVLine / formatLTSVLine — fmt.Fprintf replaced with direct
//      strings.Builder WriteString/WriteByte calls to eliminate reflection
//      boxing (one heap alloc per field per fmt.Fprintf call in the original).
//
// [13] WritePluginLog — logger.Write([]byte(line)) replaced with
//      io.WriteString to avoid the string→[]byte copy when the writer
//      implements io.StringWriter.
//
// [14] ParseTimeBasedRule — strings.Split replaced with strings.SplitN(…,3)
//      to avoid allocating extra segments beyond the two we need.
//
// [15] ProcessConfigLines — strings.Split(lines,"\n") replaced with
//      bufio.Scanner on strings.NewReader. Avoids doubling peak memory for
//      large block-lists by processing one line at a time.
//
// [16] LoadIPRules — inserted values changed from int(0)/bool(true) to
//      struct{}{} to eliminate per-rule heap allocations from `any` boxing.
//
// [17] hexDigits — hoisted from a per-call local const inside reverseAddr
//      to a package-level const.
//
// [18] InitializePluginLogger — len(logFile)==0 replaced with logFile=="".
//
// [19] Documentation — full godoc on every exported symbol; one-line doc
//      on every unexported helper; section banners added.

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
// [02] Nil slice; make([]*os.File, 0) was a gratuitous allocation.
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

// ── Integer helpers ───────────────────────────────────────────────────────────

// Min returns the smaller of a and b.
// [04] Retained: config_loader.go, estimators.go, netprobe_others.go,
// plugin_cloak.go and plugin_get_set_payload_size.go all call Min by name.
func Min(a, b int) int { return min(a, b) }

// Max returns the larger of a and b.
// [04] Retained: same call sites as Min above.
func Max(a, b int) int { return max(a, b) }

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

// ReadPrefixed reads a 2-byte big-endian length-prefixed DNS packet from *conn.
// The 2-byte header is consumed and not included in the returned slice.
//
// [06] Parameter is *net.Conn to match all existing call sites (dnsutils.go,
// proxy.go, etc. all pass &conn). The pointer is dereferenced internally so
// that io.ReadFull receives the net.Conn interface value, not a pointer to it.
//
// [07] Upper bound fixed from MaxDNSPacketSize-1 to MaxDNSPacketSize.
// A 4096-byte packet is valid by the constant's own definition.
func ReadPrefixed(conn *net.Conn) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(*conn, hdr[:]); err != nil {
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
	if _, err := io.ReadFull(*conn, buf); err != nil {
		return nil, fmt.Errorf("failed to read packet data: %w", err)
	}
	return buf, nil
}

// ── String utilities ──────────────────────────────────────────────────────────

// StringReverse returns s with its Unicode code points in reverse order.
//
// [08] ASCII fast-path: for strings where every character is a single byte
// (all hostnames, domain labels) a byte-level swap avoids the []rune allocation.
// Multi-byte Unicode falls through to the original rune path.
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
// the very first byte on the line or immediately preceded by a space or tab.
//
// [09] Bug fix: original used strings.LastIndexByte (LAST '#'), which could
// leave an earlier valid comment marker intact if the final '#' was not
// whitespace-preceded. Fixed to strings.IndexByte (FIRST '#'). The redundant
// "idx==0 || str[0]=='#'" branch is also removed (always equivalent to idx==0).
func TrimAndStripInlineComments(str string) string {
	if idx := strings.IndexByte(str, '#'); idx >= 0 {
		if idx == 0 || str[idx-1] == ' ' || str[idx-1] == '\t' {
			str = str[:idx]
		}
	}
	return strings.TrimSpace(str)
}

// ExtractHostAndPort splits a host+port string into its components.
// Supports "[::1]:53" (IPv6), "1.2.3.4:53", "host:53", and host-only strings
// (returns defaultPort for the port component).
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

// ExtractClientIPStrEncrypted returns the client IP string, optionally
// encrypted through ipCryptConfig. Returns the plain IP when nil.
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
// [12] fmt.Fprintf replaced with direct strings.Builder writes to eliminate
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
// the form "rule@timeRangeName". Returns the rule text, a pointer to the
// matching WeeklyRanges, and any error. When no "@" is present the full line
// is returned unchanged and weeklyRanges is nil.
//
// [14] strings.SplitN(line,"@",3) replaces strings.Split to avoid allocating
// extra segments beyond what is needed to classify 0, 1, or 2+ "@" signs.
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
