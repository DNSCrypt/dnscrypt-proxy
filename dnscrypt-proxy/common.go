package main

import (
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

	iradix "github.com/hashicorp/go-immutable-radix"
	"github.com/jedisct1/dlog"
)

type CryptoConstruction uint16

const (
	UndefinedConstruction CryptoConstruction = iota
	XSalsa20Poly1305
	XChacha20Poly1305
)

const (
	ClientMagicLen = 8
)

const (
	MaxHTTPBodyLength = 1000000
)

var (
	CertMagic               = [4]byte{0x44, 0x4e, 0x53, 0x43}
	ServerMagic             = [8]byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
	MinDNSPacketSize        = 12 + 5
	MaxDNSPacketSize        = 4096
	MaxDNSUDPPacketSize     = 4096
	MaxDNSUDPSafePacketSize = 1252
	InitialMinQuestionSize  = 512
)

var (
	FileDescriptors   = make([]*os.File, 0)
	FileDescriptorNum = uintptr(0)
	FileDescriptorsMu sync.Mutex
)

const (
	InheritedDescriptorsBase = uintptr(50)
)

func PrefixWithSize(packet []byte) ([]byte, error) {
	packetLen := len(packet)
	if packetLen > 0xffff {
		return packet, errors.New("Packet too large")
	}
	packet = append(append(packet, 0), 0)
	copy(packet[2:], packet[:len(packet)-2])
	binary.BigEndian.PutUint16(packet[0:2], uint16(len(packet)-2))
	return packet, nil
}

func ReadPrefixed(conn *net.Conn) ([]byte, error) {
	buf := make([]byte, 2+MaxDNSPacketSize)
	packetLength, pos := -1, 0
	for {
		readnb, err := (*conn).Read(buf[pos:])
		if err != nil {
			return buf, err
		}
		pos += readnb
		if pos >= 2 && packetLength < 0 {
			packetLength = int(binary.BigEndian.Uint16(buf[0:2]))
			if packetLength > MaxDNSPacketSize-1 {
				return buf, errors.New("Packet too large")
			}
			if packetLength < MinDNSPacketSize {
				return buf, errors.New("Packet too short")
			}
		}
		if packetLength >= 0 && pos >= 2+packetLength {
			return buf[2 : 2+packetLength], nil
		}
	}
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func StringReverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func StringTwoFields(str string) (string, string, bool) {
	if len(str) < 3 {
		return "", "", false
	}
	pos := strings.IndexFunc(str, unicode.IsSpace)
	if pos == -1 {
		return "", "", false
	}
	a, b := strings.TrimSpace(str[:pos]), strings.TrimSpace(str[pos+1:])
	if len(a) == 0 || len(b) == 0 {
		return a, b, false
	}
	return a, b, true
}

func StringQuote(str string) string {
	str = strconv.QuoteToGraphic(str)
	return str[1 : len(str)-1]
}

func StringStripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}

func TrimAndStripInlineComments(str string) string {
	if idx := strings.LastIndexByte(str, '#'); idx >= 0 {
		if idx == 0 || str[0] == '#' {
			return ""
		}
		if prev := str[idx-1]; prev == ' ' || prev == '\t' {
			str = str[:idx-1]
		}
	}
	return strings.TrimSpace(str)
}

// ExtractHostAndPort parses a string containing a host and optional port.
// If no port is present or cannot be parsed, the defaultPort is returned.
func ExtractHostAndPort(str string, defaultPort int) (host string, port int) {
	hostStr, portStr, err := net.SplitHostPort(str)
	if err != nil {
		// Likely missing port or malformed.
		// Treat entire string as host.
        // Strip brackets if they exist (e.g. [::1])
        if len(str) > 0 && str[0] == '[' && str[len(str)-1] == ']' {
            return str[1 : len(str)-1], defaultPort
        }
		return str, defaultPort
	}

	if p, err := strconv.Atoi(portStr); err == nil {
		return hostStr, p
	}
	return hostStr, defaultPort
}

// ReadTextFile reads a file and returns its contents as a string.
// It automatically removes UTF-8 BOM if present.
func ReadTextFile(filename string) (string, error) {
	bin, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	// Remove UTF-8 BOM if present
	bin = bytes.TrimPrefix(bin, []byte{0xef, 0xbb, 0xbf})
	return string(bin), nil
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// ExtractClientIPStr extracts client IP string from pluginsState based on protocol
func ExtractClientIPStr(pluginsState *PluginsState) (string, bool) {
	if pluginsState.clientAddr == nil {
		return "", false
	}
	switch pluginsState.clientProto {
	case "udp":
		return (*pluginsState.clientAddr).(*net.UDPAddr).IP.String(), true
	case "tcp", "local_doh":
		return (*pluginsState.clientAddr).(*net.TCPAddr).IP.String(), true
	default:
		return "", false
	}
}

// ExtractClientIPStrEncrypted extracts and optionally encrypts client IP string
func ExtractClientIPStrEncrypted(pluginsState *PluginsState, ipCryptConfig *IPCryptConfig) (string, bool) {
	ipStr, ok := ExtractClientIPStr(pluginsState)
	if !ok || ipCryptConfig == nil {
		return ipStr, ok
	}
	return ipCryptConfig.EncryptIPString(ipStr), ok
}

// FormatLogLine formats a log line based on the specified format (tsv or ltsv)
func FormatLogLine(format, clientIP, qName, reason string, additionalFields ...string) (string, error) {
	if format == "tsv" {
		now := time.Now()
		year, month, day := now.Date()
		hour, minute, second := now.Clock()
		tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d]", year, int(month), day, hour, minute, second)

		line := fmt.Sprintf("%s\t%s\t%s\t%s", tsStr, clientIP, StringQuote(qName), StringQuote(reason))
		for _, field := range additionalFields {
			line += fmt.Sprintf("\t%s", StringQuote(field))
		}
		return line + "\n", nil
	} else if format == "ltsv" {
		line := fmt.Sprintf("time:%d\thost:%s\tqname:%s\tmessage:%s", time.Now().Unix(), clientIP, StringQuote(qName), StringQuote(reason))

		// For LTSV format, additional fields are added with specific labels
		for i, field := range additionalFields {
			if i == 0 {
				line += fmt.Sprintf("\tip:%s", StringQuote(field))
			} else {
				line += fmt.Sprintf("\tfield%d:%s", i, StringQuote(field))
			}
		}
		return line + "\n", nil
	}
	return "", fmt.Errorf("unexpected log format: [%s]", format)
}

// WritePluginLog writes a log entry for plugin actions
func WritePluginLog(logger io.Writer, format, clientIP, qName, reason string, additionalFields ...string) error {
	if logger == nil {
		return errors.New("Log file not initialized")
	}

	line, err := FormatLogLine(format, clientIP, qName, reason, additionalFields...)
	if err != nil {
		return err
	}

	_, err = io.WriteString(logger, line)
	return err
}

// ParseTimeBasedRule parses a rule line that may contain time-based restrictions (@timerange)
func ParseTimeBasedRule(line string, lineNo int, allWeeklyRanges *map[string]WeeklyRanges) (rulePart string, weeklyRanges *WeeklyRanges, err error) {
	rulePart, timeRangeName, found := strings.Cut(line, "@")

	if !found {
		// No @ symbol found
		rulePart = line
	} else {
		// Found @
		rulePart = strings.TrimSpace(rulePart)
		timeRangeName = strings.TrimSpace(timeRangeName)

		if strings.Contains(timeRangeName, "@") {
             // If there's another @, that's the "Unexpected @ character" error case
             return "", nil, fmt.Errorf("syntax error at line %d -- Unexpected @ character", 1+lineNo)
        }
	}

	if len(timeRangeName) > 0 {
		if weeklyRangesX, ok := (*allWeeklyRanges)[timeRangeName]; ok {
			weeklyRanges = &weeklyRangesX
		} else {
			return "", nil, fmt.Errorf("time range [%s] not found at line %d", timeRangeName, 1+lineNo)
		}
	}

	return rulePart, weeklyRanges, nil
}

// ParseIPRule parses and validates an IP rule line
func ParseIPRule(line string, lineNo int) (cleanLine string, trailingStar bool, err error) {
	ip := net.ParseIP(line)
	trailingStar = strings.HasSuffix(line, "*")

	if len(line) < 2 || (ip != nil && trailingStar) {
		return "", false, fmt.Errorf("suspicious IP rule [%s] at line %d", line, lineNo)
	}

	cleanLine = line
	if trailingStar {
		cleanLine = cleanLine[:len(cleanLine)-1]
	}
	if strings.HasSuffix(cleanLine, ":") || strings.HasSuffix(cleanLine, ".") {
		cleanLine = cleanLine[:len(cleanLine)-1]
	}
	if len(cleanLine) == 0 {
		return "", false, fmt.Errorf("empty IP rule at line %d", lineNo)
	}
	if strings.Contains(cleanLine, "*") {
		return "", false, fmt.Errorf("invalid rule: [%s] - wildcards can only be used as a suffix at line %d", line, lineNo)
	}

	return strings.ToLower(cleanLine), trailingStar, nil
}

// ProcessConfigLines processes configuration file lines, calling the processor function for each non-empty line
func ProcessConfigLines(lines string, processor func(line string, lineNo int) error) error {
	for lineNo, line := range strings.Split(lines, "\n") {
		line = TrimAndStripInlineComments(line)
		if len(line) == 0 {
			continue
		}
		if err := processor(line, lineNo); err != nil {
			return err
		}
	}
	return nil
}

// LoadIPRules loads IP rules from text lines into radix tree and map structures
func LoadIPRules(lines string, prefixes *iradix.Tree, ips map[string]interface{}) (*iradix.Tree, error) {
	err := ProcessConfigLines(lines, func(line string, lineNo int) error {
		cleanLine, trailingStar, lineErr := ParseIPRule(line, lineNo)
		if lineErr != nil {
			dlog.Error(lineErr)
			return nil // Continue processing (matching existing behavior)
		}

		if trailingStar {
			prefixes, _, _ = prefixes.Insert([]byte(cleanLine), 0)
		} else {
			ips[cleanLine] = true
		}
		return nil
	})
	return prefixes, err
}

// InitializePluginLogger initializes a logger for a plugin if the log file is configured
func InitializePluginLogger(logFile, format string, maxSize, maxAge, maxBackups int) (io.Writer, string) {
	if len(logFile) > 0 {
		return Logger(maxSize, maxAge, maxBackups, logFile), format
	}
	return nil, ""
}

// reverseAddr returns the in-addr.arpa. or ip6.arpa. hostname of the IP
// address suitable for reverse DNS (PTR) record lookups.
func reverseAddr(addr string) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", errors.New("unrecognized address: " + addr)
	}
	if v4 := ip.To4(); v4 != nil {
		buf := make([]byte, 0, net.IPv4len*4+len("in-addr.arpa."))
		for i := len(v4) - 1; i >= 0; i-- {
			buf = strconv.AppendInt(buf, int64(v4[i]), 10)
			buf = append(buf, '.')
		}
		buf = append(buf, "in-addr.arpa."...)
		return string(buf), nil
	}
	// Must be IPv6
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, 0, net.IPv6len*4+len("ip6.arpa."))
	for i := len(ip) - 1; i >= 0; i-- {
		v := ip[i]
		buf = append(buf, hexDigits[v&0xF], '.', hexDigits[v>>4], '.')
	}
	buf = append(buf, "ip6.arpa."...)
	return string(buf), nil
}

// fqdn returns the fully qualified domain name (with trailing dot)
func fqdn(name string) string {
	if len(name) == 0 || name[len(name)-1] == '.' {
		return name
	}
	return name + "."
}
