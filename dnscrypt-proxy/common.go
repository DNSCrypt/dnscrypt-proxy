package main

import (
    "bufio"
    "bytes"
    "encoding/binary"
    "errors"
    "fmt"
    "io"
    "iter"
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

// PacketBufferPool reuses 4KB buffers to eliminate GC pressure.
var PacketBufferPool = sync.Pool{
    New: func() interface{} {
        b := make([]byte, 2+MaxDNSPacketSize)
        return &b
    },
}

const (
    InheritedDescriptorsBase = uintptr(50)
)

func PrefixWithSize(packet []byte) ([]byte, error) {
    packetLen := len(packet)
    if packetLen > 0xffff {
        return packet, errors.New("Packet too large")
    }
    out := make([]byte, 2+packetLen)
    binary.BigEndian.PutUint16(out[0:2], uint16(packetLen))
    copy(out[2:], packet)
    return out, nil
}

func ReadPrefixed(conn *net.Conn) ([]byte, error) {
    ptr := PacketBufferPool.Get().(*[]byte)
    buf := *ptr

    packetLength, pos := -1, 0
    for {
        readnb, err := (*conn).Read(buf[pos:])
        if err != nil {
            PacketBufferPool.Put(ptr)
            return nil, err
        }
        pos += readnb
        if pos >= 2 && packetLength < 0 {
            packetLength = int(binary.BigEndian.Uint16(buf[0:2]))
            if packetLength > MaxDNSPacketSize-1 {
                PacketBufferPool.Put(ptr)
                return nil, errors.New("Packet too large")
            }
            if packetLength < MinDNSPacketSize {
                PacketBufferPool.Put(ptr)
                return nil, errors.New("Packet too short")
            }
        }
        if packetLength >= 0 && pos >= 2+packetLength {
            result := make([]byte, packetLength)
            copy(result, buf[2:2+packetLength])
            PacketBufferPool.Put(ptr)
            return result, nil
        }
    }
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
    var sb strings.Builder
    sb.Grow(len(str))
    for _, r := range str {
        if !unicode.IsSpace(r) {
            sb.WriteRune(r)
        }
    }
    return sb.String()
}

func TrimAndStripInlineComments(str string) string {
    if before, _, found := strings.Cut(str, "#"); found {
        if len(before) > 0 {
            idx := len(before)
            if idx > 0 {
                if prev := before[idx-1]; prev == ' ' || prev == '\t' {
                    str = before[:idx-1]
                } else {
                    str = before
                }
            } else {
                return ""
            }
        } else {
            return ""
        }
    }
    return strings.TrimSpace(str)
}

func ExtractHostAndPort(str string, defaultPort int) (host string, port int) {
    host, port = str, defaultPort
    if idx := strings.LastIndexByte(str, ':'); idx >= 0 && idx < len(str)-1 {
        if portX, err := strconv.Atoi(str[idx+1:]); err == nil {
            host, port = host[:idx], portX
        }
    }
    return host, port
}

func ReadTextFile(filename string) (string, error) {
    bin, err := os.ReadFile(filename)
    if err != nil {
        return "", err
    }
    bin = bytes.TrimPrefix(bin, []byte{0xef, 0xbb, 0xbf})
    return string(bin), nil
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

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

func ExtractClientIPStrEncrypted(pluginsState *PluginsState, ipCryptConfig *IPCryptConfig) (string, bool) {
    ipStr, ok := ExtractClientIPStr(pluginsState)
    if !ok || ipCryptConfig == nil {
        return ipStr, ok
    }
    return ipCryptConfig.EncryptIPString(ipStr), ok
}

// FormatLogLine optimized with strings.Builder and safe multi-line syntax.
func FormatLogLine(format, clientIP, qName, reason string, additionalFields ...string) (string, error) {
    var sb strings.Builder
    sb.Grow(128 + len(qName) + len(reason))

    if format == "tsv" {
        now := time.Now()
        year, month, day := now.Date()
        hour, minute, second := now.Clock()

        sb.WriteByte('[')
        sb.WriteString(strconv.Itoa(year))
        sb.WriteByte('-')
        if month < 10 {
            sb.WriteByte('0')
        }
        sb.WriteString(strconv.Itoa(int(month)))
        sb.WriteByte('-')
        if day < 10 {
            sb.WriteByte('0')
        }
        sb.WriteString(strconv.Itoa(day))
        sb.WriteByte(' ')
        if hour < 10 {
            sb.WriteByte('0')
        }
        sb.WriteString(strconv.Itoa(hour))
        sb.WriteByte(':')
        if minute < 10 {
            sb.WriteByte('0')
        }
        sb.WriteString(strconv.Itoa(minute))
        sb.WriteByte(':')
        if second < 10 {
            sb.WriteByte('0')
        }
        sb.WriteString(strconv.Itoa(second))
        sb.WriteByte(']')
        sb.WriteByte('\t')

        sb.WriteString(clientIP)
        sb.WriteByte('\t')
        sb.WriteString(StringQuote(qName))
        sb.WriteByte('\t')
        sb.WriteString(StringQuote(reason))

        for _, field := range additionalFields {
            sb.WriteByte('\t')
            sb.WriteString(StringQuote(field))
        }
        sb.WriteByte('
')
        return sb.String(), nil

    } else if format == "ltsv" {
        sb.WriteString("time:")
        sb.WriteString(strconv.FormatInt(time.Now().Unix(), 10))
        sb.WriteString("\thost:")
        sb.WriteString(clientIP)
        sb.WriteString("\tqname:")
        sb.WriteString(StringQuote(qName))
        sb.WriteString("\tmessage:")
        sb.WriteString(StringQuote(reason))

        for i, field := range additionalFields {
            sb.WriteByte('\t')
            if i == 0 {
                sb.WriteString("ip:")
            } else {
                sb.WriteString("field")
                sb.WriteString(strconv.Itoa(i))
                sb.WriteByte(':')
            }
            sb.WriteString(StringQuote(field))
        }
        sb.WriteByte('
')
        return sb.String(), nil
    }
    return "", fmt.Errorf("unexpected log format: [%s]", format)
}

func WritePluginLog(logger io.Writer, format, clientIP, qName, reason string, additionalFields ...string) error {
    if logger == nil {
        return errors.New("Log file not initialized")
    }

    line, err := FormatLogLine(format, clientIP, qName, reason, additionalFields...)
    if err != nil {
        return err
    }

    _, err = logger.Write([]byte(line))
    return err
}

func ParseTimeBasedRule(line string, lineNo int, allWeeklyRanges *map[string]WeeklyRanges) (rulePart string, weeklyRanges *WeeklyRanges, err error) {
    before, after, found := strings.Cut(line, "@")

    if found {
        rulePart = strings.TrimSpace(before)
        timeRangeName := strings.TrimSpace(after)

        if strings.Contains(after, "@") {
            return "", nil, fmt.Errorf("syntax error at line %d -- Unexpected @ character", 1+lineNo)
        }

        if len(timeRangeName) > 0 {
            if weeklyRangesX, ok := (*allWeeklyRanges)[timeRangeName]; ok {
                weeklyRanges = &weeklyRangesX
            } else {
                return "", nil, fmt.Errorf("time range [%s] not found at line %d", timeRangeName, 1+lineNo)
            }
        }
    } else {
        rulePart = line
    }

    return rulePart, weeklyRanges, nil
}

func ParseIPRule(line string, lineNo int) (cleanLine string, trailingStar bool, err error) {
    if len(line) < 2 {
        return "", false, fmt.Errorf("suspicious IP rule [%s] at line %d", line, lineNo)
    }

    trailingStar = line[len(line)-1] == '*'

    ip := net.ParseIP(line)

    if ip != nil && trailingStar {
        return "", false, fmt.Errorf("suspicious IP rule [%s] at line %d", line, lineNo)
    }

    cleanLine = line
    if trailingStar {
        cleanLine = cleanLine[:len(cleanLine)-1]
    }

    if len(cleanLine) == 0 {
        return "", false, fmt.Errorf("empty IP rule at line %d", lineNo)
    }

    lastChar := cleanLine[len(cleanLine)-1]
    if lastChar == ':' || lastChar == '.' {
        cleanLine = cleanLine[:len(cleanLine)-1]
    }

    if strings.Contains(cleanLine, "*") {
        return "", false, fmt.Errorf("invalid rule: [%s] - wildcards can only be used as a suffix at line %d", line, lineNo)
    }

    return strings.ToLower(cleanLine), trailingStar, nil
}

// ProcessConfigLines uses Go 1.23+ iterators.
func ProcessConfigLines(lines string) iter.Seq2[string, int] {
    return func(yield func(string, int) bool) {
        scanner := bufio.NewScanner(strings.NewReader(lines))
        lineNo := 0
        for scanner.Scan() {
            line := scanner.Text()
            line = TrimAndStripInlineComments(line)
            if len(line) > 0 {
                if !yield(line, lineNo) {
                    return
                }
            }
            lineNo++
        }
    }
}

func LoadIPRules(lines string, prefixes *iradix.Tree, ips map[string]interface{}) (*iradix.Tree, error) {
    for line, lineNo := range ProcessConfigLines(lines) {
        cleanLine, trailingStar, lineErr := ParseIPRule(line, lineNo)
        if lineErr != nil {
            dlog.Error(lineErr)
            continue
        }

        if trailingStar {
            prefixes, _, _ = prefixes.Insert([]byte(cleanLine), 0)
        } else {
            ips[cleanLine] = true
        }
    }
    return prefixes, nil
}

func InitializePluginLogger(logFile, format string, maxSize, maxAge, maxBackups int) (io.Writer, string) {
    if len(logFile) > 0 {
        return Logger(maxSize, maxAge, maxBackups, logFile), format
    }
    return nil, ""
}

func reverseAddr(addr string) (string, error) {
    ip := net.ParseIP(addr)
    if ip == nil {
        return "", errors.New("unrecognized address: " + addr)
    }

    var sb strings.Builder
    if v4 := ip.To4(); v4 != nil {
        sb.Grow(30)
        for i := len(v4) - 1; i >= 0; i-- {
            sb.WriteString(strconv.Itoa(int(v4[i])))
            sb.WriteByte('.')
        }
        sb.WriteString("in-addr.arpa.")
        return sb.String(), nil
    }

    const hexDigits = "0123456789abcdef"
    sb.Grow(75)
    for i := len(ip) - 1; i >= 0; i-- {
        v := ip[i]
        sb.WriteByte(hexDigits[v&0xF])
        sb.WriteByte('.')
        sb.WriteByte(hexDigits[v>>4])
        sb.WriteByte('.')
    }
    sb.WriteString("ip6.arpa.")
    return sb.String(), nil
}

func fqdn(name string) string {
    if len(name) == 0 || name[len(name)-1] == '.' {
        return name
    }
    return name + "."
}
