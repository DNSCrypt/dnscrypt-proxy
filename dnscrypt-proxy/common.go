package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode"

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

func ExtractHostAndPort(str string, defaultPort int) (host string, port int) {
	host, port = str, defaultPort
	if idx := strings.LastIndex(str, ":"); idx >= 0 && idx < len(str)-1 {
		if portX, err := strconv.Atoi(str[idx+1:]); err == nil {
			host, port = host[:idx], portX
		}
	}
	return
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

func maybeWritableByOtherUsers(p string) (bool, string, error) {
	p = path.Clean(p)
	for p != "/" && p != "." {
		st, err := os.Stat(p)
		if err != nil {
			return false, p, err
		}
		mode := st.Mode()
		if mode&2 == 2 && !(st.IsDir() && mode&01000 == 01000) {
			return true, p, nil
		}
		p = path.Dir(p)
	}
	return false, "", nil
}

func WarnIfMaybeWritableByOtherUsers(p string) {
	if ok, px, err := maybeWritableByOtherUsers(p); ok {
		if px == p {
			dlog.Criticalf("[%s] is writable by other system users - If this is not intentional, it is recommended to fix the access permissions", p)
		} else {
			dlog.Warnf("[%s] can be modified by other system users because [%s] is writable by other users - If this is not intentional, it is recommended to fix the access permissions", p, px)
		}
	} else if err != nil {
		dlog.Warnf("Error while checking if [%s] is accessible: [%s] : [%s]", p, px, err)
	}
}
