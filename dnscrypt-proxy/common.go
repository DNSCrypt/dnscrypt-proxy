package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unicode"
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
	MaxHTTPBodyLength = 4000000
)

var (
	CertMagic              = [4]byte{0x44, 0x4e, 0x53, 0x43}
	ServerMagic            = [8]byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
	MinDNSPacketSize       = 12 + 5
	MaxDNSPacketSize       = 4096
	MaxDNSUDPPacketSize    = 1252
	InitialMinQuestionSize = 256
)

var (
	FileDescriptors   = make([]*os.File, 0)
	FileDescriptorNum = 0
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

func MinF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func MaxF(a, b float64) float64 {
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
	a, b := strings.TrimFunc(str[:pos], unicode.IsSpace), strings.TrimFunc(str[pos+1:], unicode.IsSpace)
	if len(a) == 0 || len(b) == 0 {
		return a, b, false
	}
	return a, b, true
}

func StringQuote(str string) string {
	str = strconv.QuoteToGraphic(str)
	return str[1 : len(str)-1]
}

func ExtractPort(str string, defaultPort int) int {
	port := defaultPort
	if idx := strings.LastIndex(str, ":"); idx >= 0 && idx < len(str)-1 {
		if portX, err := strconv.Atoi(str[idx+1:]); err == nil {
			port = portX
		}
	}
	return port
}

func ExtractHost(str string) string {
	if idx := strings.LastIndex(str, ":"); idx >= 0 && idx < len(str)-1 {
		if _, err := strconv.Atoi(str[idx+1:]); err == nil {
			str = str[:idx]
		}
	}
	return str
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

func MemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("Alloc = %v MiB", m.Alloc/1024/1024)
	fmt.Printf("\tTotalAlloc = %v MiB", m.TotalAlloc/1024/1024)
	fmt.Printf("\tSys = %v MiB", m.Sys/1024/1024)
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func ReadTextFile(filename string) (string, error) {
	bin, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	bin = bytes.TrimPrefix(bin, []byte{0xef, 0xbb, 0xbf})
	return string(bin), nil
}
