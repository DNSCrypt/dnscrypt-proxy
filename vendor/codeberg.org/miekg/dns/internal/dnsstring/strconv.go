package dnsstring

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

func AtoiUint8(s string) (uint8, error) {
	i, err := strconv.Atoi(s)
	if i < 0 {
		return 0, strconv.ErrRange
	}
	return uint8(i), err
}

func AtoiUint16(s string) (uint16, error) {
	i, err := strconv.Atoi(s)
	if i < 0 {
		return 0, strconv.ErrRange
	}
	return uint16(i), err
}

func AtoiUint32(s string) (uint32, error) {
	i, err := strconv.Atoi(s)
	if i < 0 {
		return 0, strconv.ErrRange
	}
	return uint32(i), err
}

func AtoiUint64(s string) (uint64, error) {
	i, err := strconv.ParseUint(s, 10, 64)
	return i, err
}

func ToTime(s string) (int64, error) {
	if len(s) != 14 {
		return 0, errors.New("timestamp must be exactly 14 characters")
	}
	digit := func(b byte) int { return int(b - '0') }

	year := 1000*digit(s[0]) + 100*digit(s[1]) + 10*digit(s[2]) + digit(s[3])
	month := 10*digit(s[4]) + digit(s[5])
	day := 10*digit(s[6]) + digit(s[7])
	hour := 10*digit(s[8]) + digit(s[9])
	minute := 10*digit(s[10]) + digit(s[11])
	second := 10*digit(s[12]) + digit(s[13])

	if year < 1 ||
		month < 1 || month > 12 ||
		day < 1 || day > 31 ||
		hour > 23 || minute > 59 || second > 59 {
		return 0, errors.New("timestamp contains out-of-range values")
	}

	return time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC).Unix(), nil
}

// Parse a 64 bit-like ipv6 address: "0014:4fff:ff20:ee64" Used for NID and L64 record.
func ToNodeID(s string) (uint64, error) {
	if len(s) < 19 {
		return 0, fmt.Errorf("bad NID")
	}
	// There must be three colons at fixes positions, if not its a parse error
	if s[4] != ':' && s[9] != ':' && s[14] != ':' {
		return 0, fmt.Errorf("bad NID")
	}
	s = s[0:4] + s[5:9] + s[10:14] + s[15:19]
	u, err := strconv.ParseUint(s, 16, 64)
	return u, err
}
