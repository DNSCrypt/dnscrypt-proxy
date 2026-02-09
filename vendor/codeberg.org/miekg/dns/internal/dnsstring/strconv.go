package dnsstring

import (
	"errors"
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

func ToTime(s string) (time.Time, error) {
	if len(s) != 14 {
		return time.Time{}, errors.New("timestamp must be exactly 14 characters")
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
		return time.Time{}, errors.New("timestamp contains out-of-range values")
	}

	return time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC), nil
}
