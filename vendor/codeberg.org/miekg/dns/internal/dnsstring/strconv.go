package dnsstring

import "strconv"

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
