package rdata

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns/internal/ddd"
	"codeberg.org/miekg/dns/internal/dnsstring"
)

// cmToM takes a cm value expressed in RFC 1876 SIZE mantissa/exponent
// format and returns a string in m (two decimals for the cm).
func cmToM(x uint8) string {
	m := x & 0xF0 >> 4
	e := x & 0x0F

	if e < 2 {
		if e == 1 {
			m *= 10
		}

		return fmt.Sprintf("0.%02d", m)
	}

	var s strings.Builder
	fmt.Fprintf(&s, "%d", m)
	for e > 2 {
		s.WriteString("0")
		e--
	}
	return s.String()
}

// sprint write the rdata to sb with spaces between the elements.
func sprintData(sb *strings.Builder, sx ...string) {
	for i, s := range sx {
		sb.WriteString(s)
		if i < len(sx)-1 {
			sb.WriteByte(' ')
		}
	}
}

func typeToString(t uint16) string {
	if t1, ok := dnsstring.TypeToString[uint16(t)]; ok {
		return t1
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// saltToString converts a NSECX salt to uppercase and returns "-" when it is empty.
func saltToString(s string) string {
	if s == "" {
		return "-"
	}
	return strings.ToUpper(s)
}

func euiToString(eui uint64, bits int) (hex string) {
	switch bits {
	case 64:
		hex = fmt.Sprintf("%16.16x", eui)
		hex = hex[0:2] + "-" + hex[2:4] + "-" + hex[4:6] + "-" + hex[6:8] +
			"-" + hex[8:10] + "-" + hex[10:12] + "-" + hex[12:14] + "-" + hex[14:16]
	case 48:
		hex = fmt.Sprintf("%12.12x", eui)
		hex = hex[0:2] + "-" + hex[2:4] + "-" + hex[4:6] + "-" + hex[6:8] +
			"-" + hex[8:10] + "-" + hex[10:12]
	}
	return
}

func sprintTxt(txt []string) string {
	sb := builderPool.Get()
	defer builderPool.Put(sb)

	for i, s := range txt {
		sb.Grow(3 + len(s))
		if i > 0 {
			sb.WriteString(` "`)
		} else {
			sb.WriteByte('"')
		}
		for j := 0; j < len(s); {
			b, n := ddd.Next(s, j)
			if n == 0 {
				break
			}
			writeTxtByte(&sb, b)
			j += n
		}
		sb.WriteByte('"')
	}
	return sb.String()
}

func writeTxtByte(sb *strings.Builder, b byte) {
	switch {
	case b == '"' || b == '\\':
		sb.WriteByte('\\')
		sb.WriteByte(b)
	case b < ' ' || b > '~':
		sb.WriteString(ddd.Escape(b))
	default:
		sb.WriteByte(b)
	}
}

// splitN splits a string into N sized string chunks.
func splitN(s string, n int) []string {
	if len(s) < n {
		return []string{s}
	}
	sx := []string{}
	p, i := 0, n
	for {
		if i <= len(s) {
			sx = append(sx, s[p:i])
		} else {
			sx = append(sx, s[p:])
			break

		}
		p, i = p+n, i+n
	}
	return sx
}

// Translate the TSIG time signed into a date. There is no need for RFC1982 calculations as this date is 48 bits.
func tsigTimeToString(t uint64) string {
	ti := time.Unix(int64(t), 0).UTC()
	return ti.Format("20060102150405")
}
