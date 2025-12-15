package svcb

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/internal/ddd"
	"codeberg.org/miekg/dns/internal/pack"
)

func Parse(p Pair, b, o string) error {
	switch x := p.(type) {
	case *MANDATORY:
		return x.parse(b)
	case *ALPN:
		return x.parse(b)
	case *NODEFAULTALPN:
		return x.parse(b)
	case *PORT:
		return x.parse(b)
	case *IPV4HINT:
		return x.parse(b)
	case *ECHCONFIG:
		return x.parse(b)
	case *IPV6HINT:
		return x.parse(b)
	case *DOHPATH:
		return x.parse(b)
	case *OHTTP:
		return x.parse(b)
	case *LOCAL:
		return x.parse(b)
	}
	return fmt.Errorf("no svcb parse defined")
}

func (s *MANDATORY) parse(b string) error {
	keys := make([]uint16, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var key string
		key, b, _ = strings.Cut(b, ",")
		keys = append(keys, StringToKey(key))
	}
	s.Key = keys
	return nil
}

func (s *ALPN) parse(b string) error {
	if len(b) == 0 {
		s.Alpn = []string{}
		return nil
	}

	alpn := []string{}
	a := []byte{}
	for p := 0; p < len(b); {
		c, q := ddd.Next(b, p)
		if q == 0 {
			return errors.New("svcbalpn: unterminated escape")
		}
		p += q
		// If we find a comma, we have finished reading an alpn.
		if c == ',' {
			if len(a) == 0 {
				return errors.New("svcbalpn: empty protocol identifier")
			}
			alpn = append(alpn, string(a))
			a = []byte{}
			continue
		}
		// If it's a backslash, we need to handle a comma-separated list.
		if c == '\\' {
			dc, dq := ddd.Next(b, p)
			if dq == 0 {
				return errors.New("svcbalpn: unterminated escape decoding comma-separated list")
			}
			if dc != '\\' && dc != ',' {
				return errors.New("svcbalpn: bad escaped character decoding comma-separated list")
			}
			p += dq
			c = dc
		}
		a = append(a, c)
	}
	// Add the final alpn.
	if len(a) == 0 {
		return errors.New("svcbalpn: last protocol identifier empty")
	}
	s.Alpn = append(alpn, string(a))
	return nil
}

func (*NODEFAULTALPN) parse(b string) error {
	if len(b) != 0 {
		return errors.New("svcbnodefaultalpn: no-default-alpn must have no value")
	}
	return nil
}

func (s *PORT) parse(b string) error {
	port, err := strconv.ParseUint(b, 10, 16)
	if err != nil {
		return errors.New("svcbport: port out of range")
	}
	s.Port = uint16(port)
	return nil
}

func (s *IPV4HINT) parse(b string) error {
	if len(b) == 0 {
		return errors.New("svcbipv4hint: empty hint")
	}
	if strings.Contains(b, ":") {
		return errors.New("svcbipv4hint: expected ipv4, got ipv6")
	}

	hint := make([]netip.Addr, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var e string
		e, b, _ = strings.Cut(b, ",")
		ip, err := netip.ParseAddr(e)
		if err != nil || !ip.Is4() {
			return errors.New("svcbipv4hint: bad ip")
		}
		hint = append(hint, ip)
	}
	s.Hint = hint
	return nil
}

func (s *ECHCONFIG) parse(b string) error {
	x, err := pack.Base64([]byte(b))
	if err != nil {
		return errors.New("svcbech: bad base64 ech")
	}
	s.ECH = x
	return nil
}

func (s *IPV6HINT) parse(b string) error {
	if len(b) == 0 {
		return errors.New("svcbipv6hint: empty hint")
	}

	hint := make([]netip.Addr, 0, strings.Count(b, ",")+1)
	for len(b) > 0 {
		var e string
		e, b, _ = strings.Cut(b, ",")
		ip, err := netip.ParseAddr(e)
		if err != nil {
			return errors.New("svcbipv6hint: bad ip")
		}
		if !ip.Is6() || ip.Is4In6() {
			return errors.New("svcbipv6hint: expected ipv6, got ipv4-mapped-ipv6")
		}
		hint = append(hint, ip)
	}
	s.Hint = hint
	return nil
}

func (s *DOHPATH) parse(b string) error {
	template, err := stringToPair(b)
	if err != nil {
		return fmt.Errorf("svcbdohpath: %w", err)
	}
	s.Template = string(template)
	return nil
}

func (*OHTTP) parse(b string) error {
	if len(b) != 0 {
		return errors.New("svcbotthp: svcbotthp must have no value")
	}
	return nil
}

func (s *LOCAL) parse(b string) error {
	data, err := stringToPair(b)
	if err != nil {
		return fmt.Errorf("svcblocal: svcb private/experimental key %w", err)
	}
	s.Data = data
	return nil
}

// pairToString converts the value of an SVCB parameter into a DNS presentation-format string.
func pairToString(s []byte) string {
	var str strings.Builder
	str.Grow(4 * len(s))
	for _, e := range s {
		if ' ' <= e && e <= '~' {
			switch e {
			case '"', ';', ' ', '\\':
				str.WriteByte('\\')
				str.WriteByte(e)
			default:
				str.WriteByte(e)
			}
		} else {
			str.WriteString(ddd.Escape(e))
		}
	}
	return str.String()
}

// stringToPair parses a DNS presentation-format string into an SVCB parameter value.
func stringToPair(b string) ([]byte, error) {
	data := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if b[i] != '\\' {
			data = append(data, b[i])
			i++
			continue
		}
		if i+1 == len(b) {
			return nil, errors.New("escape unterminated")
		}
		if ddd.IsDigit(b[i+1]) {
			if i+3 < len(b) && ddd.IsDigit(b[i+2]) && ddd.IsDigit(b[i+3]) {
				a, err := strconv.ParseUint(b[i+1:i+4], 10, 8)
				if err == nil {
					i += 4
					data = append(data, byte(a))
					continue
				}
			}
			return nil, errors.New("bad escaped octet")
		} else {
			data = append(data, b[i+1])
			i += 2
		}
	}
	return data, nil
}
