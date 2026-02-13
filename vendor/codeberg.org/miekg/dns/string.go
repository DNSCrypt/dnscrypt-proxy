package dns

import (
	"strconv"
	"strings"
	"sync"

	"codeberg.org/miekg/dns/pkg/pool"
)

func typeToString(t uint16) string {
	if t1, ok := TypeToString[t]; ok {
		return t1
	}
	return "TYPE" + strconv.Itoa(int(t))
}

func codeToString(t uint16) string {
	if t1, ok := CodeToString[t]; ok {
		return t1
	}
	return "CODE" + strconv.Itoa(int(t))
}

func classToString(c uint16) string {
	if s, ok := ClassToString[c]; ok {
		return s
	}
	return "CLASS" + strconv.Itoa(int(c))
}

func rcodeToString(r uint16) string {
	if r1, ok := RcodeToString[r]; ok {
		return r1
	}
	return "RCODE" + strconv.Itoa(int(r))
}

func opcodeToString(o uint8) string {
	if o1, ok := OpcodeToString[o]; ok {
		return o1
	}
	return "OPCODE" + strconv.Itoa(int(o))
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

// sprintHeader creates a strings.Builder, write the header to it, plus an extra tab and returns the builder.
func sprintHeader(rr RR) *strings.Builder {
	sb := builderPool.Get()

	sb.WriteString(rr.Header().Name)
	sb.WriteByte('\t')

	sb.WriteString(strconv.FormatInt(int64(rr.Header().TTL), 10))
	sb.WriteByte('\t')

	sb.WriteString(classToString(rr.Header().Class))
	sb.WriteByte('\t')

	rrtype := RRToType(rr)
	if rrtype == 0 {
		if r, ok := rr.(*RFC3597); ok {
			rrtype = r.RRType
		}
	}

	sb.WriteString(typeToString(rrtype))
	sb.WriteByte('\t')
	return &sb
}

// must look just enough so parsing from text will also work.
func sprintOptionHeader(rr EDNS0) *strings.Builder {
	sb := builderPool.Get()

	sb.WriteByte('.')
	sb.WriteByte('\t')

	sb.WriteByte('\t') // skip TTL

	sb.WriteString(classToString(rr.Header().Class))
	sb.WriteByte('\t')

	rrcode := RRToCode(rr)
	sb.WriteString(codeToString(rrcode))
	sb.WriteByte('\t')
	return &sb
}

var builderPool = &pool.Builder{Pool: sync.Pool{New: func() any { return strings.Builder{} }}}
