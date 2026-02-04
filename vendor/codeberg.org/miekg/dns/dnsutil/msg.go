package dnsutil

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
)

type state int

const (
	stateNone   state = iota // parse the first line
	stateHeader              // optional EDNS0 header or the question section
	stateQuestion
	statePseudo
	stateAnswer
	stateAuthority
	stateAdditional
)

// StringToMsg convert a string as created by [Msg.String] back to an dns message. If the parsing fails and
// error is returned.
// The ";; QUESTION: 1, PSEUDO: 0, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0, DATA SIZE: 0" line is skipped when
// encountered.
func StringToMsg(s string) (*dns.Msg, error) {
	m := new(dns.Msg)
	state := stateNone

	// We have an RR or
	// ;; stuff, stuff2: more,  (comma separated)
	// ;; <NAME> SECTION:
	// It's line by line, so that simplifies things
	scanner := bufio.NewScanner(strings.NewReader(s)) // Maybe not use a scanner?

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, ";; QUESTION:") {
			// this is the section count line, we don't need it
			continue
		}

		// TODO(miek): dynamic updates?
		if strings.HasPrefix(line, ";; QUESTION SECTION:") {
			state = stateQuestion
			continue
		}
		if strings.HasPrefix(line, ";; PSEUDO SECTION:") {
			state = statePseudo
			continue
		}
		if strings.HasPrefix(line, ";; ANSWER SECTION:") {
			state = stateAnswer
			continue
		}
		if strings.HasPrefix(line, ";; AUTHORITY SECTION:") {
			state = stateAuthority
			continue
		}
		if strings.HasPrefix(line, ";; ADDITIONAL SECTION:") {
			state = stateAdditional
			continue
		}

		// only here when to parse an RR, header is done above
		switch state {
		case stateNone:
			// parse ;; QUERY, rcode: NOERROR, id, flags: ....
			if len(line) < 39 {
				return nil, fmt.Errorf("bad opcode: %q", line)
			}
			// we need 3 ", " in this line.
			opcode := strings.Index(line, ", ")
			if opcode == -1 || opcode == len(line)-1 {
				return nil, fmt.Errorf("bad opcode")
			}
			rcode := strings.Index(line[opcode+1:], ", ")
			if rcode == -1 || rcode == len(line[opcode+1:])-1 {
				return nil, fmt.Errorf("bad rcode: %q", line[opcode+1:])
			}

			rcode += opcode + 3
			id := strings.Index(line[rcode:], ", ")
			if id == -1 || id == len(line[rcode:])-1 {
				return nil, fmt.Errorf("bad id: %q", line[rcode:])
			}
			id += rcode
			switch line[:opcode] {
			case ";; QUERY":
				m.Opcode = dns.OpcodeQuery
			case ";; NOTIFY":
				m.Opcode = dns.OpcodeNotify
			default:
				return nil, fmt.Errorf("bad opcode")
			}

			m.Rcode = dns.StringToRcode[line[opcode+9:rcode-2]]

			val, _ := strconv.Atoi(line[rcode+4 : id])
			m.ID = uint16(val)

			if !strings.HasPrefix(line[id+2:], "flags:") {
				return nil, fmt.Errorf("bad flags")
			}
			flags := line[id+9:] + " "
			j := 0
			for i := strings.Index(flags, " "); i > 0; i = strings.Index(flags[j:], " ") {
				switch {
				case strings.HasPrefix(flags[j:], "qr"):
					m.Response = true
				case strings.HasPrefix(flags[j:], "aa"):
					m.Authoritative = true
				case strings.HasPrefix(flags[j:], "tc"):
					m.Truncated = true
				case strings.HasPrefix(flags[j:], "rd"):
					m.RecursionDesired = true
				case strings.HasPrefix(flags[j:], "ra"):
					m.RecursionAvailable = true
				case strings.HasPrefix(flags[j:], "z"):
					m.Zero = true
				case strings.HasPrefix(flags[j:], "ad"):
					m.AuthenticatedData = true
				case strings.HasPrefix(flags[j:], "cd"):
					m.CheckingDisabled = true
				case strings.HasPrefix(flags[j:], "do"):
					m.Security = true
				case strings.HasPrefix(flags[j:], "co"):
					m.CompactAnswers = true
				case strings.HasPrefix(flags[j:], "de"):
					m.Delegation = true
				}
				j += i + 1
			}

			state = stateHeader

		case stateHeader:
			// only here *if* we have not seen a question so this is the ;; EDNS line
			size := strings.Index(line, "udp: ")
			if size == -1 || size == len(line)-1 {
				return nil, fmt.Errorf("bad udp size")
			}
			val, _ := strconv.Atoi(line[size+5:])
			m.UDPSize = uint16(val)

		case stateQuestion:
			rr, err := dns.New(line)
			if err != nil {
				return nil, err
			}
			if rr != nil {
				m.Question = append(m.Question, rr)
			}
		case statePseudo:
			rr, err := dns.New(line)
			if err != nil {
				return nil, err
			}
			if rr != nil {
				m.Pseudo = append(m.Pseudo, rr)
			}
		case stateAnswer:
			rr, err := dns.New(line)
			if err != nil {
				return nil, err
			}
			if rr != nil {
				m.Answer = append(m.Answer, rr)
			}
		case stateAuthority:
			rr, err := dns.New(line)
			if err != nil {
				return nil, err
			}
			if rr != nil {
				m.Ns = append(m.Ns, rr)
			}
		case stateAdditional:
			rr, err := dns.New(line)
			if err != nil {
				return nil, err
			}
			if rr != nil {
				m.Extra = append(m.Extra, rr)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return m, nil
}
