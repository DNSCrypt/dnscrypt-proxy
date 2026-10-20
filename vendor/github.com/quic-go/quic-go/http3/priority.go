package http3

import "strings"

const defaultPriorityUrgency int8 = 3

// parsePriority parses the RFC 9218 Priority header field value. It only
// recognizes the u and i parameters; malformed members return both defaults.
func parsePriority(value string) (urgency int8, incremental bool) {
	urgency = defaultPriorityUrgency

	var inString, escapes bool
	for i, start := 0, 0; i <= len(value); i++ {
		switch {
		case i == len(value) || !inString && value[i] == ',':
			member, _, _ := strings.Cut(strings.TrimSpace(value[start:i]), ";")
			start = i + 1
			key, item, hasValue := strings.Cut(member, "=")
			if key == "" || hasValue && item == "" {
				return defaultPriorityUrgency, false
			}
			switch key {
			case "u":
				if hasValue && len(item) == 1 && item[0] >= '0' && item[0] <= '7' {
					urgency = int8(item[0] - '0')
				}
			case "i":
				if !hasValue || item == "?1" {
					incremental = true
				} else if item == "?0" {
					incremental = false
				}
			}
		case escapes && value[i] == '\\':
			i++
		case value[i] == '"':
			inString = !inString
			escapes = inString && (i == 0 || value[i-1] != '%')
		}
	}
	if inString {
		return defaultPriorityUrgency, false
	}
	return urgency, incremental
}
