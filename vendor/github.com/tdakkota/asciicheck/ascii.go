package asciicheck

import "unicode"

func isASCII(s string) (rune, bool) {
	if len(s) == 1 {
		return []rune(s)[0], s[0] <= unicode.MaxASCII
	}

	r := []rune(s)
	for i := 0; i < len(s); i++ {
		if r[i] > unicode.MaxASCII {
			return r[i], false
		}
	}

	return 0, true
}
