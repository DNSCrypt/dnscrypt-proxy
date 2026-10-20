package revera

// Hand-written UTF-8 handling.
// The subset imports nothing, so this file spells out the few operations the engine needs.
// The decoder matches the Go standard decoder bit for bit: strict validation, no overlong forms, and no surrogates.
// Every invalid byte reports the invalid sentinel with size one.

// invalidRune marks a byte that is not valid UTF-8, and it matches nothing.
// An encoded U+FFFD decodes with size 3, so the two stay different.
const invalidRune int32 = -1

func utf8Cont(c uint8) bool {
	return c >= 0x80 && c <= 0xbf
}

// decodeRuneAt decodes one character of s, starting at byte offset at.
// It returns the character and its byte size.
// Bytes that are not one valid UTF-8 sequence give invalidRune and size one.
func decodeRuneAt(s string, at int) (int32, int) {
	c0 := s[at]
	if c0 < 0x80 {
		return int32(c0), 1
	}
	if c0 < 0xc2 {
		return invalidRune, 1
	}
	if c0 < 0xe0 {
		if at+1 >= len(s) || !utf8Cont(s[at+1]) {
			return invalidRune, 1
		}
		return int32(c0&0x1f)<<6 | int32(s[at+1]&0x3f), 2
	}
	if c0 < 0xf0 {
		if at+1 >= len(s) || !utf8Cont(s[at+1]) {
			return invalidRune, 1
		}
		if c0 == 0xe0 && s[at+1] < 0xa0 {
			return invalidRune, 1
		}
		if c0 == 0xed && s[at+1] > 0x9f {
			return invalidRune, 1
		}
		if at+2 >= len(s) || !utf8Cont(s[at+2]) {
			return invalidRune, 1
		}
		return int32(c0&0x0f)<<12 | int32(s[at+1]&0x3f)<<6 |
			int32(s[at+2]&0x3f), 3
	}
	if c0 < 0xf5 {
		if at+1 >= len(s) || !utf8Cont(s[at+1]) {
			return invalidRune, 1
		}
		if c0 == 0xf0 && s[at+1] < 0x90 {
			return invalidRune, 1
		}
		if c0 == 0xf4 && s[at+1] > 0x8f {
			return invalidRune, 1
		}
		if at+2 >= len(s) || !utf8Cont(s[at+2]) {
			return invalidRune, 1
		}
		if at+3 >= len(s) || !utf8Cont(s[at+3]) {
			return invalidRune, 1
		}
		return int32(c0&0x07)<<18 | int32(s[at+1]&0x3f)<<12 |
			int32(s[at+2]&0x3f)<<6 | int32(s[at+3]&0x3f), 4
	}
	return invalidRune, 1
}

// runeCount counts the characters of s.
// Each invalid byte counts as one character, like the standard rune counter.
func runeCount(s string) int {
	count := 0
	at := 0
	for at < len(s) {
		_, size := decodeRuneAt(s, at)
		at += size
		count++
	}
	return count
}

// utf8LeadByte returns the first byte of the UTF-8 encoding of r.
// The caller guarantees a valid scalar.
func utf8LeadByte(r int32) uint8 {
	if r < 0x80 {
		return uint8(r)
	}
	if r < 0x800 {
		return uint8(0xc0 | r>>6)
	}
	if r < 0x10000 {
		return uint8(0xe0 | r>>12)
	}
	return uint8(0xf0 | r>>18)
}
