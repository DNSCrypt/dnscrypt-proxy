package dns

import (
	"sort"
)

// Compare returns an integer comparing two RRs according to "Canonical Form and Order of Resource Records" in
// RFC 4034 Section 6. Note the TTL is skipped when comparing.
// The result will be 0 if a == b, -1 if a < b, and +1 if a > b.
func Compare(a, b RR) int {
	x := CompareName(a.Header().Name, b.Header().Name)
	if x != 0 {
		return x
	}

	at := RRToType(a)
	bt := RRToType(b)

	if at < bt {
		return -1
	}
	if at > bt {
		return +1
	}

	if a.Header().Class < b.Header().Class {
		return -1
	}
	if a.Header().Class > b.Header().Class {
		return 1
	}

	return compare(a, b)
}

var _ sort.Interface = RRset{}

func (set RRset) Len() int           { return len(set) }
func (set RRset) Less(i, j int) bool { return Compare(set[i], set[j]) == -1 }
func (set RRset) Swap(i, j int)      { set[i], set[j] = set[j], set[i] }

// CompareName compares the name a and b as defined in RFC 4034, canonical ordering of names.
// If a label is the asterisks label "*" it is always equal (wildcard match). TODO(miek): this isn't
// implemented?
func CompareName(a, b string) int {
	// See https://bert-hubert.blogspot.com/2015/10/how-to-do-fast-canonical-ordering-of.html
	// Also exact copy of dnsutil/common.go
	lasta := len(a)
	lastb := len(b)
	for {
		cura, overshota := dnsutilPrev(a, lasta)
		curb, overshotb := dnsutilPrev(b, lastb)
		if overshota && overshotb {
			return compareLabel(a[cura:lasta-1], b[curb:lastb-1])
		}
		x := compareLabel(a[cura:lasta-1], b[curb:lastb-1])
		if x != 0 || (overshota && overshotb) {
			return x
		}
		if overshota {
			return -1
		}
		if overshotb {
			return 1
		}

		lasta = cura
		lastb = curb
	}
}

// Equal returns true if a and b are equal. See [Compare].
func Equal(a, b RR) bool { return Compare(a, b) == 0 }

// EqualName returns true if the domain names a and b are equal. See [CompareName].
func EqualName(a, b string) bool { return CompareName(a, b) == 0 }

// CompareSerial compares serial numbers a and b using RFC 1982 serial number arithmetic.
// Returns -1 if a < b, +1 if a > b, and 0 if a == b. The result is undefined when the
// difference is exactly 2^31.
func CompareSerial(a, b uint32) int {
	if a == b {
		return 0
	}
	// Use uint32 modular subtraction per RFC 1982 Section 3.2. If (a - b) mod 2^32 is in
	// (0, 2^31), a is greater; otherwise a is less (or undefined at exactly 2^31).
	if (a - b) <= MaxSerialIncrement {
		return 1
	}
	return -1
}

// EqualSerial return true if a and b are equal. This function is here for consistency only.
func EqualSerial(a, b uint32) bool { return a == b }
