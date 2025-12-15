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
	lasta, _ := dnsutilPrev(a, 0)
	lastb, _ := dnsutilPrev(b, 0)

	for {
		cura, overshota := dnsutilPrev(a[:lasta], 1)
		curb, overshotb := dnsutilPrev(b[:lastb], 1)
		if overshota && overshotb {
			return 0
		}
		if overshota {
			return -1
		}
		if overshotb {
			return 1
		}

		// -1 because of the ending dot, which we most def. do _not_ want to compare
		x := compareLabel(a[cura:lasta-1], b[curb:lastb-1])
		if x != 0 {
			return x
		}
		lasta = cura
		lastb = curb
	}
}

// Equal returns true if a and b are equal. See [Compare].
func Equal(a, b RR) bool { return Compare(a, b) == 0 }

// EqualName returns true if the domain names a and b are equal. See [CompareName].
func EqualName(a, b string) bool { return CompareName(a, b) == 0 }

// CompareSerial compares a, b which are serial numbers are timestamps from signatures, while taking into
// account RFC 1984 serial arithemetic, -1 is returned when a is smaller, +1 when a is larger, otherwise 0.
func CompareSerial(a, b uint32) int {
	if a == b {
		return 0
	}

	// 3.2 of the RFC
	i1 := int(a)
	i2 := int(b)

	if i1 < i2 && (i2-i1) < MaxSerialIncrement {
		return -1
	}
	if i1 > i2 && (i1-i2) > MaxSerialIncrement {
		return -1
	}

	return 1
}

// EqualSerial return true if a and b are equal. This function is here for consistency only.
func EqualSerial(a, b uint32) bool { return a == b }
