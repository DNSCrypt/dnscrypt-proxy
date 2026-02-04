// Package dnsutil contains function that are useful in the context of working with the DNS.
package dnsutil

// Trim removes the zone component from s. It returns the trimmed name or the empty string if z is longer than s.
// The trimmed name will be returned without a trailing dot.
// s and z must be syntactically valid domain names, see [IsName] and [IsFqdn].
func Trim(s, z string) string {
	i, overshot := Prev(s, Labels(z))
	if overshot || i-1 < 0 {
		return ""
	}
	// This includes the '.', remove on return.
	return s[:i-1]
}

// IsBelow checks if child sits below parent in the DNS tree, i.e. check if the child is a sub-domain of
// parent. If child and parent are at the same level, true is returned as well.
func IsBelow(parent, child string) bool { return Common(parent, child) == Labels(parent) }
