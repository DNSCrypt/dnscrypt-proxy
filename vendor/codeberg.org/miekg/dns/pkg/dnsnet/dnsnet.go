// Package dnsnet wraps crypto/cryptobyte to allow accounting for pointers followed while unpacking.
package dnsnet

import "golang.org/x/crypto/cryptobyte"

// How many pointer may be followed in a message, per octet and the minimal amount
const (
	octetFollows = 2
	minFollows   = 2048
)

// String is a [cryptobyte.String] that carries the compression pointer follows its message has left.
type String struct {
	cryptobyte.String
	left uint32
}

// New returns a String over msg with a follow budget proportional to its length.
func New(msg []byte) String {
	return String{String: msg, left: uint32(max(octetFollows*len(msg), minFollows))}
}

// Follow spends one pointer followed and reports whether the budget allowed it.
func (s *String) Follow() bool {
	if s.left == 0 {
		return false
	}
	s.left--
	return true
}
