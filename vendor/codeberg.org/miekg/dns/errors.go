package dns

// Error represents a DNS error.
type Error struct {
	err string
}

func (e *Error) Error() string { return "dns: " + e.err }

var (
	ErrID      = &Error{err: "ID mismatch"}       // ErrID signals a mismatch with the sent message ID and the one returned.
	ErrAlg     = &Error{err: "bad algorithm"}     // ErrAlg indicates an error with the (DNSSEC) algorithm.
	ErrSig     = &Error{err: "bad signature"}     // ErrSig indicates that a signature can not be cryptographically validated.
	ErrKeyAlg  = &Error{err: "bad key algorithm"} // ErrKeyAlg indicates that the algorithm in the key is not valid.
	ErrKey     = &Error{err: "bad key"}
	ErrKeySize = &Error{err: "bad key size"}
	ErrNoTSIG  = &Error{err: "no TSIG signature"}
	ErrNoSIG0  = &Error{err: "no SIG(0) signature"}
	ErrRcode   = &Error{err: "bad rcode"}
	ErrRRset   = &Error{err: "bad rrset"}
	ErrSOA     = &Error{err: "no SOA"}   // ErrSOA indicates that no SOA RR was seen when doing zone transfers.
	ErrTime    = &Error{err: "bad time"} // ErrTime indicates a timing error in TSIG authentication.
)
