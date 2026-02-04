package dnsutil

import (
	"strings"
)

// Join joins the labels in s to form a fully qualified domain name. If the last label is the root label it is
// ignored. No other syntax checks are performed, each label should be a valid, relative name (i.e. not end in
// a dot), see [IsName].
func Join(ls ...string) string {
	if ls[len(ls)-1] == "." {
		return Fqdn(strings.Join(ls[:len(ls)-1], "."))
	}
	return Fqdn(strings.Join(ls, "."))
}
