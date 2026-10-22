package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"strings"

	"golang.org/x/net/idna"
)

var errCertHashNotFound = errors.New("Certificate hash not found")

// certHashesMatch reports whether the key of a pinned certificate is in a verified chain.
func certHashesMatch(cs *tls.ConnectionState, hashes [][]byte) bool {
	isPinned := func(cert *x509.Certificate) bool {
		h := sha256.Sum256(cert.RawTBSCertificate)
		return slices.ContainsFunc(hashes, func(hash []byte) bool { return bytes.Equal(hash, h[:]) })
	}
	pinnedKeys := make(map[string]bool)
	for _, cert := range cs.PeerCertificates {
		if isPinned(cert) {
			pinnedKeys[string(cert.RawSubjectPublicKeyInfo)] = true
		}
	}
	for _, chain := range cs.VerifiedChains {
		for _, cert := range chain {
			if pinnedKeys[string(cert.RawSubjectPublicKeyInfo)] || isPinned(cert) {
				return true
			}
		}
	}
	return false
}

func certHashesHostKey(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip := ParseIP(host); ip != nil {
		return ip.String()
	}
	if ascii, err := idna.Lookup.ToASCII(host); err == nil {
		host = ascii
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}
