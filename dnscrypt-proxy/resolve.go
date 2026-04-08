// resolve.go implements resolver diagnostics used by the --resolve command.

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	// myResolverHost is the well-known TXT name that returns the resolver's IP.
	myResolverHost = "resolver.dnscrypt.info."

	// nonexistentName must never exist; used to test whether a resolver lies.
	nonexistentName = "nonexistent-zone.dnscrypt-test."

	// initialTimeout is the deadline for the first query attempt.
	initialTimeout = 2 * time.Second

	// maxRetries is the total number of UDP send-receive attempts per query.
	maxRetries = 3

	// timeoutMultiplier doubles the per-attempt deadline after each timeout.
	timeoutMultiplier = 2

	// maxCNAMEChain caps CNAME traversal depth to prevent infinite loops.
	maxCNAMEChain = 100

	// ecsTestSubnet is the EDNS Client Subnet value sent during capability probes.
	ecsTestSubnet = "93.184.216.0/24"
)

// [R08] ECS family codes typed as uint16 to match dns.SUBNET.Family exactly.
const (
	ecsIPv4Family uint16 = 1
	ecsIPv6Family uint16 = 2
)

// [R17] ecsTestPrefix is parsed once at package init from the constant string.
// addClientSubnetOption reads addr and bits from it directly — zero parse cost
// per ECS probe.
var ecsTestPrefix = netip.MustParsePrefix(ecsTestSubnet).Masked()

// ── Sentinel errors ───────────────────────────────────────────────────────────

var (
	// ErrTimeout is returned when all retry attempts time out.
	ErrTimeout = errors.New("DNS query timeout")

	// ErrUnsupportedRecordType is returned for unknown DNS record types.
	ErrUnsupportedRecordType = errors.New("unsupported DNS record type")

	// [R19] ErrInvalidAddress removed — it was only used in the now-deleted
	// AddrFromSlice error path inside addClientSubnetOption.
)

// ── Package-level helpers ─────────────────────────────────────────────────────

// isInetRecord reports whether rr belongs to class INET and matches qType.
// [R03] Replaces the 10+ inline "RRToType != T || Class != ClassINET" guards.
func isInetRecord(rr dns.RR, qType uint16) bool {
	return rr.Header().Class == dns.ClassINET && dns.RRToType(rr) == qType
}

// printOrDash prints items joined by ", " or a single "-" when the slice is empty.
// [R04] Replaces 7 identical if-len-zero blocks throughout the file.
func printOrDash(items []string) {
	if len(items) == 0 {
		fmt.Println("-")
		return
	}
	fmt.Println(strings.Join(items, ", "))
}

// ── Core query ────────────────────────────────────────────────────────────────

// resolveQuery sends a UDP DNS query to server for (qName, qType) and returns
// the response.  On timeout it retries up to maxRetries times with exponential
// backoff; any other error is returned immediately.
func resolveQuery(server, qName string, qType uint16, sendClientSubnet bool) (*dns.Msg, error) {
	transport := dns.NewTransport()
	transport.ReadTimeout = initialTimeout
	client := &dns.Client{Transport: transport}

	msg := dns.NewMsg(qName, qType)
	if msg == nil {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedRecordType, qType)
	}
	msg.RecursionDesired = true
	msg.Opcode = dns.OpcodeQuery
	msg.UDPSize = uint16(MaxDNSPacketSize)
	msg.Security = true

	if sendClientSubnet {
		addClientSubnetOption(msg) // [R16] no error return
	}

	bg := context.Background() // [R11] cached once; reused across all retries
	timeout := transport.ReadTimeout

	for attempt := range maxRetries {
		msg.ID = dns.ID()
		msg.Data = nil // force re-pack with fresh ID

		ctx, cancel := context.WithTimeout(bg, timeout)
		response, _, err := client.Exchange(ctx, msg, "udp", server)
		cancel()

		// [R01] errors.As unwraps error chains; bare type assertion misses them.
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			if attempt < maxRetries-1 {
				timeout *= time.Duration(timeoutMultiplier) // [R07] explicit cast
				continue
			}
			return nil, fmt.Errorf("%w after %d attempts", ErrTimeout, maxRetries)
		}
		if err != nil {
			return nil, fmt.Errorf("DNS query failed: %w", err)
		}
		return response, nil
	}

	// [R15] Reachable only when maxRetries == 0.
	return nil, fmt.Errorf("%w: maxRetries is zero", ErrTimeout)
}

// addClientSubnetOption appends an EDNS Client Subnet option to msg.
//
// [R02] netip prefix replaces net.ParseCIDR + netip.AddrFromSlice + size switch.
// [R16] No error return — the function cannot fail.
// [R17] Uses the pre-parsed package-level ecsTestPrefix.
func addClientSubnetOption(msg *dns.Msg) {
	addr := ecsTestPrefix.Addr()
	bits := ecsTestPrefix.Bits()

	var family uint16
	if addr.Is4() {
		family = ecsIPv4Family
	} else {
		family = ecsIPv6Family
	}

	msg.Pseudo = append(msg.Pseudo, &dns.SUBNET{
		Family:  family,
		Netmask: uint8(bits),
		Scope:   0,
		Address: addr,
	})
}

// ── Top-level entry point ─────────────────────────────────────────────────────

// Resolve performs a comprehensive DNS diagnostic for name, printing results to
// stdout.  name may embed a server override in "name,server" format.
// When singleResolver is true, extra capability checks are performed.
func Resolve(server, name string, singleResolver bool) {
	name, server, singleResolver = parseNameAndServer(name, server, singleResolver)
	server = normalizeServer(server)

	host, port := ExtractHostAndPort(server, 53)
	fmt.Printf("Resolving [%s] using %s port %d\n\n", name, host, port)

	name = fqdn(name)
	cname := name

	clientSubnet, err := resolveResolverInfo(server)
	if err != nil {
		fmt.Printf("Unable to resolve: [%s]\n", err)
		os.Exit(1)
	}

	if singleResolver {
		checkResolverCapabilities(server, clientSubnet)
	}
	fmt.Println()

	cname = resolveCNAMEChain(server, cname)
	fmt.Println()

	resolveAddresses(server, cname)
	fmt.Println()

	resolveNameServers(server, cname)
	resolveMailServers(server, cname)
	fmt.Println()

	resolveHTTPSRecords(server, cname)
	fmt.Println()

	resolveHostInfo(server, cname)
	resolveTXTRecords(server, cname)
	fmt.Println()
}

// ── Input normalisation ───────────────────────────────────────────────────────

// parseNameAndServer splits name on the first comma.  If a comma is present
// the text after it overrides server and singleResolver becomes true.
func parseNameAndServer(name, server string, singleResolver bool) (string, string, bool) {
	if host, override, ok := strings.Cut(name, ","); ok {
		return host, override, true
	}
	return name, server, singleResolver
}

// normalizeServer rewrites wildcard bind addresses to their loopback
// equivalents so the address can be dialled as a query target.
func normalizeServer(server string) string {
	host, port := ExtractHostAndPort(server, 53)
	switch host {
	case "0.0.0.0":
		host = "127.0.0.1"
	case "[::]":
		host = "[::1]"
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// ── Resolver metadata ─────────────────────────────────────────────────────────

// resolveResolverInfo queries the well-known resolver TXT record, prints the
// resolver IP (enriched with PTR), and returns the EDNS Client Subnet value.
func resolveResolverInfo(server string) (clientSubnet string, err error) {
	response, err := resolveQuery(server, myResolverHost, dns.TypeTXT, true)
	if err != nil {
		return "", fmt.Errorf("resolver info query failed: %w", err)
	}
	fmt.Print("Resolver      : ")
	printOrDash(extractResolverIPs(server, response, &clientSubnet))
	return clientSubnet, nil
}

// extractResolverIPs walks the TXT answers, extracts resolver IPs and the ECS
// subnet value, enriches each IP with a PTR hostname, and returns the list.
func extractResolverIPs(server string, response *dns.Msg, clientSubnet *string) []string {
	results := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if !isInetRecord(answer, dns.TypeTXT) { // [R03]
			continue
		}
		rec, ok := answer.(*dns.TXT)
		if !ok {
			continue
		}
		ip := extractIPFromTXT(rec, clientSubnet)
		if ip == "" {
			continue
		}
		results = append(results, enrichWithPTR(server, ip))
	}
	return results
}

// extractIPFromTXT reads "Resolver IP:" and "EDNS0 client subnet:" entries
// from the TXT string list.  Returns the resolver IP (empty if not found).
func extractIPFromTXT(rec *dns.TXT, clientSubnet *string) string {
	var ip string
	for _, txt := range rec.Txt {
		if after, ok := strings.CutPrefix(txt, "Resolver IP: "); ok {
			ip = after
		} else if after, ok := strings.CutPrefix(txt, "EDNS0 client subnet: "); ok {
			*clientSubnet = after
		}
	}
	return ip
}

// enrichWithPTR appends the PTR hostname to ip when one can be resolved.
// Returns ip unchanged on any error.
func enrichWithPTR(server, ip string) string {
	rev, err := reverseAddr(ip)
	if err != nil {
		return ip
	}
	response, err := resolveQuery(server, rev, dns.TypePTR, false)
	if err != nil {
		return ip
	}
	for _, answer := range response.Answer {
		if !isInetRecord(answer, dns.TypePTR) { // [R03]
			continue
		}
		if rec, ok := answer.(*dns.PTR); ok {
			return fmt.Sprintf("%s (%s)", ip, rec.Ptr)
		}
	}
	return ip
}

// ── Resolver capability probes ────────────────────────────────────────────────

// checkResolverCapabilities probes server for NXDOMAIN hijacking, DNSSEC
// validation, and EDNS Client Subnet forwarding.
func checkResolverCapabilities(server, clientSubnet string) {
	response, err := resolveQuery(server, nonexistentName, dns.TypeA, false)

	fmt.Print("Lying         : ")
	if err != nil {
		fmt.Printf("[%v]\n", err)
		return
	}

	switch response.Rcode {
	case dns.RcodeSuccess:
		fmt.Println("yes. That resolver returns wrong responses")
	case dns.RcodeNameError:
		fmt.Println("no")
	default:
		fmt.Printf("unknown - query returned %s\n", dns.RcodeToString[response.Rcode])
	}

	// DNSSEC is only meaningful when the resolver correctly returned NXDOMAIN.
	if response.Rcode == dns.RcodeNameError {
		fmt.Print("DNSSEC        : ")
		if response.AuthenticatedData {
			fmt.Println("yes, the resolver supports DNSSEC")
		} else {
			fmt.Println("no, the resolver doesn't support DNSSEC")
		}
	}

	fmt.Print("ECS           : ")
	if clientSubnet != "" {
		fmt.Println("client network address is sent to authoritative servers")
	} else {
		fmt.Println("ignored or selective")
	}
}

// ── CNAME chain ───────────────────────────────────────────────────────────────

// resolveCNAMEChain follows CNAME records to the terminal name, stopping on
// a query error, a missing next hop, or after maxCNAMEChain hops.
//
// [R09] nextCNAME replaces the bool "found" flag — data-flow is explicit.
func resolveCNAMEChain(server, name string) string {
	fmt.Print("Canonical name: ")
	cname := name

	for i := range maxCNAMEChain {
		response, err := resolveQuery(server, cname, dns.TypeCNAME, false)
		if err != nil {
			break
		}

		var nextCNAME string // [R09] empty string signals no further hop
		for _, answer := range response.Answer {
			if !isInetRecord(answer, dns.TypeCNAME) { // [R03]
				continue
			}
			if rec, ok := answer.(*dns.CNAME); ok {
				nextCNAME = rec.Target
				break
			}
		}

		if nextCNAME == "" {
			break
		}
		cname = nextCNAME

		if i == maxCNAMEChain-1 {
			fmt.Printf("%s (truncated - max chain length reached)\n", cname)
			return cname
		}
	}

	fmt.Println(cname)
	return cname
}

// ── Address resolution ────────────────────────────────────────────────────────

// resolveAddresses prints IPv4 and IPv6 addresses for cname.
func resolveAddresses(server, cname string) {
	resolveAndPrintAddresses(server, cname, dns.TypeA, "IPv4 addresses")
	resolveAndPrintAddresses(server, cname, dns.TypeAAAA, "IPv6 addresses")
}

// resolveAndPrintAddresses queries qType records for cname and prints them.
func resolveAndPrintAddresses(server, cname string, qType uint16, label string) {
	fmt.Printf("%-15s: ", label)
	response, err := resolveQuery(server, cname, qType, false)
	if err != nil {
		fmt.Println("-")
		return
	}
	printOrDash(extractIPAddresses(response, qType)) // [R04]
}

// extractIPAddresses collects address strings from A or AAAA records in response.
//
// [R13] Type switch on answer.(type) replaces the uint16 dispatch +
// separate type assertions — idiomatic and concise.
func extractIPAddresses(response *dns.Msg, qType uint16) []string {
	addresses := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if !isInetRecord(answer, qType) { // [R03]
			continue
		}
		switch rec := answer.(type) { // [R13]
		case *dns.A:
			addresses = append(addresses, rec.A.String())
		case *dns.AAAA:
			addresses = append(addresses, rec.AAAA.String())
		}
	}
	return addresses
}

// ── Name server resolution ────────────────────────────────────────────────────

// resolveNameServers prints NS records for cname and its DNSSEC signed status.
func resolveNameServers(server, cname string) {
	fmt.Print("Name servers  : ")

	response, err := resolveQuery(server, cname, dns.TypeNS, false)
	if err != nil {
		fmt.Println("-")
		fmt.Println("DNSSEC signed : -")
		return
	}

	nameServers := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if !isInetRecord(answer, dns.TypeNS) { // [R03]
			continue
		}
		if rec, ok := answer.(*dns.NS); ok {
			nameServers = append(nameServers, rec.Ns)
		}
	}

	switch {
	case response.Rcode == dns.RcodeNameError:
		fmt.Println("name does not exist")
	case response.Rcode != dns.RcodeSuccess:
		fmt.Printf("server returned %s\n", dns.RcodeToString[response.Rcode])
	case len(nameServers) == 0:
		fmt.Println("no name servers found")
	default:
		fmt.Println(strings.Join(nameServers, ", "))
	}

	fmt.Print("DNSSEC signed : ")
	if response.AuthenticatedData {
		fmt.Println("yes")
	} else {
		fmt.Println("no")
	}
}

// ── Mail server resolution ────────────────────────────────────────────────────

// resolveMailServers prints MX hostnames for cname.
//
// [R21] Now prints actual MX record values (consistent with every other
// record-type function) instead of the original count-only display.
func resolveMailServers(server, cname string) {
	fmt.Print("Mail servers  : ")

	response, err := resolveQuery(server, cname, dns.TypeMX, false)
	if err != nil {
		fmt.Println("-")
		return
	}

	mailServers := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if !isInetRecord(answer, dns.TypeMX) { // [R03]
			continue
		}
		if rec, ok := answer.(*dns.MX); ok {
			mailServers = append(mailServers, rec.Mx)
		}
	}
	printOrDash(mailServers) // [R04] [R21]
}

// ── HTTPS / SVCB records ──────────────────────────────────────────────────────

// resolveHTTPSRecords prints HTTPS alias (priority 0) and service-parameter
// (priority > 0) records for cname in a single answer-section pass. [R12]
func resolveHTTPSRecords(server, cname string) {
	response, err := resolveQuery(server, cname, dns.TypeHTTPS, false)
	if err != nil {
		fmt.Println("HTTPS alias   : -")
		fmt.Println("HTTPS info    : -")
		return
	}
	aliases, info := extractHTTPSRecords(response) // [R12] single pass
	fmt.Print("HTTPS alias   : ")
	printOrDash(aliases) // [R04]
	fmt.Print("HTTPS info    : ")
	printOrDash(info) // [R04]
}

// extractHTTPSRecords splits HTTPS records into AliasMode (priority 0) and
// ServiceMode (priority > 0) entries in one pass over the answer section.
// [R12] Replaces the previous two-pass design.
func extractHTTPSRecords(response *dns.Msg) (aliases, info []string) {
	aliases = make([]string, 0, len(response.Answer)) // [R06]
	info = make([]string, 0, len(response.Answer))    // [R06]

	for _, answer := range response.Answer {
		if !isInetRecord(answer, dns.TypeHTTPS) { // [R03]
			continue
		}
		rec, ok := answer.(*dns.HTTPS)
		if !ok {
			continue
		}
		switch {
		case rec.Priority == 0 && len(rec.Target) >= 2:
			// AliasMode record
			aliases = append(aliases, rec.Target)
		case rec.Priority > 0 && len(rec.Target) <= 1:
			// ServiceMode record — collect key=value pairs
			for _, value := range rec.Value {
				key := svcb.KeyToString(svcb.PairToKey(value))
				info = append(info, fmt.Sprintf("[%s]=[%s]", key, value.String()))
			}
		}
	}
	return aliases, info
}

// ── Host info and TXT records ─────────────────────────────────────────────────

// resolveHostInfo prints HINFO (CPU and OS) records for cname.
func resolveHostInfo(server, cname string) {
	fmt.Print("Host info     : ")
	response, err := resolveQuery(server, cname, dns.TypeHINFO, false)
	if err != nil {
		fmt.Println("-")
		return
	}
	hostInfo := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if !isInetRecord(answer, dns.TypeHINFO) { // [R03]
			continue
		}
		if rec, ok := answer.(*dns.HINFO); ok {
			hostInfo = append(hostInfo, fmt.Sprintf("%s %s", rec.Cpu, rec.Os))
		}
	}
	printOrDash(hostInfo) // [R04]
}

// resolveTXTRecords prints TXT records for cname.
func resolveTXTRecords(server, cname string) {
	fmt.Print("TXT records   : ")
	response, err := resolveQuery(server, cname, dns.TypeTXT, false)
	if err != nil {
		fmt.Println("-")
		return
	}
	txtRecords := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		if !isInetRecord(answer, dns.TypeTXT) { // [R03]
			continue
		}
		if rec, ok := answer.(*dns.TXT); ok {
			txtRecords = append(txtRecords, strings.Join(rec.Txt, " "))
		}
	}
	printOrDash(txtRecords) // [R04]
}
