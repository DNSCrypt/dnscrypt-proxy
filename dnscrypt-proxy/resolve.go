package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
)

const (
	myResolverHost  string = "resolver.dnscrypt.info."
	nonexistentName string = "nonexistent-zone.dnscrypt-test."
)

// Resolver holds reusable client state to avoid per-query allocations
type Resolver struct {
	server    string
	transport *dns.Transport
	client    *dns.Client
	ecsOpt    *dns.SUBNET // pre-built ECS option
}

// NewResolver creates a reusable resolver instance
func NewResolver(server string, sendClientSubnet bool) *Resolver {
	tr := dns.NewTransport()
	tr.ReadTimeout = 1500 * time.Millisecond
	c := &dns.Client{Transport: tr}

	var ecs *dns.SUBNET
	if sendClientSubnet {
		subnet := net.IPNet{IP: net.IPv4(93, 184, 216, 0), Mask: net.CIDRMask(24, 32)}
		bits, totalSize := subnet.Mask.Size()
		var family uint16
		if totalSize == 32 {
			family = 1
		} else if totalSize == 128 {
			family = 2
		}
		addr, _ := netip.AddrFromSlice(subnet.IP)
		ecs = &dns.SUBNET{
			Family:  family,
			Netmask: uint8(bits),
			Scope:   0,
			Address: addr,
		}
	}

	return &Resolver{
		server:    server,
		transport: tr,
		client:    c,
		ecsOpt:    ecs,
	}
}

// resolveQuery performs a DNS query with automatic TCP fallback on truncation
func (r *Resolver) resolveQuery(ctx context.Context, qName string, qType uint16, useECS bool) (*dns.Msg, error) {
	msg := dns.NewMsg(qName, qType)
	if msg == nil {
		return nil, fmt.Errorf("unsupported DNS record type: %d", qType)
	}
	msg.RecursionDesired = true
	msg.Opcode = dns.OpcodeQuery
	msg.UDPSize = uint16(MaxDNSPacketSize)
	msg.Security = true

	if useECS && r.ecsOpt != nil {
		msg.Pseudo = append(msg.Pseudo, r.ecsOpt)
	}

	// Retry with bounded timeout growth
	timeout := r.transport.ReadTimeout
	for attempt := 0; attempt < 2; attempt++ {
		msg.ID = dns.ID()
		msg.Data = nil

		queryCtx, cancel := context.WithTimeout(ctx, timeout)
		response, _, err := r.client.Exchange(queryCtx, msg, "udp", r.server)
		cancel()

		// TCP fallback on truncation
		if err == nil && response != nil && response.Truncated {
			msg.ID = dns.ID()
			msg.Data = nil
			tcpCtx, tcpCancel := context.WithTimeout(ctx, timeout)
			response, _, err = r.client.Exchange(tcpCtx, msg, "tcp", r.server)
			tcpCancel()
			return response, err
		}

		if err == nil {
			return response, nil
		}

		if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
			timeout = timeout * 3 / 2 // 1.5x instead of 2x
			continue
		}
		return nil, err
	}
	return nil, errors.New("timeout")
}

// parallelQueries executes multiple DNS queries concurrently
func (r *Resolver) parallelQueries(ctx context.Context, qName string, qTypes []uint16) map[uint16]*dns.Msg {
	results := make(map[uint16]*dns.Msg, len(qTypes))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, qType := range qTypes {
		wg.Add(1)
		go func(qt uint16) {
			defer wg.Done()
			resp, err := r.resolveQuery(ctx, qName, qt, false)
			if err == nil && resp != nil {
				mu.Lock()
				results[qt] = resp
				mu.Unlock()
			}
		}(qType)
	}

	wg.Wait()
	return results
}

func Resolve(server string, name string, singleResolver bool) {
	parts := strings.SplitN(name, ",", 2)
	if len(parts) == 2 {
		name, server = parts[0], parts[1]
		singleResolver = true
	}

	host, port := ExtractHostAndPort(server, 53)
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	} else if host == "[::]" {
		host = "[::1]"
	}
	server = fmt.Sprintf("%s:%d", host, port)

	fmt.Printf("Resolving [%s] using %s port %d\n\n", name, host, port)
	name = fqdn(name)

	ctx := context.Background()
	resolver := NewResolver(server, true)

	cname := name
	var clientSubnet string

	// Resolver identification with parallel PTR lookups
	for once := true; once; once = false {
		response, err := resolver.resolveQuery(ctx, myResolverHost, dns.TypeTXT, true)
		if err != nil {
			fmt.Printf("Unable to resolve: [%s]\n", err)
			os.Exit(1)
		}
		fmt.Printf("Resolver      : ")

		type resolverInfo struct {
			ip  string
			ptr string
		}

		infos := make([]resolverInfo, 0, len(response.Answer))

		for _, answer := range response.Answer {
			if answer.Header().Class != dns.ClassINET || dns.RRToType(answer) != dns.TypeTXT {
				continue
			}
			var ip string
			for _, txt := range answer.(*dns.TXT).Txt {
				if strings.HasPrefix(txt, "Resolver IP: ") {
					ip = strings.TrimPrefix(txt, "Resolver IP: ")
				} else if strings.HasPrefix(txt, "EDNS0 client subnet: ") {
					clientSubnet = strings.TrimPrefix(txt, "EDNS0 client subnet: ")
				}
			}
			if ip != "" {
				infos = append(infos, resolverInfo{ip: ip})
			}
		}

		// Parallel PTR lookups
		var wg sync.WaitGroup
		for i := range infos {
			if rev, err := reverseAddr(infos[i].ip); err == nil {
				wg.Add(1)
				go func(idx int, revAddr string) {
					defer wg.Done()
					if response, err := resolver.resolveQuery(ctx, revAddr, dns.TypePTR, false); err == nil {
						for _, answer := range response.Answer {
							if dns.RRToType(answer) == dns.TypePTR && answer.Header().Class == dns.ClassINET {
								infos[idx].ptr = answer.(*dns.PTR).Ptr
								break
							}
						}
					}
				}(i, rev)
			}
		}
		wg.Wait()

		res := make([]string, 0, len(infos))
		for _, info := range infos {
			if info.ptr != "" {
				res = append(res, info.ip+" ("+info.ptr+")")
			} else {
				res = append(res, info.ip)
			}
		}

		if len(res) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(res, ", "))
		}
	}

	if singleResolver {
		for once := true; once; once = false {
			fmt.Printf("Lying         : ")
			response, err := resolver.resolveQuery(ctx, nonexistentName, dns.TypeA, false)
			if err != nil {
				fmt.Printf("[%v]", err)
				break
			}
			if response.Rcode == dns.RcodeSuccess {
				fmt.Println("yes. That resolver returns wrong responses")
			} else if response.Rcode == dns.RcodeNameError {
				fmt.Println("no")
			} else {
				fmt.Printf("unknown - query returned %s\n", dns.RcodeToString[response.Rcode])
			}

			if response.Rcode == dns.RcodeNameError {
				fmt.Printf("DNSSEC        : ")
				if response.AuthenticatedData {
					fmt.Println("yes, the resolver supports DNSSEC")
				} else {
					fmt.Println("no, the resolver doesn't support DNSSEC")
				}
			}

			fmt.Printf("ECS           : ")
			if clientSubnet != "" {
				fmt.Println("client network address is sent to authoritative servers")
			} else {
				fmt.Println("ignored or selective")
			}
		}
	}

	fmt.Println("")

	// CNAME resolution with early exit
cname:
	for once := true; once; once = false {
		fmt.Printf("Canonical name: ")
		for i := 0; i < 10; i++ { // reduced from 100
			response, err := resolver.resolveQuery(ctx, cname, dns.TypeCNAME, false)
			if err != nil {
				break cname
			}
			found := false
			for _, answer := range response.Answer {
				if dns.RRToType(answer) != dns.TypeCNAME || answer.Header().Class != dns.ClassINET {
					continue
				}
				cname = answer.(*dns.CNAME).Target
				found = true
				break
			}
			if !found {
				break
			}
		}
		fmt.Println(cname)
	}

	fmt.Println("")

	// Parallel A/AAAA queries
	ipQueries := resolver.parallelQueries(ctx, cname, []uint16{dns.TypeA, dns.TypeAAAA})

	fmt.Printf("IPv4 addresses: ")
	if resp, ok := ipQueries[dns.TypeA]; ok {
		ipv4 := make([]string, 0, len(resp.Answer))
		for _, answer := range resp.Answer {
			if dns.RRToType(answer) == dns.TypeA && answer.Header().Class == dns.ClassINET {
				ipv4 = append(ipv4, answer.(*dns.A).A.String())
			}
		}
		if len(ipv4) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(ipv4, ", "))
		}
	} else {
		fmt.Println("-")
	}

	fmt.Printf("IPv6 addresses: ")
	if resp, ok := ipQueries[dns.TypeAAAA]; ok {
		ipv6 := make([]string, 0, len(resp.Answer))
		for _, answer := range resp.Answer {
			if dns.RRToType(answer) == dns.TypeAAAA && answer.Header().Class == dns.ClassINET {
				ipv6 = append(ipv6, answer.(*dns.AAAA).AAAA.String())
			}
		}
		if len(ipv6) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(ipv6, ", "))
		}
	} else {
		fmt.Println("-")
	}

	fmt.Println("")

	// Parallel record queries (NS/MX/HTTPS/HINFO/TXT)
	recordQueries := resolver.parallelQueries(ctx, cname, []uint16{
		dns.TypeNS, dns.TypeMX, dns.TypeHTTPS, dns.TypeHINFO, dns.TypeTXT,
	})

	// Name servers
	fmt.Printf("Name servers  : ")
	if response, ok := recordQueries[dns.TypeNS]; ok {
		nss := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if dns.RRToType(answer) == dns.TypeNS && answer.Header().Class == dns.ClassINET {
				nss = append(nss, answer.(*dns.NS).Ns)
			}
		}
		if response.Rcode == dns.RcodeNameError {
			fmt.Println("name does not exist")
		} else if response.Rcode != dns.RcodeSuccess {
			fmt.Printf("server returned %s", dns.RcodeToString[response.Rcode])
		} else if len(nss) == 0 {
			fmt.Println("no name servers found")
		} else {
			fmt.Println(strings.Join(nss, ", "))
		}
		fmt.Printf("DNSSEC signed : ")
		if response.AuthenticatedData {
			fmt.Println("yes")
		} else {
			fmt.Println("no")
		}
	} else {
		fmt.Println("-")
		fmt.Printf("DNSSEC signed : -\n")
	}

	// Mail servers
	fmt.Printf("Mail servers  : ")
	if response, ok := recordQueries[dns.TypeMX]; ok {
		mxs := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if dns.RRToType(answer) == dns.TypeMX && answer.Header().Class == dns.ClassINET {
				mxs = append(mxs, answer.(*dns.MX).Mx)
			}
		}
		if len(mxs) == 0 {
			fmt.Println("no mail servers found")
		} else if len(mxs) > 1 {
			fmt.Printf("%d mail servers found\n", len(mxs))
		} else {
			fmt.Println("1 mail server found")
		}
	} else {
		fmt.Println("-")
	}

	fmt.Println("")

	// HTTPS records
	fmt.Printf("HTTPS alias   : ")
	if response, ok := recordQueries[dns.TypeHTTPS]; ok {
		aliases := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if dns.RRToType(answer) == dns.TypeHTTPS && answer.Header().Class == dns.ClassINET {
				https := answer.(*dns.HTTPS)
				if https.Priority == 0 && len(https.Target) >= 2 {
					aliases = append(aliases, https.Target)
				}
			}
		}
		if len(aliases) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(aliases, ", "))
		}

		fmt.Printf("HTTPS info    : ")
		info := make([]string, 0, len(response.Answer)*2)
		for _, answer := range response.Answer {
			if dns.RRToType(answer) == dns.TypeHTTPS && answer.Header().Class == dns.ClassINET {
				https := answer.(*dns.HTTPS)
				if https.Priority != 0 || len(https.Target) <= 1 {
					for _, value := range https.Value {
						info = append(info, fmt.Sprintf("[%s]=[%s]", svcb.KeyToString(svcb.PairToKey(value)), value.String()))
					}
				}
			}
		}
		if len(info) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(info, ", "))
		}
	} else {
		fmt.Println("-")
		fmt.Printf("HTTPS info    : -\n")
	}

	fmt.Println("")

	// Host info
	fmt.Printf("Host info     : ")
	if response, ok := recordQueries[dns.TypeHINFO]; ok {
		hinfo := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if dns.RRToType(answer) == dns.TypeHINFO && answer.Header().Class == dns.ClassINET {
				hinfo = append(hinfo, fmt.Sprintf("%s %s", answer.(*dns.HINFO).Cpu, answer.(*dns.HINFO).Os))
			}
		}
		if len(hinfo) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(hinfo, ", "))
		}
	} else {
		fmt.Println("-")
	}

	// TXT records
	fmt.Printf("TXT records   : ")
	if response, ok := recordQueries[dns.TypeTXT]; ok {
		txt := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if dns.RRToType(answer) == dns.TypeTXT && answer.Header().Class == dns.ClassINET {
				txt = append(txt, strings.Join(answer.(*dns.TXT).Txt, " "))
			}
		}
		if len(txt) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(txt, ", "))
		}
	} else {
		fmt.Println("-")
	}

	fmt.Println("")
}
