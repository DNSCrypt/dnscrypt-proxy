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

const (
	myResolverHost  string = "resolver.dnscrypt.info."
	nonexistentName string = "nonexistent-zone.dnscrypt-test."
)

func resolveQuery(server string, qName string, qType uint16, sendClientSubnet bool) (*dns.Msg, error) {
	transport := dns.NewTransport()
	transport.ReadTimeout = 2 * time.Second
	client := &dns.Client{Transport: transport}
	msg := dns.NewMsg(qName, qType)
	if msg == nil {
		return nil, fmt.Errorf("unsupported DNS record type: %d", qType)
	}
	msg.RecursionDesired = true
	msg.Opcode = dns.OpcodeQuery
	msg.UDPSize = uint16(MaxDNSPacketSize)
	msg.Security = true

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
		ecsOpt := &dns.SUBNET{
			Family:  family,
			Netmask: uint8(bits),
			Scope:   0,
			Address: addr,
		}
		msg.Pseudo = append(msg.Pseudo, ecsOpt)
	}

	readTimeout := transport.ReadTimeout
	for i := 0; i < 3; i++ {
		msg.ID = dns.ID()
		msg.Data = nil // Clear packed data so Exchange will re-pack with new ID
		ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
		response, rtt, err := client.Exchange(ctx, msg, "udp", server)
		cancel()
		if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
			readTimeout *= 2
			continue
		}
		_ = rtt
		if err != nil {
			return nil, err
		}
		return response, nil
	}
	return nil, errors.New("Timeout")
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

	cname := name
	var clientSubnet string

	for once := true; once; once = false {
		response, err := resolveQuery(server, myResolverHost, dns.TypeTXT, true)
		if err != nil {
			fmt.Printf("Unable to resolve: [%s]\n", err)
			os.Exit(1)
		}
		fmt.Printf("Resolver      : ")
		res := make([]string, 0)
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
			if ip == "" {
				continue
			}
			if rev, err := reverseAddr(ip); err == nil {
				response, err = resolveQuery(server, rev, dns.TypePTR, false)
				if err != nil {
					break
				}
				for _, answer := range response.Answer {
					if dns.RRToType(answer) != dns.TypePTR || answer.Header().Class != dns.ClassINET {
						continue
					}
					ip = ip + " (" + answer.(*dns.PTR).Ptr + ")"
					break
				}
			}
			res = append(res, ip)
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
			response, err := resolveQuery(server, nonexistentName, dns.TypeA, false)
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

cname:
	for once := true; once; once = false {
		fmt.Printf("Canonical name: ")
		for i := 0; i < 100; i++ {
			response, err := resolveQuery(server, cname, dns.TypeCNAME, false)
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

	for once := true; once; once = false {
		fmt.Printf("IPv4 addresses: ")
		response, err := resolveQuery(server, cname, dns.TypeA, false)
		if err != nil {
			break
		}
		ipv4 := make([]string, 0)
		for _, answer := range response.Answer {
			if dns.RRToType(answer) != dns.TypeA || answer.Header().Class != dns.ClassINET {
				continue
			}
			ipv4 = append(ipv4, answer.(*dns.A).A.String())
		}
		if len(ipv4) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(ipv4, ", "))
		}
	}

	for once := true; once; once = false {
		fmt.Printf("IPv6 addresses: ")
		response, err := resolveQuery(server, cname, dns.TypeAAAA, false)
		if err != nil {
			break
		}
		ipv6 := make([]string, 0)
		for _, answer := range response.Answer {
			if dns.RRToType(answer) != dns.TypeAAAA || answer.Header().Class != dns.ClassINET {
				continue
			}
			ipv6 = append(ipv6, answer.(*dns.AAAA).AAAA.String())
		}
		if len(ipv6) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(ipv6, ", "))
		}
	}

	fmt.Println("")

	for once := true; once; once = false {
		fmt.Printf("Name servers  : ")
		response, err := resolveQuery(server, cname, dns.TypeNS, false)
		if err != nil {
			break
		}
		nss := make([]string, 0)
		for _, answer := range response.Answer {
			if dns.RRToType(answer) != dns.TypeNS || answer.Header().Class != dns.ClassINET {
				continue
			}
			nss = append(nss, answer.(*dns.NS).Ns)
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
	}

	for once := true; once; once = false {
		fmt.Printf("Mail servers  : ")
		response, err := resolveQuery(server, cname, dns.TypeMX, false)
		if err != nil {
			break
		}
		mxs := make([]string, 0)
		for _, answer := range response.Answer {
			if dns.RRToType(answer) != dns.TypeMX || answer.Header().Class != dns.ClassINET {
				continue
			}
			mxs = append(mxs, answer.(*dns.MX).Mx)
		}
		if len(mxs) == 0 {
			fmt.Println("no mail servers found")
		} else if len(mxs) > 1 {
			fmt.Printf("%d mail servers found\n", len(mxs))
		} else {
			fmt.Println("1 mail server found")
		}
	}

	fmt.Println("")

	for once := true; once; once = false {
		fmt.Printf("HTTPS alias   : ")
		response, err := resolveQuery(server, cname, dns.TypeHTTPS, false)
		if err != nil {
			break
		}
		aliases := make([]string, 0)
		for _, answer := range response.Answer {
			if dns.RRToType(answer) != dns.TypeHTTPS || answer.Header().Class != dns.ClassINET {
				continue
			}
			https := answer.(*dns.HTTPS)
			if https.Priority != 0 || len(https.Target) < 2 {
				continue
			}
			aliases = append(aliases, https.Target)
		}
		if len(aliases) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(aliases, ", "))
		}

		fmt.Printf("HTTPS info    : ")
		info := make([]string, 0)
		for _, answer := range response.Answer {
			if dns.RRToType(answer) != dns.TypeHTTPS || answer.Header().Class != dns.ClassINET {
				continue
			}
			https := answer.(*dns.HTTPS)
			if https.Priority == 0 || len(https.Target) > 1 {
				continue
			}
			for _, value := range https.Value {
				info = append(info, fmt.Sprintf("[%s]=[%s]", svcb.KeyToString(svcb.PairToKey(value)), value.String()))
			}
		}
		if len(info) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(info, ", "))
		}
	}

	fmt.Println("")

	for once := true; once; once = false {
		fmt.Printf("Host info     : ")
		response, err := resolveQuery(server, cname, dns.TypeHINFO, false)
		if err != nil {
			break
		}
		hinfo := make([]string, 0)
		for _, answer := range response.Answer {
			if dns.RRToType(answer) != dns.TypeHINFO || answer.Header().Class != dns.ClassINET {
				continue
			}
			hinfo = append(hinfo, fmt.Sprintf("%s %s", answer.(*dns.HINFO).Cpu, answer.(*dns.HINFO).Os))
		}
		if len(hinfo) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(hinfo, ", "))
		}
	}

	for once := true; once; once = false {
		fmt.Printf("TXT records   : ")
		response, err := resolveQuery(server, cname, dns.TypeTXT, false)
		if err != nil {
			break
		}
		txt := make([]string, 0)
		for _, answer := range response.Answer {
			if dns.RRToType(answer) != dns.TypeTXT || answer.Header().Class != dns.ClassINET {
				continue
			}
			txt = append(txt, strings.Join(answer.(*dns.TXT).Txt, " "))
		}
		if len(txt) == 0 {
			fmt.Println("-")
		} else {
			fmt.Println(strings.Join(txt, ", "))
		}
	}

	fmt.Println("")
}
