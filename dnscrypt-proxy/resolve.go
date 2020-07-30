package main

import (
	"fmt"
	"net"
	"strings"
)

const myResolverHost string = "resolver.dnscrypt.info"

func Resolve(name string) {
	fmt.Printf("Resolving [%s]\n\n", name)

	fmt.Printf("Canonical name: ")
	cname, err := net.LookupCNAME(name)
	if err != nil {
		fmt.Println("-")
	} else {
		fmt.Println(cname)
	}

	fmt.Printf("IP addresses:   ")
	addrs, err := net.LookupHost(name)
	if err != nil {
		fmt.Println("-")
	} else {
		fmt.Println(strings.Join(addrs, ", "))
	}

	fmt.Printf("TXT records:    ")
	txt, err := net.LookupTXT(name)
	if err != nil {
		fmt.Println("-")
	} else {
		fmt.Println(strings.Join(txt, " "))
	}

	mxs, _ := net.LookupMX(name)
	if len(mxs) > 0 {
		fmt.Printf("Mail servers:   %d mail servers found\n", len(mxs))
	}

	ns, _ := net.LookupNS(name)
	if len(ns) > 0 {
		fmt.Printf("Name servers:   %d name servers found\n", len(ns))
	}

	resIP, err := net.LookupHost(myResolverHost)
	if err == nil && len(resIP) > 0 {
		fmt.Printf("Resolver IP:    %s", resIP[0])
		rev, err := net.LookupAddr(resIP[0])
		if err == nil && len(rev) > 0 {
			fmt.Printf(" (%s)", rev[0])
		}
		fmt.Println("")
	}
	fmt.Println("")
}
