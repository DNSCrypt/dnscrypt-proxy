package dnscrypt

import (
	"fmt"
	"net"
	"strings"
)

const myResolverHost string = "resolver.dnscrypt.info"

func Resolve(name string) {
	fmt.Printf("Resolving [%s]\n\n", name)

	fmt.Printf("Domain exists:  ")
	ns, err := net.LookupNS(name)
	if err != nil || len(ns) == 0 {
		if name == "." {
			fmt.Println("'No' would mean that the Internet doesn't exist any more, and that would be very sad. On the bright side, you just found an easter egg.")
		} else {
			fmt.Println("probably not, or blocked by the proxy")
		}
	} else {
		fmt.Printf("yes, %d name servers found\n", len(ns))
	}

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
