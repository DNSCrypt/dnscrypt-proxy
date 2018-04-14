package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/jedisct1/dnscrypt-proxy/stamps"
	flag "github.com/ogier/pflag"
)

var (
	stamp         stamps.ServerStamp
	providerPk    string
	ip            string
	hashesStr     string
	doh, dnscrypt bool
	dnssec        bool
	noLogs        bool
	noFilter      bool
	port          uint
)

func init() {
	flag.BoolVar(&doh, "doh", false, "create a DNS-over-HTTPS stamp")
	flag.BoolVar(&dnscrypt, "dnscrypt", true, "create a dnscrypt stamp")

	flag.StringVar(&stamp.ServerAddrStr, "ip", "", "IP address")
	flag.StringVar(&stamp.ProviderName, "host", "", "host name for DNS-over-TLS")
	flag.StringVar(&stamp.ProviderName, "provider-name", "", "provider name for the dnscrypt server; same as --host")
	flag.StringVar(&providerPk, "provider-public-key", "", "provider public key fingerprint hash (SHA256) for the dnscrypt server, in hexadecimal format (12:34:aa:bb:...)")
	flag.StringVar(&hashesStr, "hashes", "", "SHA256 hashes for the DNS-over-TLS server certificate, in hexadecimal format (12:34:aa:bb:...), comma separated; colons are optional")
	flag.UintVar(&port, "port", 0, "port for dnscrypt or DNS-over-TLS; if non-standard will be appended to host/provider name")
	flag.StringVar(&stamp.Path, "path", "/dns-query", "path for DNS-over-TLS queries")

	flag.BoolVar(&dnssec, "dnssec", true, "enforce DNSSEC")
	flag.BoolVar(&noLogs, "no-logs", true, "enforce no logs")
	flag.BoolVar(&noFilter, "no-filter", true, "enforce no filter")
}

func main() {
	flag.Parse()

	if (doh && dnscrypt) || (!doh && !dnscrypt) {
		fmt.Fprintf(os.Stderr, "ERROR: either --doh or --dnscrypt should be specified\n")
		os.Exit(1)
	}

	if port != 0 && port != 443 {
		stamp.ServerAddrStr += fmt.Sprintf(":%d", port)
	}

	if doh {
		stamp.Proto = stamps.StampProtoTypeDoH

		if len(providerPk) != 0 {
			fmt.Fprintf(os.Stderr, "ERROR: provider public key cannot be specified for DoH servers, use --hashes instead\n")
			os.Exit(3)
		}

		// parse provided hashes for the DoH server
		for _, hashStr := range strings.Split(hashesStr, ",") {
			h, err := hex.DecodeString(strings.Replace(hashStr, ":", "", -1))
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: invalid hexadecimal hash string: %v\n", err)
				os.Exit(2)
			}
			stamp.Hashes = append(stamp.Hashes, h)
		}
	} else {
		stamp.Proto = stamps.StampProtoTypeDNSCrypt

		if len(hashesStr) != 0 {
			fmt.Fprintf(os.Stderr, "ERROR: hashes cannot be specified for dnscrypt servers, use --provider-public-key instead\n")
			os.Exit(3)
		}

		// parse the public key SHA256 hash
		pk, err := hex.DecodeString(strings.Replace(providerPk, ":", "", -1))
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: invalid hexadecimal string for the provider public key: %v\n", err)
			os.Exit(2)
		}
		stamp.ServerPk = pk
	}
	if dnssec {
		stamp.Props |= stamps.ServerInformalPropertyDNSSEC
	}
	if noLogs {
		stamp.Props |= stamps.ServerInformalPropertyNoLog
	}
	if noFilter {
		stamp.Props |= stamps.ServerInformalPropertyNoFilter
	}

	fmt.Println(stamp.String())
}
