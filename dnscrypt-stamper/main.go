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
	noLog         bool
	noFilter      bool
	port          uint
)

const exampleStamp = `sdns://AQcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5BkyLmRuc2NyeXB0LWNlcnQubG9jYWxob3N0`

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
	flag.BoolVar(&noLog, "no-log", false, "enforce no logs")
	flag.BoolVar(&noFilter, "no-filter", false, "enforce no filter")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of dnscrypt-stamper:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nSpecify one or more DNS stamps on command-line to visualize them:\n")
		fmt.Fprintf(os.Stderr, "\ndnscrypt-stamper %s\n", exampleStamp)
	}
}

func main() {
	// display help if no arguments were specified
	if len(os.Args) == 1 {
		// calling Usage() will exit with code 2
		flag.Usage()
	}

	flag.Parse()

	nonParsed := flag.Args()
	if len(nonParsed) != 0 {
		for _, stampStr := range nonParsed {
			stamp, err := stamps.NewServerStampFromString(stampStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
				os.Exit(2)
			}

			// print out common fields
			fmt.Printf(" ---> %s:\n", stamp.String())
			fmt.Println("\tproto =", stamp.Proto.String())

			if stamp.Props&stamps.ServerInformalPropertyDNSSEC != 0 {
				fmt.Println("\tdnssec = yes")
			} else {
				fmt.Println("\tdnssec = no")
			}
			if stamp.Props&stamps.ServerInformalPropertyNoLog != 0 {
				fmt.Println("\tno-log = yes")
			} else {
				fmt.Println("\tno-log = no")
			}
			if stamp.Props&stamps.ServerInformalPropertyNoFilter != 0 {
				fmt.Println("\tno-filter = yes")
			} else {
				fmt.Println("\tnofilter = no")
			}
			fmt.Println("\tip =", stamp.ServerAddrStr)

			if stamp.Proto == stamps.StampProtoTypeDNSCrypt {
				fmt.Println("\tprovider-public-key =", formatHex(stamp.ServerPk))
				fmt.Println("\tprovider-name =", stamp.ProviderName)
			} else if stamp.Proto == stamps.StampProtoTypeDoH {
				fmt.Println("\thost =", stamp.ProviderName)
				var hashes []string
				for _, hBytes := range stamp.Hashes {
					hashes = append(hashes, formatHex(hBytes))
				}
				if len(hashes) != 0 {
					fmt.Println("\thashes =", strings.Join(hashes, ","))
				}
				fmt.Println("\tpath =", stamp.Path)
			} else {
				panic("unsupported proto")
			}
		}

		// do not generate anything when displaying
		return
	}

	if (doh && dnscrypt) || (!doh && !dnscrypt) {
		fmt.Fprintf(os.Stderr, "ERROR: either --doh or --dnscrypt should be specified\n")
		os.Exit(1)
	}

	if port != 0 && port != stamps.DefaultPort {
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
	if noLog {
		stamp.Props |= stamps.ServerInformalPropertyNoLog
	}
	if noFilter {
		stamp.Props |= stamps.ServerInformalPropertyNoFilter
	}

	fmt.Println(stamp.String())
}

func formatHex(b []byte) string {
	s := strings.ToUpper(hex.EncodeToString(b))

	for i := 0; i < len(s); i += 3 {
		s = s[:i] + ":" + s[i:]
	}

	return s[1:]
}
