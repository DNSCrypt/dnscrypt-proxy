// Package dnsconf is used to get the DNS system configuration, typically stored in /etc/resolv.conf on unix
// systems.
package dnsconf

import (
	"bufio"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/dnsutil"
)

// Config wraps the contents of the /etc/resolv.conf file.
type Config struct {
	Servers  []string // Servers to use.
	Search   []string // Suffixes to append to local name.
	Port     string   // Port to use.
	Ndots    int      // Number of dots in name to trigger absolute lookup.
	Timeout  int      // Seconds before giving up on packet.
	Attempts int      // Lost packets before giving up on server.
}

// FromFile parses a resolv.conf(5) like file and returns a [*Config].
func FromFile(resolvconf string) (*Config, error) {
	file, err := os.Open(resolvconf)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return FromReader(file)
}

// FromReader works like [FromFile] but takes an io.Reader as argument.
func FromReader(resolvconf io.Reader) (*Config, error) {
	c := new(Config)
	scanner := bufio.NewScanner(resolvconf)
	c.Servers = make([]string, 0)
	c.Search = make([]string, 0)
	c.Port = "53"
	c.Ndots = 1
	c.Timeout = 5
	c.Attempts = 2

	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		line := scanner.Text()
		f := strings.Fields(line)
		if len(f) < 1 {
			continue
		}
		switch f[0] {
		case "nameserver": // add one name server
			if len(f) > 1 {
				// One more check: make sure server name is
				// just an IP address.  Otherwise we need DNS
				// to look it up.
				name := f[1]
				c.Servers = append(c.Servers, name)
			}

		case "domain": // set search path to just this domain
			if len(f) > 1 {
				c.Search = make([]string, 1)
				c.Search[0] = f[1]
			} else {
				c.Search = make([]string, 0)
			}

		case "search": // set search path to given servers
			c.Search = slices.Clone(f[1:])

		case "options": // magic options
			for _, s := range f[1:] {
				switch {
				case len(s) >= 6 && s[:6] == "ndots:":
					n, _ := strconv.Atoi(s[6:])
					if n < 0 {
						n = 0
					} else if n > 15 {
						n = 15
					}
					c.Ndots = n
				case len(s) >= 8 && s[:8] == "timeout:":
					n, _ := strconv.Atoi(s[8:])
					if n < 1 {
						n = 1
					}
					c.Timeout = n
				case len(s) >= 9 && s[:9] == "attempts:":
					n, _ := strconv.Atoi(s[9:])
					if n < 1 {
						n = 1
					}
					c.Attempts = n
				case s == "rotate":
					/* not imp */
				}
			}
		}
	}
	return c, nil
}

// NameList returns all of the names that should be queried based on the
// config. It is based off of go's net/dns name building, but it does not
// check the length of the resulting names.
func (c *Config) NameList(name string) []string {
	// if this domain is already fully qualified, no append needed.
	if dnsutil.IsFqdn(name) {
		return []string{name}
	}

	// Check to see if the name has more labels than Ndots. Do this before making
	// the domain fully qualified.
	hasNdots := dnsutil.Labels(name) > c.Ndots
	// Make the domain fully qualified.
	name = dnsutil.Fqdn(name)

	// Make a list of names based off search.
	names := []string{}

	// If name has enough dots, try that first.
	if hasNdots {
		names = append(names, name)
	}
	for _, s := range c.Search {
		names = append(names, dnsutil.Fqdn(name+s))
	}
	// If we didn't have enough dots, try after suffixes.
	if !hasNdots {
		names = append(names, name)
	}
	return names
}
