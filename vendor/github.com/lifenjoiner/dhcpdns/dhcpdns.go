// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

// Package dhcpdns gets the DHCP/DHCPv6 DNS.
package dhcpdns

import (
	"crypto/rand"
	"errors"
	//"log"
	"net"
	"runtime"
	"sync"
	"time"
)

const (
	dhcpv4MessageSizeMax  = 576
	dhcpv6MessageSizeComm = 1024
)

var (
	err4InvalidParam = errors.New("invalid DHCPv4 parameters")
	err4NotReply     = errors.New("not DHCPv4 reply")
	err4TidNotMatch  = errors.New("DHCPv4 TID not match")
)

var (
	errInvalidReply = errors.New("invalid reply")
	errNoDNSFound   = errors.New("no DNS found")
)

var (
	err6InterfaceNotRunning = errors.New("interface is not running")
	err6InvalidParam        = errors.New("invalid DHCPv6 parameters")
	err6NoLLUAFound         = errors.New("no link-local address found")
	err6NotReply            = errors.New("not DHCPv6 Reply")
	err6TidNotMatch         = errors.New("DHCPv6 TID not match")
)

var (
	errIsLLA    = errors.New("unsupported link-local address")
	errIsTeredo = errors.New("unsupported Teredo Tunneling Pseudo-Interface")
)

// Sample messages, https://wiki.wireshark.org/SampleCaptures.md

// GetDNSFromReply4 gets DNS from a DHCP reply message.
func GetDNSFromReply4(msg []byte, tid []byte) (ip []net.IP, err error) {
	n := len(msg)

	if n < 241 || len(tid) < 4 {
		err = err4InvalidParam
		return
	}

	if msg[0] != 0x02 {
		err = err4NotReply
		return
	}

	if msg[4] != tid[0] || msg[5] != tid[1] || msg[6] != tid[2] || msg[7] != tid[3] {
		err = err4TidNotMatch
		return
	}

	m := 240
	for m < n {
		opt := msg[m]
		if opt == 255 {
			// END
			break
		}
		m++

		if m < n {
			i := m + 1
			m += 1 + int(msg[m])
			if m <= n {
				if opt == 6 {
					// DHCP DNS
					for i+4 <= m {
						ip = append(ip, msg[i:i+4])
						i += 4
					}
					break
				}
				continue
			}
		}

		err = errInvalidReply
		break
	}

	if len(ip) == 0 {
		err = errNoDNSFound
		//log.Printf("%x", msg)
	}
	return
}

// GetDNSByIPv4 sends DHCP message and return the DNS.
// ip is the reaching out IP.
func GetDNSByIPv4(ip string) (dns []net.IP, err error) {
	ipAddr, ifi, err := getOutboundParams(ip)
	if err != nil {
		return nil, err
	}
	//log.Printf("Receiving addr Zone: %v", ipAddr.Zone)

	// Windows (WSL2) can't choose the right IP.
	pc, err := reuseListenPacket("udp4", ip+":68")
	if err != nil {
		return nil, err
	}

	// Minimal DHCP message
	// We prefer to be reached by a broadcast than unicast relpy, in case of there is the OS DHCP deamon binding.
	// https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
	// https://datatracker.ietf.org/doc/html/rfc2132#section-9.6
	// INIT-REBOOT: https://datatracker.ietf.org/doc/html/rfc2131#section-4.3.2
	dhcpMsg := []byte{
		0x01,                   // message type
		0x01,                   // hardware type: Ethernet
		0x06,                   // hardware address length: Ethernet
		0x00,                   // hops
		0x48, 0x59, 0x58, 0x27, // transaction id
		0x00, 0x00, // seconds elasped
		0x80, 0x00, // flags: BROADCAST. Unicast may not be received.
		0x00, 0x00, 0x00, 0x00, // client ip: ciaddr
		0x00, 0x00, 0x00, 0x00, // your ip: yiaddr
		0x00, 0x00, 0x00, 0x00, // server ip: siaddr
		0x00, 0x00, 0x00, 0x00, // relay ip: giaddr
		// client MAC: https://gitlab.com/wireshark/wireshark/-/raw/master/manuf
		0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // client hardware address padding
		// ServerHostName
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// BootFileName
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// magic cookie: DHCP
		0x63, 0x82, 0x53, 0x63, // 240B
		// Options
		0x35, 0x01, 0x03, // DHCPREQUEST. DHCPDISCOVER may cause the server to release the OFFER.
		0x32, 0x04, 0xc0, 0xa8, 0x01, 0x04, // Requested IP address for `INIT-REBOOT`
		0x37, 0x01, 0x06, // Parameter Request List: DNS
		0x3d, 0x07, 0x01, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // Client Identifier
		0xff, // END
		// padding: min length of 300 bytes per RFC951
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// new transaction id
	tid := dhcpMsg[4:8]
	_, _ = rand.Read(tid)

	// MAC. On devices (Android) with both IPv6 and IPv6 available, MAC would be nil.
	copy(dhcpMsg[28:28+16], ifi.HardwareAddr)
	// Requested IP address
	copy(dhcpMsg[245:245+4], ipAddr.IP.To4())
	// The DHCP server of VMware NAT mode requires Client identifier.
	m := len(ifi.HardwareAddr)
	//log.Printf("MAC[%v]: %v", m, ifi.HardwareAddr)
	if m > 0 {
		copy(dhcpMsg[255:255+m], ifi.HardwareAddr)
		dhcpMsg[253] = byte(m&0xff) + 1
		dhcpMsg[255+m] = 0xff
	}

	rAddr := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = pc.WriteTo(dhcpMsg, rAddr)
	if err != nil {
		// defer doesn't work on reassignment
		_ = pc.Close()
		return nil, err
	}

	// Prefer broadcast:
	// (*nix) may have a deamon binding the local IPPort and the gateway IPPort.
	// If so and the server replies with a broadcast to the local IPPort, rather than IPv4bcast,
	// it may not be received on some OS.
	if ipAddr.Zone != "" {
		_ = pc.Close()
		pc, err = reuseListenPacket("udp4", ":68")
		if err != nil {
			return nil, err
		}
	}

	//log.Printf("Receiving addr: %v", pc.LocalAddr())

	buf := make([]byte, dhcpv4MessageSizeMax)
	_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf[:])
	_ = pc.Close()
	if err != nil {
		return nil, err
	}
	//log.Printf("Received from: %v", rAddr2)

	dns, err = GetDNSFromReply4(buf[:n], tid)

	return
}

// Required.
func getOutboundParams(ip string) (*net.IPAddr, *net.Interface, error) {
	ipAddr, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return nil, nil, err
	}

	is6 := ipAddr.IP.To4() == nil

	ift, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, ifi := range ift {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}

		var ipUnicast net.IP
		var got bool
		for _, addr := range addrs {
			ipi := addr.(*net.IPNet).IP
			if ipi.Equal(ipAddr.IP) {
				got = true
			}
			if is6 && ipi.To4() == nil && ipi.IsLinkLocalUnicast() {
				ipUnicast = ipi
			}
			//log.Printf("%v: %v", ifi.Name, ipi)
		}

		if got {
			// https://www.kernel.org/doc/html/latest/networking/operstates.html
			if ifi.Flags&net.FlagRunning == net.FlagRunning {
				if ipUnicast != nil {
					ipAddr.IP = ipUnicast
				}
				// Bind fe80::/10 and ListenUDP needs Zone on *nix.
				if ipAddr.Zone == "" && runtime.GOOS != "windows" {
					ipAddr.Zone = ifi.Name
				}
				return ipAddr, &ifi, nil
			}
			return nil, nil, err6InterfaceNotRunning
		}
	}

	return nil, nil, err6NoLLUAFound
}

func readBigEndianUint16(b []byte) uint16 {
	return uint16(b[0])<<8&0xff00 | uint16(b[1])
}

// GetDNSFromReply6 gets DNS from a DHCPv6 REPLY message.
// https://datatracker.ietf.org/doc/html/rfc3646
func GetDNSFromReply6(msg []byte, tid []byte) (ip []net.IP, err error) {
	n := len(msg)

	if n < 7 || len(tid) < 3 {
		err = err6InvalidParam
		return
	}

	if msg[0] != 0x07 {
		err = err6NotReply
		return
	}

	if msg[1] != tid[0] || msg[2] != tid[1] || msg[3] != tid[2] {
		err = err6TidNotMatch
		return
	}

	m := 4
	for m+2 <= n {
		opt := readBigEndianUint16(msg[m : m+2])
		m += 2
		if m+2 < n {
			i := m + 2
			m += 2 + int(readBigEndianUint16(msg[m:m+2]))
			if m <= n {
				if opt == 23 {
					// DHCPv6 DNS
					for i+16 <= m {
						ip = append(ip, msg[i:i+16])
						i += 16
					}
					break
				}
				continue
			}
		}
		err = errInvalidReply
		break
	}
	if len(ip) == 0 {
		err = errNoDNSFound
	}
	return
}

// GetDNSByIPv6 sends DHCPv6 INFORMATION-REQUEST message and return the DNS.
// ip is the reaching out IP.
func GetDNSByIPv6(ip string) (dns []net.IP, err error) {
	ipAddr, _, err := getOutboundParams(ip)
	if err != nil {
		return nil, err
	}

	pc, err := reuseListenPacket("udp6", "["+ipAddr.String()+"]:546")
	if err != nil {
		return nil, err
	}

	//log.Printf("Receiving addr: %v", pc.LocalAddr())

	// Minimal INFORMATION-REQUEST message
	// https://en.wikipedia.org/wiki/DHCPv6
	// INFORMATION-REQUEST (11):
	// https://datatracker.ietf.org/doc/html/rfc8415#section-18.2.6
	// https://datatracker.ietf.org/doc/html/rfc8415#section-8
	dhcpv6Msg := []byte{
		0x0b,             // message type
		0x48, 0x59, 0x58, // transaction id
		// Options
		// Elapsed Time Option: https://datatracker.ietf.org/doc/html/rfc8415#section-21.9
		0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
		// option request: INF_MAX_RT, Information Refresh Time, DNS
		0x00, 0x06, 0x00, 0x06, 0x00, 0x53, 0x00, 0x20, 0x00, 0x17,
		// Client Identifier Option: https://datatracker.ietf.org/doc/html/rfc8415#section-21.2
		// anonymity profile DUID-LLT: https://datatracker.ietf.org/doc/html/rfc7844#section-4.3
		0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x26, 0xeb, 0x58, 0x35, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	}

	// new transaction id
	tid := dhcpv6Msg[1:4]
	_, _ = rand.Read(tid)

	rAddr := &net.UDPAddr{IP: net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02}, Port: 547}
	_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = pc.WriteTo(dhcpv6Msg, rAddr)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, dhcpv6MessageSizeComm)
	_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf[:])
	_ = pc.Close()
	if err != nil {
		return nil, err
	}

	dns, err = GetDNSFromReply6(buf[:n], tid)

	return
}

// Detector holds the parameters and results.
//
//	if err == nil {
//		if lastActiveIP != "" {
//			// got DNS
//		} else {
//			// uninitialized
//		}
//	} else if lastActiveIP == "" {
//		// offline/invalid
//	} else if constancy > x {
//		// treat as (switched to a network that) can't get DNS
//	} else {
//		// treat as temporarily failed
//	}
type Detector struct {
	sync.RWMutex
	got bool
	// RemoteIPPort is the remote IPPort to detect within UDP.
	RemoteIPPort string
	lastActiveIP string
	dns          []net.IP
	err          error
	constancy    int
}

func detect(d *Detector) (string, []net.IP, error) {
	c, err := net.Dial("udp", d.RemoteIPPort)
	if err != nil {
		return "", nil, err
	}
	ipPort := c.LocalAddr().String()
	_ = c.Close()

	ip, _, err := net.SplitHostPort(ipPort)
	if err != nil {
		return "", nil, err
	}

	if ip[:7] == "2001:0:" {
		// https://en.wikipedia.org/wiki/Teredo_tunneling#IPv6_addressing
		err = errIsTeredo
	} else if ip[:6] == "fe80::" || ip[:7] == "169.254" {
		// Only detect valid network. https://www.wikiwand.com/en/Link-local_address
		err = errIsLLA
	}

	var dns []net.IP
	if err == nil && (!d.got || d.lastActiveIP != ip) {
		if ipPort[0] == '[' {
			dns, err = GetDNSByIPv6(ip)
		} else {
			dns, err = GetDNSByIPv4(ip)
		}
	}
	return ip, dns, err
}

// Detect the DNS from the active interface which is adopted to connect to the provided IPPort address.
// The last active IP is used to reduce traffic or defense.
// If got and IP hasn't changed, skip sending DHCP messages as soft detecting.
func (d *Detector) Detect() error {
	ip, dns, err := detect(d)
	d.Lock()
	if err == nil {
		if len(dns) > 0 {
			d.dns = dns
		}
		d.got = true
	}
	if d.lastActiveIP == ip && isTheSameErr(err, d.err) {
		d.constancy++
	} else {
		d.constancy = 1
	}
	d.lastActiveIP = ip
	d.err = err
	d.Unlock()
	return err
}

// SetNewRound sets a new force detecting.
func (d *Detector) SetNewRound() {
	d.Lock()
	d.got = false
	d.Unlock()
}

// Status gets the detected results.
func (d *Detector) Status() (constancy int, ip string, dns []net.IP, err error) {
	d.RLock()
	constancy = d.constancy
	ip = d.lastActiveIP
	dns = d.dns
	err = d.err
	d.RUnlock()
	return
}

// Serve periodically detects the DNS as a daemon.
// cycle is the soft detecting rounds following a force detecting. sleep is in seconds.
func (d *Detector) Serve(cycle, sleep int) {
	var i int
	if cycle <= 0 {
		cycle = 9
	}
	if sleep <= 0 {
		sleep = 10
	}
	for {
		if i%cycle == 0 {
			d.SetNewRound()
		}
		_ = d.Detect()
		i++
		time.Sleep(time.Duration(sleep) * time.Second)
	}
}

func isTheSameErr(err1, err2 error) bool {
	return err1 == err2 || (err1 != nil && err2 != nil && err1.Error() == err2.Error())
}
