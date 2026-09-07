package main

import (
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func TestDNSExchangeOutboundSource(t *testing.T) {
	sourceIP := usableNonLoopbackIPv4(t)
	policy, err := parseOutboundSourcePolicy(sourceIP.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &Proxy{timeout: 2 * time.Second, outboundSource: policy}
	proxy.xTransport = NewXTransport(&proxy.outboundSource)

	for _, proto := range []string{"udp", "tcp"} {
		for _, relayed := range []bool{false, true} {
			name := proto + "-direct"
			if relayed {
				name = proto + "-relayed"
			}
			t.Run(name, func(t *testing.T) {
				relayAddress, peerCh, closeServer := startOutboundDNSServer(t, proto, sourceIP, relayed, nil)
				serverAddress := relayAddress.String()
				if relayed {
					serverAddress = "9.9.9.9:53"
				}
				defer closeServer()
				var relay *DNSCryptRelay
				if relayed {
					relay = &DNSCryptRelay{}
					if proto == "udp" {
						relay.RelayUDPAddr = relayAddress.(*net.UDPAddr)
					} else {
						relay.RelayTCPAddr = relayAddress.(*net.TCPAddr)
					}
				}
				query := dns.NewMsg("example.org.", dns.TypeA)
				response := _dnsExchange(proxy, proto, query, serverAddress, relay, 0)
				if response.err != nil {
					t.Fatal(response.err)
				}
				peer := <-peerCh
				if !peer.Equal(sourceIP) {
					t.Fatalf("peer source = %s, want %s", peer, sourceIP)
				}
			})
		}
	}
}

func startOutboundDNSServer(t *testing.T, proto string, destinationIP net.IP, relayed bool, answer func(*dns.Msg)) (net.Addr, <-chan net.IP, func()) {
	t.Helper()
	peerCh := make(chan net.IP, 1)
	respond := func(packet []byte) []byte {
		if relayed {
			packet = packet[anonymizedDNSHeaderSize:]
		}
		msg := dns.Msg{Data: packet}
		if msg.Unpack() != nil {
			return nil
		}
		msg.Response = true
		if answer != nil {
			answer(&msg)
		}
		if msg.Pack() != nil {
			return nil
		}
		return msg.Data
	}
	if proto == "udp" {
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			packet := make([]byte, MaxDNSPacketSize)
			length, peer, err := listener.ReadFromUDP(packet)
			if err == nil {
				peerCh <- peer.IP
				_, _ = listener.WriteToUDP(respond(packet[:length]), peer)
			}
		}()
		port := listener.LocalAddr().(*net.UDPAddr).Port
		return &net.UDPAddr{IP: destinationIP, Port: port}, peerCh, func() { _ = listener.Close() }
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		defer conn.Close()
		peerCh <- conn.RemoteAddr().(*net.TCPAddr).IP
		packet, err := ReadPrefixed(conn)
		if err != nil {
			return
		}
		packet, err = PrefixWithSize(respond(packet))
		if err == nil {
			_, _ = conn.Write(packet)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	return &net.TCPAddr{IP: destinationIP, Port: port}, peerCh, func() { _ = listener.Close() }
}
